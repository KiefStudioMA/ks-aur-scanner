//! Name-confusion primitives for typo-squat detection.
//!
//! An AUR package name is the only thing most people read before they type
//! `yay -S <name>`, so a name that is one keystroke or one lookalike glyph away
//! from something trusted is a delivery mechanism in its own right. This module
//! holds the pure comparison logic -- edit distance, keyboard adjacency,
//! confusable folding, and the split/separator tricks -- so it can be tested
//! exhaustively without a registry, a network, or a filesystem.
//!
//! Everything here is deliberately conservative. A typo-squat finding accuses a
//! named human of impersonation, and the AUR legitimately contains thousands of
//! near-identical names (`foo`, `foo-git`, `foo-bin`, `foo-beta`), so the rule
//! is: **a near-miss is only suspicious once the well-known AUR variant
//! suffixes are accounted for.** `ripgrep-git` is not squatting `ripgrep`.

use std::collections::HashSet;

/// Suffixes that claim to be *the same software, obtained differently*:
/// a prebuilt binary, a VCS checkout, a repackaged upstream artifact.
///
/// These are the reputation-carrying names. A user who sees `foo-bin` believes
/// it is `foo`, built by whoever builds `foo`. The AUR does not enforce that,
/// which is what makes this list the interesting one -- see
/// [`variant_claim_on`].
pub const BUILD_VARIANT_SUFFIXES: &[&str] = &[
    "-git",
    "-bin",
    "-svn",
    "-hg",
    "-bzr",
    "-cvs",
    "-nightly",
    "-beta",
    "-alpha",
    "-rc",
    "-stable",
    "-latest",
    "-appimage",
    "-flatpak",
    "-snap",
    "-deb",
    "-rpm",
    "-static",
    "-insiders",
    "-canary",
    "-edge",
    "-preview",
    "-next",
];

/// Suffixes that name a *component* of a package rather than an alternate build
/// of it: the docs, the headers, the shared libraries.
///
/// Splitting a package into components is ordinary distribution practice and
/// carries no impersonation claim -- `gcc-libs` does not pretend to be `gcc`.
/// These participate in the name-similarity false-positive guard but never in
/// variant-claim detection.
pub const COMPONENT_SUFFIXES: &[&str] = &[
    "-dev",
    "-devel",
    "-lts",
    "-legacy",
    "-old",
    "-debug",
    "-dbg",
    "-doc",
    "-docs",
    "-man",
    "-common",
    "-libs",
    "-lib",
    "-headers",
    "-src",
    "-source",
    "-electron",
    "-wayland",
    "-x11",
    "-qt5",
    "-qt6",
    "-gtk3",
    "-gtk4",
    "-cli",
    "-gui",
    "-server",
    "-client",
    "-daemon",
    "-tools",
    "-utils",
    "-extra",
    "-full",
    "-minimal",
    "-lite",
    "-plus",
    "-ce",
    "-oss",
    "-free",
    "-nonfree",
    "-proprietary",
    "-v2",
    "-v3",
    "-ng",
];

/// Every suffix that marks a name as a relative of another package, for the
/// name-similarity false-positive guard.
pub fn variant_suffixes() -> impl Iterator<Item = &'static str> {
    BUILD_VARIANT_SUFFIXES
        .iter()
        .copied()
        .chain(COMPONENT_SUFFIXES.iter().copied())
}

/// Strip every trailing variant suffix, so `visual-studio-code-bin-git` and
/// `visual-studio-code` compare as the same stem.
pub fn strip_variant_suffixes(name: &str) -> &str {
    let mut s = name;
    loop {
        let before = s;
        for suffix in variant_suffixes() {
            if let Some(stripped) = s.strip_suffix(suffix) {
                // Never strip a name down to nothing: `-git` alone is a name.
                if !stripped.is_empty() {
                    s = stripped;
                    break;
                }
            }
        }
        if s == before {
            return s;
        }
    }
}

/// Levenshtein distance, capped: once the distance provably exceeds `max` we
/// stop early rather than filling the whole matrix. Package names are short, but
/// this is called across every official package name for every scan.
pub fn edit_distance_within(a: &str, b: &str, max: usize) -> Option<usize> {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > max {
        return None;
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        let mut row_min = cur[0];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
            row_min = row_min.min(cur[j]);
        }
        if row_min > max {
            return None;
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    let d = prev[b.len()];
    (d <= max).then_some(d)
}

/// Unicode characters that render like an ASCII letter or digit in a normal
/// terminal font. A package name is ASCII by AUR policy, so any of these in a
/// name is by itself a strong signal -- there is no legitimate reason for
/// Cyrillic `а` to appear in `java-runtime`.
///
/// Keyed by the confusable, valued by the ASCII character it imitates.
pub fn confusable_to_ascii(c: char) -> Option<char> {
    Some(match c {
        // Cyrillic
        'а' => 'a',
        'е' => 'e',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'х' => 'x',
        'у' => 'y',
        'ѕ' => 's',
        'і' => 'i',
        'ј' => 'j',
        'һ' => 'h',
        'ԁ' => 'd',
        'ԛ' => 'q',
        'ѡ' => 'w',
        'ν' => 'v',
        'ᴜ' => 'u',
        'ɡ' => 'g',
        'ł' => 'l',
        // Greek
        'ο' => 'o',
        'α' => 'a',
        'ρ' => 'p',
        'τ' => 't',
        'υ' => 'u',
        'κ' => 'k',
        'ι' => 'i',
        'ε' => 'e',
        'ζ' => 'z',
        'η' => 'n',
        'μ' => 'u',
        'β' => 'b',
        // Fullwidth / mathematical / other Latin blocks
        'ａ' => 'a',
        'ｅ' => 'e',
        'ｏ' => 'o',
        'ｉ' => 'i',
        'ｌ' => 'l',
        'ｓ' => 's',
        'ⅰ' => 'i',
        'ⅼ' => 'l',
        'ⅾ' => 'd',
        'ⅽ' => 'c',
        'ⅿ' => 'm',
        'ｘ' => 'x',
        'ᒐ' => 'l',
        'ɑ' => 'a',
        'ǝ' => 'e',
        'ơ' => 'o',
        'ĸ' => 'k',
        'ſ' => 's',
        _ => return None,
    })
}

/// Every non-ASCII character in `name` that imitates an ASCII one, with the
/// character it imitates. Empty for an honest ASCII name.
///
/// Only reports glyphs in the table above, so it answers "what is this
/// pretending to be". For "is anything here non-ASCII at all", which is the
/// actual security question, use [`non_ascii_chars`].
pub fn confusables(name: &str) -> Vec<(char, char)> {
    name.chars()
        .filter(|c| !c.is_ascii())
        .filter_map(|c| confusable_to_ascii(c).map(|a| (c, a)))
        .collect()
}

/// Every non-ASCII character in a package name, whether or not it is a known
/// confusable.
///
/// The confusable table is hand-written and Unicode is not: an attacker who
/// picks a lookalike glyph outside the table would be invisible to a
/// table-driven check. The table is therefore for *explaining* a name, not for
/// deciding about one.
///
/// The decision rests on policy instead. AUR package names are restricted to
/// alphanumerics and `@._+-`, all ASCII, so a non-ASCII character in a package
/// name is anomalous no matter which one it is — there is no legitimate name
/// this rejects, and no glyph it can miss.
pub fn non_ascii_chars(name: &str) -> Vec<char> {
    name.chars().filter(|c| !c.is_ascii()).collect()
}

/// Fold a name to the ASCII it *looks* like: confusables become the character
/// they imitate, and separators are normalized, so two names that render
/// identically fold to the same string.
pub fn fold_to_ascii_skeleton(name: &str) -> String {
    name.chars()
        .map(|c| confusable_to_ascii(c).unwrap_or(c))
        .map(|c| c.to_ascii_lowercase())
        .map(|c| if c == '_' || c == '.' { '-' } else { c })
        .collect()
}

/// Drop ASCII digits, so two names that differ only by a version number
/// compare equal (`qt5-base` and `qt6-base` both become `qt-base`).
fn strip_digits(s: &str) -> String {
    s.chars().filter(|c| !c.is_ascii_digit()).collect()
}

/// Character pairs that are hard to tell apart in a terminal even when both are
/// plain ASCII. A substitution drawn from this set is worth more than an
/// arbitrary one-character edit.
fn is_visually_similar_pair(a: char, b: char) -> bool {
    const PAIRS: &[(char, char)] = &[
        ('l', '1'),
        ('l', 'i'),
        ('l', 'I'),
        ('i', '1'),
        ('i', 'j'),
        ('o', '0'),
        ('O', '0'),
        ('s', '5'),
        ('s', 'z'),
        ('b', '6'),
        ('g', '9'),
        ('g', 'q'),
        ('u', 'v'),
        ('n', 'm'),
        ('c', 'e'),
        ('a', 'e'),
        ('t', 'f'),
        ('h', 'b'),
        ('d', 'b'),
        ('p', 'q'),
        ('2', 'z'),
        ('8', 'B'),
    ];
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    PAIRS
        .iter()
        .any(|(x, y)| (*x == a && *y == b) || (*x == b && *y == a))
}

/// QWERTY neighbours: a one-key slip is the most common honest typo and the
/// most common deliberate squat.
fn is_keyboard_adjacent(a: char, b: char) -> bool {
    const ROWS: &[&str] = &["1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm"];
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    for row in ROWS {
        let chars: Vec<char> = row.chars().collect();
        for w in chars.windows(2) {
            if (w[0] == a && w[1] == b) || (w[0] == b && w[1] == a) {
                return true;
            }
        }
    }
    false
}

/// How a candidate name differs from a trusted one.
///
/// There are deliberately only two kinds. Earlier drafts also reported
/// one-character insertions/deletions and two-character edits; measured against
/// the real 15,436-name official corpus those produced 2,039 and 23,662
/// false positives respectively, because a dense namespace of short names means
/// almost everything is two edits from something. They are not recoverable with
/// tuning and are not implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SquatKind {
    /// Renders identically but is not the same string: confusable glyphs
    /// (Cyrillic `а` for ASCII `a`) or a separator swap (`foo_bar` for
    /// `foo-bar`). Zero false positives across the full official corpus --
    /// two distinct packages never render the same on purpose.
    Lookalike,
    /// One character substituted for a visually similar or keyboard-adjacent
    /// one (`openss1` for `openssl`). Only ever reported against a curated
    /// high-value target list; against the whole corpus it produces 264 false
    /// positives, almost all of them locale-suffix families.
    OneCharSubstitution,
}

impl SquatKind {
    /// A short phrase for the finding description.
    pub fn describe(&self) -> &'static str {
        match self {
            SquatKind::Lookalike => "renders identically to",
            SquatKind::OneCharSubstitution => "is one lookalike keystroke from",
        }
    }
}

/// A detected near-miss against a trusted name.
#[derive(Debug, Clone)]
pub struct SquatMatch {
    /// The trusted name being imitated.
    pub target: String,
    /// How the candidate differs from it.
    pub kind: SquatKind,
    /// Confusable characters present in the candidate, if any.
    pub confusables: Vec<(char, char)>,
}

/// If `candidate` is `base` plus one or more AUR variant suffixes, return the
/// suffix chain that was added (`"-bin"`, `"-git-bin"`).
///
/// This is the *inverse* of the [`strip_variant_suffixes`] false-positive
/// guard, and it exists because that guard describes a real attack when you
/// look at who published each name. The AUR has no namespace ownership: anyone
/// may publish `<yourpackage>-bin`, and users reasonably assume `foo-bin` is
/// the same project's binary build of `foo`. It usually is. When it is not --
/// when a different account holds the variant name -- the variant is trading on
/// the base package's reputation, and that is a supply-chain position regardless
/// of what the PKGBUILD currently contains.
///
/// Name shape alone proves nothing here: the overwhelming majority of `-bin`
/// and `-git` packages are honest. The caller **must** confirm a maintainer
/// mismatch against the base before reporting anything.
pub fn variant_claim_on(candidate: &str, base: &str) -> Option<String> {
    if candidate == base {
        return None;
    }
    let suffix = candidate.strip_prefix(base)?;
    if suffix.is_empty() {
        return None;
    }
    // Every added segment must be a recognized BUILD-variant suffix, so
    // `foo-bar` is not a claim on `foo`, and neither is a split-package
    // component like `gcc-libs` or `dbus-docs` -- shipping the docs of a
    // package is not claiming to be the package.
    let mut rest = suffix;
    let mut saw_build_variant = false;
    while !rest.is_empty() {
        let matched = BUILD_VARIANT_SUFFIXES
            .iter()
            .chain(COMPONENT_SUFFIXES.iter())
            .filter(|s| rest.starts_with(**s))
            // Longest match first so `-git-bin` consumes `-git` then `-bin`
            // rather than stalling on a shorter prefix.
            .max_by_key(|s| s.len())?;
        if BUILD_VARIANT_SUFFIXES.contains(matched) {
            saw_build_variant = true;
        }
        rest = &rest[matched.len()..];
    }
    saw_build_variant.then(|| suffix.to_string())
}

/// Two names that differ only in a short trailing token are a family, not a
/// squat: `aspell-ca`/`aspell-cs`, `gimp-help-da`/`gimp-help-de`,
/// `man-pages-cs`/`man-pages-es`. Locale and language packs are the single
/// largest source of one-character-substitution noise in the official repos.
fn differs_only_in_final_short_token(a: &str, b: &str) -> bool {
    let (a_head, a_tail) = match a.rsplit_once('-') {
        Some(x) => x,
        None => return false,
    };
    let (b_head, b_tail) = match b.rsplit_once('-') {
        Some(x) => x,
        None => return false,
    };
    a_head == b_head && a_tail.len() <= 3 && b_tail.len() <= 3
}

/// Compare `candidate` against one trusted `target` for *rendering* collision
/// only.
///
/// This is the corpus-safe comparison: it fires only when two distinct names
/// display the same, which two honest packages never do. Measured across all
/// 15,436 official package names it produced zero false positives.
///
/// Returns `None` when they are the same package, when the only difference is
/// an AUR variant suffix, or when they simply look different.
pub fn compare(candidate: &str, target: &str) -> Option<SquatMatch> {
    if candidate == target {
        return None;
    }

    let cand_stem = strip_variant_suffixes(candidate);
    let targ_stem = strip_variant_suffixes(target);

    // `ripgrep-git` vs `ripgrep`: a declared variant of the same stem is the
    // AUR working as intended.
    if cand_stem == targ_stem {
        return None;
    }

    let cand_skel = fold_to_ascii_skeleton(cand_stem);
    let targ_skel = fold_to_ascii_skeleton(targ_stem);

    // Folds to the same rendering: confusable glyphs, case, or `_`/`.` for `-`.
    if cand_skel == targ_skel {
        return Some(SquatMatch {
            target: target.to_string(),
            kind: SquatKind::Lookalike,
            confusables: confusables(candidate),
        });
    }

    None
}

/// Compare `candidate` against a **high-value** trusted `target`, additionally
/// allowing a single lookalike keystroke.
///
/// Only ever call this with a curated list of packages actually worth
/// impersonating. Against the full corpus the substitution rule produces 264
/// false positives; against a few hundred high-value names it is workable,
/// because the question changes from "is this near anything at all" to "is this
/// near something an attacker would want you to mistype".
pub fn compare_high_value(candidate: &str, target: &str) -> Option<SquatMatch> {
    if let Some(m) = compare(candidate, target) {
        return Some(m);
    }

    let cand_stem = strip_variant_suffixes(candidate);
    let targ_stem = strip_variant_suffixes(target);
    let cand_skel = fold_to_ascii_skeleton(cand_stem);
    let targ_skel = fold_to_ascii_skeleton(targ_stem);

    // A substitution can only exist between equal-length names.
    if cand_skel.chars().count() != targ_skel.chars().count() {
        return None;
    }

    // Version siblings are not squats. `qt5-base`/`qt6-base`,
    // `python2`/`python3`, `llvm15`/`llvm16` differ by a digit -- and adjacent
    // digits are keyboard-adjacent, so distance alone would call every one of
    // these an impersonation. Identical once digits are removed means the same
    // software at two versions.
    //
    // This deliberately does not suppress a digit-for-*letter* swap:
    // `openss1` vs `openssl` survives, because removing digits leaves
    // `openss` != `openssl`.
    if strip_digits(&cand_skel) == strip_digits(&targ_skel) {
        return None;
    }

    // Locale/language families.
    if differs_only_in_final_short_token(&cand_skel, &targ_skel) {
        return None;
    }

    // Short names are dense: colliding by accident is the norm below 5 chars.
    // Measure the *full* name, not the suffix-stripped stem -- `paru-bin` is a
    // real, widely installed target even though its stem is only four
    // characters, while `yay` and `gcc` are genuinely too short to reason about.
    if fold_to_ascii_skeleton(target).chars().count() < 5
        || fold_to_ascii_skeleton(candidate).chars().count() < 5
    {
        return None;
    }

    let swapped: Vec<(char, char)> = cand_skel
        .chars()
        .zip(targ_skel.chars())
        .filter(|(a, b)| a != b)
        .collect();
    let (a, b) = match swapped.as_slice() {
        [pair] => *pair,
        _ => return None,
    };
    if !is_visually_similar_pair(a, b) && !is_keyboard_adjacent(a, b) {
        return None;
    }

    Some(SquatMatch {
        target: target.to_string(),
        kind: SquatKind::OneCharSubstitution,
        confusables: confusables(candidate),
    })
}

/// Compare `candidate` against a set of trusted names, returning the closest
/// match. Deduped and deterministic: the strongest kind wins, ties break on the
/// target name so output never depends on set iteration order.
///
/// `high_value` selects the comparison: `false` uses the corpus-safe rendering
/// check, `true` additionally allows one lookalike keystroke.
pub fn nearest<'a, I>(candidate: &str, targets: I, high_value: bool) -> Option<SquatMatch>
where
    I: IntoIterator<Item = &'a str>,
{
    let cmp = if high_value {
        compare_high_value
    } else {
        compare
    };
    let mut seen: HashSet<&str> = HashSet::new();
    let mut best: Option<SquatMatch> = None;
    for target in targets {
        if !seen.insert(target) {
            continue;
        }
        let Some(m) = cmp(candidate, target) else {
            continue;
        };
        let better = match &best {
            None => true,
            Some(b) => match (rank(&m.kind), rank(&b.kind)) {
                (a, c) if a < c => true,
                (a, c) if a > c => false,
                _ => m.target < b.target,
            },
        };
        if better {
            best = Some(m);
        }
    }
    best
}

/// Lower is stronger.
fn rank(kind: &SquatKind) -> u8 {
    match kind {
        SquatKind::Lookalike => 0,
        SquatKind::OneCharSubstitution => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_suffixes_are_not_squats() {
        // The single most important false-positive class: the AUR is *built*
        // out of `-git` and `-bin` rebuilds of repo packages.
        for name in [
            "ripgrep-git",
            "ripgrep-bin",
            "ripgrep-git-bin",
            "firefox-nightly",
            "neovim-git",
            "visual-studio-code-bin",
        ] {
            let stem = strip_variant_suffixes(name);
            assert!(
                compare(name, stem).is_none(),
                "{name} must not be a squat of its own stem {stem}"
            );
        }
    }

    #[test]
    fn identical_name_is_not_a_squat() {
        assert!(compare("ripgrep", "ripgrep").is_none());
    }

    #[test]
    fn cyrillic_lookalike_is_caught() {
        // Cyrillic 'а' (U+0430) renders exactly like ASCII 'a'.
        let m = compare("jаva-runtime", "java-runtime").expect("cyrillic squat must be caught");
        assert_eq!(m.kind, SquatKind::Lookalike);
        assert_eq!(m.confusables, vec![('а', 'a')]);
    }

    #[test]
    fn separator_swap_is_a_lookalike() {
        let m = compare("python_requests", "python-requests").expect("separator swap");
        assert_eq!(m.kind, SquatKind::Lookalike);
    }

    #[test]
    fn keyboard_slip_is_a_substitution_against_high_value_targets() {
        // 'a' and 's' are adjacent on QWERTY, so `psru-bin` is one slip from
        // the very widely installed `paru-bin`.
        let m = compare_high_value("psru-bin", "paru-bin").expect("keyboard slip");
        assert_eq!(m.kind, SquatKind::OneCharSubstitution);
    }

    #[test]
    fn substitution_never_fires_on_the_general_corpus_path() {
        // The whole point of splitting the two comparisons: a one-character
        // substitution is only admissible against a curated target list.
        assert!(compare("psru-bin", "paru-bin").is_none());
        assert!(compare("openss1", "openssl").is_none());
    }

    #[test]
    fn version_siblings_are_not_squats() {
        // Adjacent digits are keyboard-adjacent, so without the digit rule
        // every versioned package family accuses its own sibling.
        for (a, b) in [
            ("qt5-base", "qt6-base"),
            ("python2", "python3"),
            ("llvm15", "llvm16"),
            ("php7-fpm", "php8-fpm"),
        ] {
            assert!(
                compare_high_value(a, b).is_none(),
                "{a} and {b} are versions of one package, not a squat"
            );
        }
    }

    #[test]
    fn locale_families_are_not_squats() {
        // Measured against the real corpus these were the dominant
        // false-positive family for one-character substitution.
        for (a, b) in [
            ("aspell-ca", "aspell-cs"),
            ("gimp-help-da", "gimp-help-de"),
            ("man-pages-cs", "man-pages-es"),
            ("aspell-nb", "aspell-nn"),
        ] {
            assert!(
                compare_high_value(a, b).is_none(),
                "{a} and {b} are a locale family, not a squat"
            );
        }
    }

    #[test]
    fn digit_for_letter_swap_still_fires_despite_the_version_rule() {
        // The version rule must not become a hiding place: `openss1` is a
        // digit standing in for a *letter*, which is the classic squat.
        let m = compare_high_value("openss1", "openssl").expect("l -> 1 must survive");
        assert_eq!(m.kind, SquatKind::OneCharSubstitution);
    }

    #[test]
    fn insertions_and_deletions_are_not_reported() {
        // Measured at 2,039 false positives across the official corpus. The
        // capability is intentionally absent, not merely tuned down.
        assert!(compare("pythn3-requests", "python3-requests").is_none());
        assert!(compare_high_value("pythn3-requests", "python3-requests").is_none());
    }

    #[test]
    fn short_names_are_not_compared_by_distance() {
        // Three- and four-letter names are dense; colliding by accident is the
        // norm, so a substitution says nothing.
        assert!(compare_high_value("gc", "gcc").is_none());
        assert!(compare_high_value("vim", "zim").is_none());
        assert!(compare_high_value("yay", "yad").is_none());
    }

    #[test]
    fn genuinely_different_names_do_not_match() {
        for (a, b) in [
            ("firefox", "chromium"),
            ("ripgrep", "fd-find"),
            ("python-requests", "python-urllib3"),
            ("linux-lts", "linux-zen"),
        ] {
            assert!(
                compare_high_value(a, b).is_none(),
                "{a} and {b} are different packages, not a squat"
            );
        }
    }

    #[test]
    fn related_but_distinct_official_names_do_not_match() {
        // Real neighbours in the repos -- these must stay quiet or the rule is
        // unusable in practice.
        for (a, b) in [
            ("python-pytest", "python-pytest-cov"),
            ("gstreamer", "gst-plugins-base"),
            ("qt5-base", "qt6-base"),
            ("lua-lub", "lua-luv"),
        ] {
            assert!(
                compare_high_value(a, b).is_none(),
                "{a} vs {b} must not fire"
            );
        }
    }

    #[test]
    fn variant_claim_detects_the_unclaimed_namespace_grab() {
        // The real case: `aur-scanner` and `ks-aur-scanner` are ours, we never
        // published a `-bin`, and someone else did. The AUR has no namespace
        // ownership, so nothing stopped them.
        assert_eq!(
            variant_claim_on("aur-scanner-bin", "aur-scanner").as_deref(),
            Some("-bin")
        );
        assert_eq!(
            variant_claim_on("ripgrep-git-bin", "ripgrep").as_deref(),
            Some("-git-bin")
        );
        assert_eq!(
            variant_claim_on("neovim-nightly", "neovim").as_deref(),
            Some("-nightly")
        );
    }

    #[test]
    fn variant_claim_ignores_unrelated_and_meaningful_suffixes() {
        // A suffix that is not a build-variant marker means a different
        // package, not a claim on this one.
        assert!(variant_claim_on("aur-scanner-web", "aur-scanner").is_none());
        assert!(variant_claim_on("python-requests", "python").is_none());
        assert!(variant_claim_on("firefox", "firefox").is_none());
        assert!(variant_claim_on("gimp", "firefox").is_none());
        // A prefix match that is not on a separator boundary is not a claim.
        assert!(variant_claim_on("aur-scannerbin", "aur-scanner").is_none());
    }

    #[test]
    fn split_package_components_are_not_variant_claims() {
        // Shipping the docs or the shared libraries of a package is ordinary
        // packaging, not an impersonation of it. Measured across the official
        // corpus these accounted for the bulk of variant-shaped pairs.
        for (component, base) in [
            ("gcc-libs", "gcc"),
            ("dbus-docs", "dbus"),
            ("glib2-devel", "glib2"),
            ("iptables-legacy", "iptables"),
            ("ca-certificates-utils", "ca-certificates"),
        ] {
            assert!(
                variant_claim_on(component, base).is_none(),
                "{component} is a component of {base}, not a claim on it"
            );
        }
    }

    #[test]
    fn a_component_suffix_after_a_build_variant_is_still_a_claim() {
        // `-bin-libs` still contains the reputation-carrying `-bin`.
        assert!(variant_claim_on("aur-scanner-bin-libs", "aur-scanner").is_some());
    }

    #[test]
    fn name_proximity_alone_cannot_clear_an_established_package() {
        // `bibutils` really is one keyboard-adjacent character from `binutils`,
        // and this layer correctly says so -- 'b' and 'n' are neighbours. Name
        // proximity is necessary but never sufficient: `bibutils` is a decade-old
        // package with community standing, and it is the *analyzer's* job to
        // weigh that before emitting a finding. This test pins the division of
        // responsibility so nobody "fixes" it here by special-casing a name.
        let m = compare_high_value("bibutils", "binutils");
        assert!(
            m.is_some(),
            "the name layer reports proximity; the registry gate decides"
        );
    }

    #[test]
    fn nearest_picks_the_strongest_match_deterministically() {
        let targets = ["python3", "python2", "pythonx"];
        let m = nearest("pythоn3", targets, false).expect("cyrillic 'о' lookalike");
        assert_eq!(m.target, "python3");
    }

    #[test]
    fn nearest_is_stable_regardless_of_input_order() {
        let a = nearest("openss1", ["openssl", "openssh"], true).unwrap();
        let b = nearest("openss1", ["openssh", "openssl"], true).unwrap();
        assert_eq!(a.target, b.target);
    }

    #[test]
    fn edit_distance_cap_short_circuits() {
        assert_eq!(edit_distance_within("abc", "abc", 2), Some(0));
        assert_eq!(edit_distance_within("abc", "abd", 2), Some(1));
        assert_eq!(edit_distance_within("abc", "xyz", 2), None);
        assert_eq!(edit_distance_within("a", "abcdef", 2), None);
    }

    #[test]
    fn non_ascii_detection_does_not_depend_on_the_table() {
        // The confusable table is hand-written; Unicode is not. A lookalike
        // glyph outside the table must still be caught, because the rule is
        // "AUR names are ASCII", not "AUR names avoid the glyphs we listed".
        let exotic = "pyth\u{1D5FC}n"; // MATHEMATICAL MONOSPACE SMALL O, not in the table
        assert!(
            confusable_to_ascii('\u{1D5FC}').is_none(),
            "this test is only meaningful while the glyph is absent from the table"
        );
        assert!(
            confusables(exotic).is_empty(),
            "table-driven check cannot see it, by construction"
        );
        assert_eq!(
            non_ascii_chars(exotic),
            vec!['\u{1D5FC}'],
            "the policy-based check must still catch it"
        );
        assert!(non_ascii_chars("python-requests").is_empty());
        assert!(non_ascii_chars("gtk3-nocsd").is_empty());
        assert!(non_ascii_chars("lib32-glibc").is_empty());
        assert!(non_ascii_chars("c++").is_empty());
    }

    #[test]
    fn confusables_ignores_honest_ascii() {
        assert!(confusables("ripgrep").is_empty());
        assert!(confusables("python-requests").is_empty());
        assert!(!confusables("rіpgrep").is_empty()); // Cyrillic 'і'
    }

    #[test]
    fn skeleton_folds_case_and_separators() {
        assert_eq!(fold_to_ascii_skeleton("Foo_Bar.baz"), "foo-bar-baz");
    }

    #[test]
    fn strip_suffixes_never_empties_a_name() {
        assert_eq!(strip_variant_suffixes("-git"), "-git");
        assert_eq!(strip_variant_suffixes("git"), "git");
    }
}
