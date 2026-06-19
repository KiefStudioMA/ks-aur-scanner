//! Validation of attacker-controlled package identifiers.
//!
//! Package names and bases enter the tool from many untrusted places: CLI
//! arguments, `pacman -Qm` output, AUR RPC JSON (`Name`/`PackageBase`), and
//! dependency specifiers parsed out of a hostile PKGBUILD. Those values are
//! then used to build network URLs *and* filesystem paths (clone destinations,
//! `remove_dir_all`/`create_dir_all` targets, install-script discovery). An
//! unvalidated value such as `../../../.config/systemd/user` or `x#@evil` turns
//! a "fetch" into path traversal or request injection.
//!
//! This module is the single chokepoint that defines what a legal Arch package
//! identifier is, so every entry point can reject garbage *before* it reaches
//! the network or the filesystem.

use crate::error::{Result, ScanError};

/// Maximum length we accept for a package identifier. Real names are short;
/// this is purely a sanity bound against absurd inputs.
const MAX_NAME_LEN: usize = 256;

/// Return `true` if `name` is a syntactically legal Arch/AUR package name or
/// base.
///
/// Arch package names consist of alphanumerics plus `@ . _ + -`, and may not
/// begin with a hyphen or dot. We additionally forbid the path-significant
/// segments `.`/`..` outright. Because `/`, whitespace, and URL/shell
/// metacharacters are all outside the permitted set, a value that passes this
/// check is safe to use as a single URL path segment and as a single
/// filesystem path component. Case is permitted (some historical names use it);
/// the security boundary is the *character set*, not the case.
pub fn is_valid_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return false;
    }
    if name == "." || name == ".." {
        return false;
    }
    let mut chars = name.chars();
    // First character may not be a hyphen (arg-injection) or dot (hidden/
    // traversal-adjacent), per Arch naming rules.
    match chars.next() {
        Some('-') | Some('.') => return false,
        Some(c) if is_name_char(c) => {}
        _ => return false,
    }
    chars.all(is_name_char)
}

/// Validate a package identifier, returning a descriptive error if it is not a
/// legal name. Use this at every boundary where an untrusted name becomes a URL
/// or a path.
pub fn validate_package_name(name: &str) -> Result<()> {
    if is_valid_package_name(name) {
        Ok(())
    } else {
        Err(ScanError::Validation(format!(
            "illegal package name {name:?}: must be a bare Arch package identifier \
             (alphanumerics and @._+-, not starting with - or .)"
        )))
    }
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '+' | '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_real_names() {
        for ok in [
            "paru",
            "yay",
            "google-chrome",
            "lib32-glibc",
            "python-pip",
            "gtk+",
            "c++",
            "foo.bar",
            "a_b",
            "node@18",
            "0ad",
        ] {
            assert!(is_valid_package_name(ok), "should accept {ok:?}");
        }
    }

    #[test]
    fn rejects_traversal_and_injection() {
        for bad in [
            "",
            ".",
            "..",
            "../../etc/passwd",
            "../../../.config/systemd/user",
            "a/b",
            "-rf",     // leading hyphen -> arg injection
            ".hidden", // leading dot
            "x#@evil",
            "foo bar", // whitespace
            "foo&arg[]=bar",
            "name\ninjected",
            "pkg;rm -rf /",
            "$(touch x)",
            "a\0b",
        ] {
            assert!(!is_valid_package_name(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn validate_returns_err_for_bad() {
        assert!(validate_package_name("../evil").is_err());
        assert!(validate_package_name("paru").is_ok());
    }
}
