//! Paru FileManager view discovery
//!
//! When paru invokes a FileManager, it creates a temporary directory
//! containing symlinks to the actual package clone directories and
//! pre-computed diff files.
//!
//! View structure for a single package "my-package":
//! ```text
//! /tmp/aurXXXXXX/
//! ├── my-package            -> ~/.cache/paru/clone/my-package/     (symlink)
//! ├── my-package.PKGBUILD   -> ~/.cache/paru/clone/my-package/PKGBUILD  (symlink)
//! ├── my-package.SRCINFO    -> ~/.cache/paru/clone/my-package/.SRCINFO  (symlink)
//! └── my-package.diff       -> ~/.cache/paru/diff/my-package.diff  (symlink, if available)
//! ```
//!
//! Multiple packages may be present in a single view when paru
//! processes several AUR updates at once.

use crate::error::ScanError;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::debug;

/// A package discovered in a paru FileManager view
#[derive(Debug, Clone)]
pub struct ParuViewPackage {
    /// Package name (derived from the symlink name)
    pub name: String,
    /// Resolved path to the PKGBUILD file
    pub pkgbuild_path: PathBuf,
    /// Resolved path to the clone directory (git repo), if available
    pub clone_dir: Option<PathBuf>,
    /// Path to the pre-computed diff file, if available
    pub diff_path: Option<PathBuf>,
}

/// Check whether a directory looks like a paru FileManager view.
///
/// Returns `true` if the directory contains `*.PKGBUILD` symlinks
/// or subdirectory symlinks pointing to paru clone directories.
pub fn is_paru_view(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }

    // Check for *.PKGBUILD files (primary indicator)
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with(".PKGBUILD") {
                return true;
            }
        }
    }

    // Fallback: check for symlinked subdirectories containing a PKGBUILD
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_symlink() && path.is_dir() && path.join("PKGBUILD").is_file() {
                return true;
            }
        }
    }

    false
}

/// Discover all packages present in a paru FileManager view directory.
///
/// This function examines the view directory for `*.PKGBUILD` symlinks
/// (primary method) or subdirectory symlinks (fallback), resolves them
/// to their real paths, and checks for associated `.diff` files.
pub fn discover_paru_view(view_dir: &Path) -> Result<Vec<ParuViewPackage>, ScanError> {
    if !view_dir.is_dir() {
        return Err(ScanError::NotFound(format!(
            "View directory does not exist: {}",
            view_dir.display()
        )));
    }

    let mut packages = Vec::new();
    let mut seen = HashSet::new();

    // Primary method: find *.PKGBUILD symlinks
    if let Ok(entries) = fs::read_dir(view_dir) {
        let mut pkgbuild_entries: Vec<_> = entries
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".PKGBUILD"))
            .collect();
        pkgbuild_entries.sort_by_key(|e| e.file_name());

        for entry in pkgbuild_entries {
            let filename = entry.file_name();
            let name_str = filename.to_string_lossy();

            // Extract package name: "my-package.PKGBUILD" -> "my-package"
            let pkg_name = match name_str.strip_suffix(".PKGBUILD") {
                Some(name) => name.to_string(),
                None => continue,
            };

            if seen.contains(&pkg_name) {
                continue;
            }
            seen.insert(pkg_name.clone());

            // Resolve the PKGBUILD symlink to the real file
            let pkgbuild_path = match fs::canonicalize(entry.path()) {
                Ok(p) => p,
                Err(_) => continue,
            };

            // The clone directory is the parent of the resolved PKGBUILD
            let clone_dir = pkgbuild_path.parent().map(|p| p.to_path_buf());

            // Check for a .diff file
            let diff_file = view_dir.join(format!("{}.diff", pkg_name));
            let diff_path = if diff_file.exists() {
                Some(match fs::canonicalize(&diff_file) {
                    Ok(p) => p,
                    Err(_) => diff_file,
                })
            } else {
                None
            };

            debug!(
                "Discovered package '{}': pkgbuild={}, clone_dir={:?}, has_diff={}",
                pkg_name,
                pkgbuild_path.display(),
                clone_dir.as_ref().map(|p| p.display().to_string()),
                diff_path.is_some()
            );

            packages.push(ParuViewPackage {
                name: pkg_name,
                pkgbuild_path,
                clone_dir,
                diff_path,
            });
        }
    }

    // Fallback: if no *.PKGBUILD files found, look for subdirectory symlinks
    if packages.is_empty() {
        if let Ok(entries) = fs::read_dir(view_dir) {
            let mut dir_entries: Vec<_> = entries.flatten().filter(|e| e.path().is_dir()).collect();
            dir_entries.sort_by_key(|e| e.file_name());

            for entry in dir_entries {
                let pkg_name = entry.file_name().to_string_lossy().to_string();

                if seen.contains(&pkg_name) || pkg_name.starts_with('.') {
                    continue;
                }

                // Resolve symlink to the real clone directory
                let clone_dir = match fs::canonicalize(entry.path()) {
                    Ok(p) => p,
                    Err(_) => entry.path(),
                };

                let pkgbuild_path = clone_dir.join("PKGBUILD");
                if !pkgbuild_path.is_file() {
                    continue;
                }

                seen.insert(pkg_name.clone());

                let diff_file = view_dir.join(format!("{}.diff", pkg_name));
                let diff_path = if diff_file.exists() {
                    Some(match fs::canonicalize(&diff_file) {
                        Ok(p) => p,
                        Err(_) => diff_file,
                    })
                } else {
                    None
                };

                debug!(
                    "Discovered package '{}' (fallback): pkgbuild={}, has_diff={}",
                    pkg_name,
                    pkgbuild_path.display(),
                    diff_path.is_some()
                );

                packages.push(ParuViewPackage {
                    name: pkg_name,
                    pkgbuild_path,
                    clone_dir: Some(clone_dir),
                    diff_path,
                });
            }
        }
    }

    if packages.is_empty() {
        return Err(ScanError::NotFound(
            "No packages found in paru view directory".into(),
        ));
    }

    Ok(packages)
}

/// Read the diff content for a package, either from paru's pre-computed
/// `.diff` file or by running `git diff` against the clone directory.
pub fn read_package_diff(pkg: &ParuViewPackage) -> Option<String> {
    // Prefer paru's pre-computed diff
    if let Some(ref diff_path) = pkg.diff_path {
        if let Ok(content) = fs::read_to_string(diff_path) {
            if !content.trim().is_empty() {
                debug!("Using paru diff for '{}'", pkg.name);
                return Some(content);
            }
        }
    }

    // Fallback: git diff from the clone directory
    if let Some(ref clone_dir) = pkg.clone_dir {
        if clone_dir.join(".git").is_dir() {
            debug!("Falling back to git diff for '{}'", pkg.name);
            return git_diff(clone_dir);
        }
    }

    None
}

/// Run `git diff HEAD~1..HEAD` in a directory to get the latest changes.
fn git_diff(repo_dir: &Path) -> Option<String> {
    // Try HEAD~1..HEAD first (most common case: updating an existing package)
    let output = std::process::Command::new("git")
        .args(["diff", "HEAD~1..HEAD", "--", "PKGBUILD", "*.install"])
        .current_dir(repo_dir)
        .output()
        .ok()?;

    if output.status.success() {
        let diff = String::from_utf8_lossy(&output.stdout).to_string();
        if !diff.trim().is_empty() {
            return Some(diff);
        }
    }

    // Fallback for first-time clones: diff against empty tree
    let log_output = std::process::Command::new("git")
        .args(["log", "--oneline", "-2"])
        .current_dir(repo_dir)
        .output()
        .ok()?;

    let log_text = String::from_utf8_lossy(&log_output.stdout);
    if log_text.trim().lines().count() < 2 {
        // Only one commit — show full content as diff
        let output = std::process::Command::new("git")
            .args([
                "diff",
                "4b825dc642cb6eb9a060e54bf899d69f82cf7100",
                "HEAD",
                "--",
                "PKGBUILD",
                "*.install",
            ])
            .current_dir(repo_dir)
            .output()
            .ok()?;

        if output.status.success() {
            let diff = String::from_utf8_lossy(&output.stdout).to_string();
            if !diff.trim().is_empty() {
                return Some(diff);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn test_is_paru_view_empty_dir() {
        let dir = TempDir::new().unwrap();
        assert!(!is_paru_view(dir.path()));
    }

    #[test]
    fn test_is_paru_view_with_pkgbuild_files() {
        let dir = TempDir::new().unwrap();
        let pkg_dir = dir.path().join("test-pkg");
        fs::create_dir(&pkg_dir).unwrap();
        fs::write(pkg_dir.join("PKGBUILD"), "pkgname=test").unwrap();

        // Create symlinks like paru does
        symlink(
            pkg_dir.join("PKGBUILD"),
            dir.path().join("test-pkg.PKGBUILD"),
        )
        .unwrap();

        assert!(is_paru_view(dir.path()));
    }

    #[test]
    fn test_discover_packages_from_pkgbuild_symlinks() {
        // Simulate paru's structure: clone dir is outside the view dir
        let clone_base = TempDir::new().unwrap();
        let pkg_dir = clone_base.path().join("my-package");
        fs::create_dir(&pkg_dir).unwrap();
        fs::write(pkg_dir.join("PKGBUILD"), "pkgname=my-package\npkgver=1.0\n").unwrap();

        // View dir (like /tmp/aurXXXXXX) contains only symlinks
        let view_dir = TempDir::new().unwrap();
        symlink(
            pkg_dir.join("PKGBUILD"),
            view_dir.path().join("my-package.PKGBUILD"),
        )
        .unwrap();
        symlink(&pkg_dir, view_dir.path().join("my-package")).unwrap();

        let packages = discover_paru_view(view_dir.path()).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "my-package");
        assert!(packages[0].pkgbuild_path.is_file());
        assert!(packages[0].diff_path.is_none());
    }

    #[test]
    fn test_discover_with_diff_file() {
        let dir = TempDir::new().unwrap();
        let pkg_dir = dir.path().join("test-pkg");
        fs::create_dir(&pkg_dir).unwrap();
        fs::write(pkg_dir.join("PKGBUILD"), "pkgname=test-pkg\n").unwrap();

        symlink(
            pkg_dir.join("PKGBUILD"),
            dir.path().join("test-pkg.PKGBUILD"),
        )
        .unwrap();

        // Create a diff file
        let diff_content =
            "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-pkgver=1.0\n+pkgver=2.0\n";
        fs::write(dir.path().join("test-pkg.diff"), diff_content).unwrap();

        let packages = discover_paru_view(dir.path()).unwrap();
        assert_eq!(packages.len(), 1);
        assert!(packages[0].diff_path.is_some());
    }

    #[test]
    fn test_discover_multiple_packages() {
        let dir = TempDir::new().unwrap();

        for name in &["pkg-a", "pkg-b", "pkg-c"] {
            let pkg_dir = dir.path().join(name);
            fs::create_dir(&pkg_dir).unwrap();
            fs::write(
                pkg_dir.join("PKGBUILD"),
                format!("pkgname={}\npkgver=1.0\n", name),
            )
            .unwrap();
            symlink(
                pkg_dir.join("PKGBUILD"),
                dir.path().join(format!("{}.PKGBUILD", name)),
            )
            .unwrap();
        }

        let packages = discover_paru_view(dir.path()).unwrap();
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].name, "pkg-a");
        assert_eq!(packages[1].name, "pkg-b");
        assert_eq!(packages[2].name, "pkg-c");
    }

    #[test]
    fn test_discover_fallback_subdirectories() {
        // Clone dir lives outside the view dir
        let clone_base = TempDir::new().unwrap();
        let pkg_dir = clone_base.path().join("fallback-pkg");
        fs::create_dir(&pkg_dir).unwrap();
        fs::write(pkg_dir.join("PKGBUILD"), "pkgname=fallback-pkg\n").unwrap();

        // View dir only contains a symlink (no .PKGBUILD file -> fallback path)
        let view_dir = TempDir::new().unwrap();
        symlink(&pkg_dir, view_dir.path().join("fallback-pkg")).unwrap();

        let packages = discover_paru_view(view_dir.path()).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "fallback-pkg");
    }
}
