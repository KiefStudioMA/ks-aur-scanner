//! AUR package fetching and information retrieval
//!
//! Provides functionality to fetch PKGBUILDs directly from the AUR
//! before installation for pre-emptive security scanning.

use crate::error::{Result, ScanError};
use crate::validate::validate_package_name;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tracing::{debug, info, warn};

/// AUR RPC API base URL
const AUR_RPC_URL: &str = "https://aur.archlinux.org/rpc/v5";

/// AUR Git base URL
const AUR_GIT_URL: &str = "https://aur.archlinux.org";

/// Hard cap on an RPC response body. The 30s timeout bounds *time*, not *size*:
/// a hostile or MITM'd endpoint (or a redirect target) can otherwise stream
/// unbounded data into memory. Real `info`/`search` replies are well under this;
/// the cap only stops abuse.
const MAX_RPC_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Read a response body with a hard size cap and deserialize it as JSON.
///
/// `Content-Length` cannot be trusted (it may be absent or a lie), so we stream
/// chunks and abort the moment the accumulated body exceeds the cap rather than
/// buffering whatever the server decides to send.
async fn read_capped_json<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    if let Some(len) = resp.content_length() {
        if len > MAX_RPC_BODY_BYTES as u64 {
            return Err(ScanError::Network(format!(
                "AUR response too large: {len} bytes > {MAX_RPC_BODY_BYTES} cap"
            )));
        }
    }
    let mut resp = resp;
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ScanError::Network(format!("Failed to read response: {e}")))?
    {
        if body.len() + chunk.len() > MAX_RPC_BODY_BYTES {
            return Err(ScanError::Network(format!(
                "AUR response exceeded {MAX_RPC_BODY_BYTES} byte cap; aborting read"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|e| ScanError::Network(format!("Failed to parse response: {e}")))
}

/// Information about an AUR package from the RPC API
#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct AurPackageInfo {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "Maintainer")]
    pub maintainer: Option<String>,
    #[serde(rename = "NumVotes")]
    pub num_votes: Option<i32>,
    #[serde(rename = "Popularity")]
    pub popularity: Option<f64>,
    #[serde(rename = "OutOfDate")]
    pub out_of_date: Option<i64>,
    #[serde(rename = "FirstSubmitted")]
    pub first_submitted: Option<i64>,
    #[serde(rename = "LastModified")]
    pub last_modified: Option<i64>,
    #[serde(rename = "PackageBase")]
    pub package_base: String,
    /// Runtime dependencies (may carry version constraints).
    #[serde(rename = "Depends", default)]
    pub depends: Vec<String>,
    /// Build-time dependencies.
    #[serde(rename = "MakeDepends", default)]
    pub make_depends: Vec<String>,
    /// Test-time dependencies.
    #[serde(rename = "CheckDepends", default)]
    pub check_depends: Vec<String>,
    /// Optional dependencies (may carry ": description").
    #[serde(rename = "OptDepends", default)]
    pub opt_depends: Vec<String>,
    /// Virtual names this package provides.
    #[serde(rename = "Provides", default)]
    pub provides: Vec<String>,
}

/// RPC API response wrapper
#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[serde(rename = "type")]
    response_type: String,
    results: Vec<AurPackageInfo>,
    #[serde(default)]
    error: Option<String>,
}

/// Fetched AUR package with local path to PKGBUILD
pub struct FetchedPackage {
    /// Package information from AUR
    pub info: AurPackageInfo,
    /// Temporary directory containing the cloned repo
    pub temp_dir: TempDir,
    /// Path to the PKGBUILD file
    pub pkgbuild_path: PathBuf,
    /// Path to install script if present
    pub install_script_path: Option<PathBuf>,
}

/// AUR client for fetching package information and PKGBUILDs
pub struct AurClient {
    http_client: reqwest::Client,
}

impl AurClient {
    /// Create a new AUR client.
    ///
    /// Hardened against SSRF/downgrade: redirects are refused outright (the AUR
    /// RPC never needs them, and a followed redirect is the classic SSRF
    /// amplifier), and `https_only` guarantees no request — including any
    /// redirect hop — is ever made over plaintext.
    pub fn new() -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .user_agent(format!("aur-scan/{}", crate::VERSION))
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .build()
            .map_err(|e| ScanError::Network(e.to_string()))?;

        Ok(Self { http_client })
    }

    /// Build an RPC URL with `segments` appended as percent-encoded path
    /// components. Using `path_segments_mut` (not `format!`) means an attacker
    /// cannot inject `?`, `#`, `&`, `/`, or whitespace into the request.
    fn rpc_url(segments: &[&str]) -> Result<reqwest::Url> {
        let mut url = reqwest::Url::parse(AUR_RPC_URL)
            .map_err(|e| ScanError::Network(format!("invalid base URL: {e}")))?;
        url.path_segments_mut()
            .map_err(|_| ScanError::Network("base URL cannot be a base".into()))?
            .extend(segments);
        Ok(url)
    }

    /// Get package information from AUR RPC API
    pub async fn get_package_info(&self, package_name: &str) -> Result<AurPackageInfo> {
        // Reject illegal names before they reach the network: a name is also a
        // URL path segment, and downstream a filesystem path component.
        validate_package_name(package_name)?;
        let url = Self::rpc_url(&["info", package_name])?;
        debug!("Fetching package info from: {}", url);

        let response: RpcResponse =
            read_capped_json(
                self.http_client.get(url).send().await.map_err(|e| {
                    ScanError::Network(format!("Failed to fetch package info: {}", e))
                })?,
            )
            .await?;

        // Validate response type
        if response.response_type == "error" {
            let msg = response
                .error
                .unwrap_or_else(|| "Unknown error".to_string());
            return Err(ScanError::Network(format!("AUR API error: {}", msg)));
        }

        if let Some(error) = response.error {
            return Err(ScanError::Network(format!("AUR API error: {}", error)));
        }

        // Do not trust `resultcount`; use the actual array so a lying count
        // (e.g. count:1, results:[]) cannot panic the process.
        response.results.into_iter().next().ok_or_else(|| {
            ScanError::NotFound(format!("Package '{}' not found in AUR", package_name))
        })
    }

    /// Search for packages in AUR.
    ///
    /// `query` is free-form, but it is appended as a percent-encoded path
    /// segment by `rpc_url`, so it cannot inject extra path/query/fragment
    /// components. (No CLI surface currently calls this; if one is added,
    /// consider the AUR `by`/`arg` query form for multi-word searches.)
    pub async fn search(&self, query: &str) -> Result<Vec<AurPackageInfo>> {
        let url = Self::rpc_url(&["search", query])?;
        debug!("Searching AUR: {}", url);

        let response: RpcResponse = read_capped_json(
            self.http_client
                .get(url)
                .send()
                .await
                .map_err(|e| ScanError::Network(format!("Failed to search: {}", e)))?,
        )
        .await?;

        // Validate response type
        if response.response_type == "error" {
            let msg = response
                .error
                .unwrap_or_else(|| "Unknown error".to_string());
            return Err(ScanError::Network(format!("AUR API error: {}", msg)));
        }

        if let Some(error) = response.error {
            return Err(ScanError::Network(format!("AUR API error: {}", error)));
        }

        Ok(response.results)
    }

    /// Clone an AUR package's git repository into `dest` (an existing, empty
    /// directory), with full hardening against repo-side code execution and
    /// option/protocol abuse. The same routine backs both scanning and the
    /// race-free build path, so the bytes built are the bytes scanned.
    ///
    /// Hardening:
    ///  - core.hooksPath=/dev/null : never run hooks from the clone
    ///  - protocol.{file,ext}.allow=never : block file:// and ext:: vectors
    ///  - core.symlinks=false : write symlinks as plain files (no escape)
    ///  - --no-recurse-submodules : never fetch/initialize submodules
    ///  - GIT_TERMINAL_PROMPT=0 : never block on a credential prompt
    ///  - `--` before the URL : the URL can never be parsed as an option
    pub async fn clone_repo(&self, package_base: &str, dest: &Path) -> Result<()> {
        // `package_base` comes from attacker-controlled RPC JSON and is about to
        // become a URL path. Reject anything that is not a bare package
        // identifier so it cannot alter the URL path (e.g. `../../other`).
        validate_package_name(package_base)?;
        let git_url = format!("{}/{}.git", AUR_GIT_URL, package_base);
        debug!("Cloning {} into {}", git_url, dest.display());
        let output = tokio::process::Command::new("git")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "protocol.file.allow=never",
                "-c",
                "protocol.ext.allow=never",
                "-c",
                "core.symlinks=false",
                "clone",
                "--depth=1",
                "--no-tags",
                "--no-recurse-submodules",
                "--",
                &git_url,
                ".",
            ])
            .current_dir(dest)
            .output()
            .await
            .map_err(|e| {
                ScanError::Io(std::io::Error::other(format!("Failed to run git: {}", e)))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ScanError::Network(format!(
                "Failed to clone AUR repo: {}",
                stderr
            )));
        }
        Ok(())
    }

    /// Fetch PKGBUILD by cloning the AUR git repository
    pub async fn fetch_pkgbuild(&self, package_name: &str) -> Result<FetchedPackage> {
        // First get package info to find the package base
        let info = self.get_package_info(package_name).await?;

        info!(
            "Fetching PKGBUILD for {} (base: {})",
            package_name, info.package_base
        );

        // Create temp directory
        let temp_dir = TempDir::new().map_err(|e| {
            ScanError::Io(std::io::Error::other(format!(
                "Failed to create temp directory: {}",
                e
            )))
        })?;

        // Clone the AUR git repo into the temp directory (hardened).
        self.clone_repo(&info.package_base, temp_dir.path()).await?;

        let pkgbuild_path = temp_dir.path().join("PKGBUILD");
        if !pkgbuild_path.exists() {
            return Err(ScanError::NotFound(
                "PKGBUILD not found in cloned repository".to_string(),
            ));
        }

        // Check for install script
        let install_script_path = find_install_script(temp_dir.path(), &info.package_base);

        Ok(FetchedPackage {
            info,
            temp_dir,
            pkgbuild_path,
            install_script_path,
        })
    }

    /// Check whether a package is present in the AUR.
    ///
    /// Returns `Ok(true)` when the RPC authoritatively reports the package
    /// present, `Ok(false)` when it authoritatively reports it absent
    /// (`NotFound`), and `Err(..)` when the lookup could not be completed at all
    /// (network/timeout/parse/API error).
    ///
    /// SECURITY: never collapse an error into `false`. The previous version
    /// returned a bare `bool` via `.is_ok()`, so a transient RPC blip silently
    /// became "does not exist" -> `is_aur_package` reported "not AUR" -> the
    /// wrapper installed the package UNSCANNED (fail-open). Callers that gate on
    /// this MUST treat `Err` as "could not determine" and fail closed: assume the
    /// package may be in the AUR and scan it.
    pub async fn package_exists(&self, package_name: &str) -> Result<bool> {
        match self.get_package_info(package_name).await {
            Ok(_) => Ok(true),
            // Authoritative "not in the AUR" -- the only result that may safely
            // be reported as absent.
            Err(ScanError::NotFound(_)) => Ok(false),
            // Anything else (network/timeout/parse/API error) is indeterminate;
            // surface it so the caller can fail closed instead of guessing.
            Err(e) => Err(e),
        }
    }

    /// Get info for multiple packages at once
    pub async fn get_multiple_info(&self, package_names: &[&str]) -> Result<Vec<AurPackageInfo>> {
        if package_names.is_empty() {
            return Ok(Vec::new());
        }

        // Only query syntactically legal names. An illegal name cannot be a real
        // AUR package, and feeding it to the query builder unencoded would let it
        // inject extra `arg[]` parameters. Drop-and-warn rather than fail the
        // whole batch so one bad dependency name doesn't abort resolution.
        let mut url = reqwest::Url::parse(&format!("{}/info", AUR_RPC_URL))
            .map_err(|e| ScanError::Network(format!("invalid base URL: {e}")))?;
        {
            let mut qp = url.query_pairs_mut();
            for name in package_names {
                if crate::validate::is_valid_package_name(name) {
                    qp.append_pair("arg[]", name);
                } else {
                    warn!("skipping illegal package name in batch query: {name:?}");
                }
            }
        }

        debug!("Fetching info for {} packages", package_names.len());

        let response: RpcResponse =
            read_capped_json(
                self.http_client.get(url).send().await.map_err(|e| {
                    ScanError::Network(format!("Failed to fetch package info: {}", e))
                })?,
            )
            .await?;

        // Validate response type
        if response.response_type == "error" {
            let msg = response
                .error
                .unwrap_or_else(|| "Unknown error".to_string());
            return Err(ScanError::Network(format!("AUR API error: {}", msg)));
        }

        if let Some(error) = response.error {
            return Err(ScanError::Network(format!("AUR API error: {}", error)));
        }

        Ok(response.results)
    }
}

/// Abstract source of AUR package metadata, so dependency resolution can be
/// unit-tested without network access.
#[async_trait::async_trait]
pub trait PackageInfoSource: Send + Sync {
    /// Batch-fetch info for `names`. Names that are not AUR packages (official
    /// repo or virtual) are simply absent from the returned vector.
    async fn info_batch(&self, names: &[&str]) -> Result<Vec<AurPackageInfo>>;
}

#[async_trait::async_trait]
impl PackageInfoSource for AurClient {
    async fn info_batch(&self, names: &[&str]) -> Result<Vec<AurPackageInfo>> {
        self.get_multiple_info(names).await
    }
}

/// Find install script in a package directory by its common filenames.
///
/// This only probes well-known filenames; it deliberately does NOT re-read the
/// PKGBUILD to resolve an `install=` value. The scanner already reads the
/// PKGBUILD exactly once and resolves the install script from that single
/// parsed copy (see `resolve_install_path` in `lib.rs`); re-reading the file
/// here opened a time-of-check/time-of-use gap (the bytes resolved could differ
/// from the bytes parsed) for a value nothing downstream consumes.
fn find_install_script(dir: &Path, package_base: &str) -> Option<PathBuf> {
    let patterns = [
        format!("{}.install", package_base),
        "install".to_string(),
        format!("{}.install", package_base.replace("-", "_")),
    ];

    for pattern in &patterns {
        let path = dir.join(pattern);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

/// Decide whether the install gate should treat a package as AUR (and therefore
/// scan it), given the two upstream signals. Kept pure so the fail-closed
/// contract is unit-testable without touching the network or pacman.
///
/// * `in_official_repos` -- pacman authoritatively found it in the official repos.
/// * `aur_lookup` -- the outcome of the AUR membership lookup: `Ok(true)` present,
///   `Ok(false)` authoritatively absent, `Err(..)` could-not-determine.
///
/// Fail-closed rule: an indeterminate AUR lookup (`Err`) is treated as "may be
/// AUR" so the package is scanned rather than waved through. Only an
/// authoritative answer (in official repos, or a definitive AUR present/absent)
/// is allowed to skip the AUR scan.
fn classify_aur_membership(in_official_repos: bool, aur_lookup: Result<bool>) -> bool {
    if in_official_repos {
        return false; // authoritatively official -> not an AUR package
    }
    // `Ok(present)` -> use the authoritative answer; `Err(..)` could not be
    // determined -> fail closed -> treat as AUR -> scan.
    aur_lookup.unwrap_or(true)
}

/// Check if a package is from AUR (not in official repos).
///
/// Fails CLOSED: if AUR membership cannot be determined (e.g. a transient RPC
/// error), the package is reported as AUR so the gate scans it. The only ways to
/// return `Ok(false)` ("not AUR, skip the scan") are an authoritative
/// official-repo hit or an authoritative AUR "not found".
pub async fn is_aur_package(package_name: &str) -> Result<bool> {
    // Check if it's in official repos using pacman
    // `--` ensures a name that begins with `-` can never be parsed as a flag.
    let output = tokio::process::Command::new("pacman")
        .args(["-Si", "--", package_name])
        .output()
        .await
        .map_err(ScanError::Io)?;

    let in_official_repos = output.status.success();

    // Only consult the AUR when pacman did not authoritatively place the package
    // in the official repos. The lookup result (including any error) is fed to
    // the fail-closed classifier.
    let aur_lookup = if in_official_repos {
        Ok(false)
    } else {
        let client = AurClient::new()?;
        let lookup = client.package_exists(package_name).await;
        if let Err(e) = &lookup {
            warn!(
                "AUR membership check for {package_name:?} could not be completed \
                 ({e}); treating as AUR (fail closed) so it is scanned"
            );
        }
        lookup
    };

    Ok(classify_aur_membership(in_official_repos, aur_lookup))
}

/// Get list of installed AUR packages
pub async fn get_installed_aur_packages() -> Result<Vec<String>> {
    let output = tokio::process::Command::new("pacman")
        .args(["-Qm"])
        .output()
        .await
        .map_err(ScanError::Io)?;

    if !output.status.success() {
        return Err(ScanError::Io(std::io::Error::other(
            "Failed to get foreign packages",
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let packages: Vec<String> = stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(|s| s.to_string())
        .collect();

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Hits the live AUR RPC. Ignored by default so CI (sandboxed, no outbound
    // network) stays deterministic; run locally with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "requires live network access to aur.archlinux.org"]
    async fn test_get_package_info() {
        let client = AurClient::new().unwrap();
        // paru is a well-known AUR package
        let info = client.get_package_info("paru").await;
        assert!(info.is_ok());
        let info = info.unwrap();
        assert_eq!(info.name, "paru");
    }

    // Hits the live AUR RPC. Ignored by default for the same reason as
    // test_get_package_info; run locally with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "requires live network access to aur.archlinux.org"]
    async fn test_package_not_found() {
        let client = AurClient::new().unwrap();
        let info = client
            .get_package_info("this-package-definitely-does-not-exist-12345")
            .await;
        assert!(info.is_err());
    }

    // --- fail-closed AUR classification (defect #1) ---------------------------
    // The security contract: an indeterminate AUR lookup must NOT downgrade a
    // package to "not AUR" and let it install unscanned. Only an authoritative
    // answer may skip the scan.

    #[test]
    fn official_repo_package_is_not_scanned_as_aur() {
        // pacman authoritatively owns it -> not AUR, regardless of the AUR side.
        assert!(!classify_aur_membership(true, Ok(false)));
        assert!(!classify_aur_membership(
            true,
            Err(ScanError::Network("ignored".into()))
        ));
    }

    #[test]
    fn present_in_aur_is_scanned() {
        assert!(classify_aur_membership(false, Ok(true)));
    }

    #[test]
    fn authoritatively_absent_is_not_scanned() {
        // Not in official repos and the AUR definitively has no such package:
        // nothing to scan (the helper will fail to find it too).
        assert!(!classify_aur_membership(false, Ok(false)));
    }

    #[test]
    fn indeterminate_aur_lookup_fails_closed_and_is_scanned() {
        // The regression for defect #1: a transient RPC/network error must be
        // treated as "could be AUR" so the package is SCANNED, not skipped.
        // Before the fix `package_exists` collapsed this error into `false`,
        // so the package slipped through unscanned.
        for err in [
            ScanError::Network("timeout".into()),
            ScanError::Network("AUR API error: rate limited".into()),
        ] {
            assert!(
                classify_aur_membership(false, Err(err)),
                "an indeterminate AUR lookup must fail closed (scan)"
            );
        }
    }
}
