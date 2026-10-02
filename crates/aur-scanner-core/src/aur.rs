//! AUR package fetching and information retrieval
//!
//! Provides functionality to fetch PKGBUILDs directly from the AUR
//! before installation for pre-emptive security scanning.

use crate::error::{Result, ScanError};
use crate::validate::validate_package_name;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;
use tracing::{debug, info, warn};

/// AUR RPC API base URL
const AUR_RPC_URL: &str = "https://aur.archlinux.org/rpc/v5";

/// Default network/clone deadline, matching `ScanConfig::timeout_seconds`.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

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
    /// Deadline for one `git clone` (from `ScanConfig::timeout_seconds`).
    clone_timeout: Duration,
}

impl AurClient {
    /// Create a new AUR client.
    ///
    /// Hardened against SSRF/downgrade: redirects are refused outright (the AUR
    /// RPC never needs them, and a followed redirect is the classic SSRF
    /// amplifier), and `https_only` guarantees no request — including any
    /// redirect hop — is ever made over plaintext.
    pub fn new() -> Result<Self> {
        Self::with_timeout(DEFAULT_TIMEOUT_SECS)
    }

    /// Like [`Self::new`], with the RPC request and `git clone` deadline set from
    /// `ScanConfig::timeout_seconds` (clamped to at least one second).
    pub fn with_timeout(timeout_seconds: u64) -> Result<Self> {
        let timeout = Duration::from_secs(timeout_seconds.max(1));
        let http_client = reqwest::Client::builder()
            .user_agent(format!("aur-scan/{}", crate::VERSION))
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .build()
            .map_err(|e| ScanError::Network(e.to_string()))?;

        Ok(Self {
            http_client,
            clone_timeout: timeout,
        })
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

    /// Search the AUR for packages that declare `name` in `provides=`
    /// (`search/{name}?by=provides`).
    pub async fn search_providers(&self, name: &str) -> Result<Vec<AurPackageInfo>> {
        validate_package_name(name)?;
        let mut url = Self::rpc_url(&["search", name])?;
        url.query_pairs_mut().append_pair("by", "provides");
        debug!("Searching AUR providers: {}", url);
        let response: RpcResponse = read_capped_json(
            self.http_client
                .get(url)
                .send()
                .await
                .map_err(|e| ScanError::Network(format!("Failed to search: {}", e)))?,
        )
        .await?;
        if response.response_type == "error" || response.error.is_some() {
            return Err(ScanError::Network(format!(
                "AUR API error: {}",
                response.error.unwrap_or_else(|| "Unknown error".into())
            )));
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
    ///  - env_clear + allowlist : no inherited `GIT_SSL_NO_VERIFY`, `GIT_SSH`,
    ///    `GIT_CONFIG_*`, `GIT_PROXY_COMMAND`, ...; system and global git config
    ///    are ignored
    ///  - transfer.fsckObjects=true : reject malformed/malicious objects
    ///  - a hard deadline: the child is killed when it elapses
    pub async fn clone_repo(&self, package_base: &str, dest: &Path) -> Result<()> {
        // `package_base` comes from attacker-controlled RPC JSON and is about to
        // become a URL path. Reject anything that is not a bare package
        // identifier so it cannot alter the URL path (e.g. `../../other`).
        validate_package_name(package_base)?;
        let git_url = format!("{}/{}.git", AUR_GIT_URL, package_base);
        debug!("Cloning {} into {}", git_url, dest.display());
        let mut cmd = tokio::process::Command::new("git");
        cmd.env_clear();
        for (k, v) in git_clone_env(std::env::vars()) {
            cmd.env(k, v);
        }
        cmd.args(git_clone_args(&git_url)).current_dir(dest);
        let output = output_with_deadline(cmd, self.clone_timeout).await?;

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

/// Environment variables a hardened `git clone` may inherit: locale and proxy
/// settings only. Everything else (notably every `GIT_*` variable, `SSL_CERT_*`,
/// `LD_*`) is dropped, because each is a way to disable verification or redirect
/// the transport.
const GIT_ENV_ALLOW: &[&str] = &[
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "all_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
];

/// Build the sanitized environment for `git clone` from the ambient one.
fn git_clone_env<I>(ambient: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut env: Vec<(String, String)> = ambient
        .into_iter()
        .filter(|(k, _)| GIT_ENV_ALLOW.contains(&k.as_str()))
        .collect();
    env.extend(
        [
            ("PATH", "/usr/bin:/bin:/usr/local/bin"),
            ("GIT_TERMINAL_PROMPT", "0"),
            // Do not read /etc/gitconfig or ~/.gitconfig (insteadOf rewrites,
            // credential helpers, sslVerify=false, ...).
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string())),
    );
    env
}

/// Arguments for the hardened clone of `git_url` into the current directory.
fn git_clone_args(git_url: &str) -> Vec<String> {
    [
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "core.symlinks=false",
        "-c",
        "transfer.fsckObjects=true",
        "clone",
        "--depth=1",
        "--no-tags",
        "--no-recurse-submodules",
        "--",
        git_url,
        ".",
    ]
    .map(String::from)
    .to_vec()
}

/// Run `cmd` to completion, but give up (killing the child) after `deadline`.
/// A timeout is an error, never a partial success.
pub async fn output_with_deadline(
    mut cmd: tokio::process::Command,
    deadline: Duration,
) -> Result<std::process::Output> {
    cmd.kill_on_drop(true).stdin(std::process::Stdio::null());
    match tokio::time::timeout(deadline, cmd.output()).await {
        Ok(Ok(out)) => Ok(out),
        Ok(Err(e)) => Err(ScanError::Io(std::io::Error::other(format!(
            "Failed to run {:?}: {e}",
            cmd.as_std().get_program()
        )))),
        Err(_) => Err(ScanError::Timeout(deadline.as_secs())),
    }
}

/// Overall per-package deadline derived from `ScanConfig::timeout_seconds`: the
/// fetch gets `timeout_seconds` and the scan the same again.
pub fn package_deadline(timeout_seconds: u64) -> Duration {
    Duration::from_secs(timeout_seconds.max(1).saturating_mul(2))
}

/// Await `fut` for at most `deadline`; elapsing is a [`ScanError::Timeout`]
/// (callers must treat it as "not reviewed", i.e. fail closed).
pub async fn with_deadline<T>(
    deadline: Duration,
    fut: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    match tokio::time::timeout(deadline, fut).await {
        Ok(r) => r,
        Err(_) => Err(ScanError::Timeout(deadline.as_secs())),
    }
}

/// SHA-256 of every file under `dir` (skipping `.git`), keyed by relative path.
/// Symlinks are recorded by target, never followed. Taken at scan time and
/// compared again immediately before building, so a directory modified between
/// scan and build is detected.
pub fn snapshot_dir(dir: &Path) -> Result<BTreeMap<String, String>> {
    use sha2::{Digest, Sha256};
    fn walk(root: &Path, cur: &Path, out: &mut BTreeMap<String, String>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(cur)? {
            let entry = entry?;
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            let ft = entry.file_type()?;
            if ft.is_symlink() {
                let target = std::fs::read_link(&path)?;
                out.insert(rel, format!("symlink:{}", target.display()));
            } else if ft.is_dir() {
                if entry.file_name() == ".git" {
                    continue;
                }
                walk(root, &path, out)?;
            } else {
                let mut h = Sha256::new();
                let mut f = std::fs::File::open(&path)?;
                std::io::copy(&mut f, &mut h)?;
                let d = h.finalize();
                out.insert(rel, d.iter().map(|b| format!("{b:02x}")).collect());
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out)?;
    Ok(out)
}

/// Compare `dir` against an earlier [`snapshot_dir`]; returns the paths that were
/// added, removed or modified (empty = unchanged).
pub fn snapshot_changes(dir: &Path, before: &BTreeMap<String, String>) -> Result<Vec<String>> {
    let now = snapshot_dir(dir)?;
    let mut changed = Vec::new();
    for (k, v) in before {
        match now.get(k) {
            None => changed.push(format!("{k} (removed)")),
            Some(nv) if nv != v => changed.push(format!("{k} (modified)")),
            _ => {}
        }
    }
    for k in now.keys() {
        if !before.contains_key(k) {
            changed.push(format!("{k} (added)"));
        }
    }
    Ok(changed)
}

/// Abstract source of AUR package metadata, so dependency resolution can be
/// unit-tested without network access.
#[async_trait::async_trait]
pub trait PackageInfoSource: Send + Sync {
    /// Batch-fetch info for `names`. Names that are not AUR packages (official
    /// repo or virtual) are simply absent from the returned vector.
    async fn info_batch(&self, names: &[&str]) -> Result<Vec<AurPackageInfo>>;

    /// Names of AUR packages that declare `name` in `provides=`. The default is
    /// "none", which fails closed (an unsatisfied virtual dependency becomes
    /// unresolved rather than trusted).
    async fn find_providers(&self, _name: &str) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}

#[async_trait::async_trait]
impl PackageInfoSource for AurClient {
    async fn info_batch(&self, names: &[&str]) -> Result<Vec<AurPackageInfo>> {
        self.get_multiple_info(names).await
    }

    async fn find_providers(&self, name: &str) -> Result<Vec<String>> {
        Ok(self
            .search_providers(name)
            .await?
            .into_iter()
            .map(|i| i.name)
            .collect())
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

/// Every package name in the configured official repositories.
///
/// Read from the local pacman sync databases -- no network, no new parsing
/// dependency, and exactly the set of names the user's own pacman would resolve.
/// Used as the trusted corpus for name-impersonation comparison.
///
/// Returns an empty vector rather than an error when pacman is unavailable or
/// the sync databases have never been populated. A missing corpus must make the
/// name analyzer quieter, never noisier: there is no safe way to guess at what
/// is official, so we simply do not compare.
pub async fn official_package_names() -> Vec<String> {
    let output = match tokio::process::Command::new("pacman")
        .args(["-Slq"])
        .output()
        .await
    {
        Ok(o) if o.status.success() => o,
        Ok(_) => {
            debug!("pacman -Slq returned non-zero; skipping official-name comparison");
            return Vec::new();
        }
        Err(e) => {
            debug!("pacman unavailable ({e}); skipping official-name comparison");
            return Vec::new();
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut names: Vec<String> = stdout
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|s| s.to_string())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Whether a package name exists in the official repositories.
pub async fn is_official_package(name: &str) -> bool {
    // `--` so a name beginning with `-` can never be parsed as a flag.
    tokio::process::Command::new("pacman")
        .args(["-Si", "--", name])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
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

    // --- hardened clone (git env/args, deadline) -------------------------------

    #[test]
    fn git_env_drops_poison_and_isolates_config() {
        let ambient = [
            ("GIT_SSL_NO_VERIFY", "1"),
            ("GIT_SSH_COMMAND", "evil"),
            ("GIT_CONFIG_GLOBAL", "/tmp/evil"),
            ("GIT_PROXY_COMMAND", "evil"),
            ("SSL_CERT_FILE", "/tmp/ca"),
            ("LD_PRELOAD", "/tmp/x.so"),
            ("PATH", "/tmp/evil"),
            ("HOME", "/home/u"),
            ("LANG", "C"),
            ("HTTPS_PROXY", "http://proxy:3128"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()));
        let env = git_clone_env(ambient);
        let get = |k: &str| {
            env.iter()
                .filter(|(ek, _)| ek == k)
                .map(|(_, v)| v.as_str())
                .collect::<Vec<_>>()
        };
        assert!(get("GIT_SSL_NO_VERIFY").is_empty());
        assert!(get("GIT_SSH_COMMAND").is_empty());
        assert!(get("GIT_PROXY_COMMAND").is_empty());
        assert!(get("SSL_CERT_FILE").is_empty());
        assert!(get("LD_PRELOAD").is_empty());
        assert_eq!(get("GIT_CONFIG_GLOBAL"), vec!["/dev/null"]);
        assert_eq!(get("GIT_CONFIG_NOSYSTEM"), vec!["1"]);
        assert_eq!(get("GIT_TERMINAL_PROMPT"), vec!["0"]);
        assert_eq!(get("PATH"), vec!["/usr/bin:/bin:/usr/local/bin"]);
        assert_eq!(get("HOME"), vec!["/home/u"]);
        assert_eq!(get("HTTPS_PROXY"), vec!["http://proxy:3128"]);
    }

    #[test]
    fn git_args_enable_fsck_and_end_options_before_url() {
        let a = git_clone_args("https://aur.archlinux.org/x.git");
        assert!(a
            .windows(2)
            .any(|w| w == ["-c", "transfer.fsckObjects=true"]));
        assert!(a
            .windows(2)
            .any(|w| w == ["-c", "core.hooksPath=/dev/null"]));
        let dd = a.iter().position(|x| x == "--").unwrap();
        assert_eq!(a[dd + 1], "https://aur.archlinux.org/x.git");
    }

    #[tokio::test]
    async fn child_is_killed_when_the_deadline_elapses() {
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("30");
        let start = std::time::Instant::now();
        let r = output_with_deadline(cmd, Duration::from_millis(150)).await;
        assert!(matches!(r, Err(ScanError::Timeout(_))), "{r:?}");
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn with_deadline_fails_closed_on_timeout() {
        let r: Result<()> = with_deadline(Duration::from_millis(50), async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(())
        })
        .await;
        assert!(matches!(r, Err(ScanError::Timeout(_))));
        let ok: Result<u8> = with_deadline(Duration::from_secs(5), async { Ok(7) }).await;
        assert_eq!(ok.unwrap(), 7);
    }

    #[test]
    fn package_deadline_is_derived_from_config() {
        assert_eq!(package_deadline(30), Duration::from_secs(60));
        assert_eq!(package_deadline(0), Duration::from_secs(2));
    }

    // --- scanned-directory snapshot (TOCTOU re-verification) -------------------

    #[test]
    fn snapshot_detects_modified_added_and_removed_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("PKGBUILD"), "pkgname=a\n").unwrap();
        std::fs::write(dir.path().join("a.install"), "post_install() { :; }\n").unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/HEAD"), "x").unwrap();
        let snap = snapshot_dir(dir.path()).unwrap();
        assert!(snap.contains_key("PKGBUILD") && !snap.keys().any(|k| k.starts_with(".git")));
        assert!(snapshot_changes(dir.path(), &snap).unwrap().is_empty());

        // .git churn is ignored; real file changes are not.
        std::fs::write(dir.path().join(".git/HEAD"), "y").unwrap();
        assert!(snapshot_changes(dir.path(), &snap).unwrap().is_empty());

        std::fs::write(dir.path().join("PKGBUILD"), "pkgname=a\ncurl x|sh\n").unwrap();
        std::fs::remove_file(dir.path().join("a.install")).unwrap();
        std::fs::write(dir.path().join("evil.patch"), "x").unwrap();
        let mut ch = snapshot_changes(dir.path(), &snap).unwrap();
        ch.sort();
        assert_eq!(
            ch,
            vec![
                "PKGBUILD (modified)",
                "a.install (removed)",
                "evil.patch (added)"
            ]
        );
    }
}
