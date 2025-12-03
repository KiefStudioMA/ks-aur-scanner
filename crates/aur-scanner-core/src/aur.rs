//! AUR package fetching and information retrieval
//!
//! Provides functionality to fetch PKGBUILDs directly from the AUR
//! before installation for pre-emptive security scanning.

use crate::error::{Result, ScanError};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tracing::{debug, info};

/// AUR RPC API base URL
const AUR_RPC_URL: &str = "https://aur.archlinux.org/rpc/v5";

/// AUR Git base URL
const AUR_GIT_URL: &str = "https://aur.archlinux.org";

/// Information about an AUR package from the RPC API
#[derive(Debug, Clone, Deserialize)]
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
}

/// RPC API response wrapper
#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[serde(rename = "type")]
    response_type: String,
    resultcount: i32,
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
    /// Create a new AUR client
    pub fn new() -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .user_agent(format!("aur-scan/{}", crate::VERSION))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| ScanError::Network(e.to_string()))?;

        Ok(Self { http_client })
    }

    /// Get package information from AUR RPC API
    pub async fn get_package_info(&self, package_name: &str) -> Result<AurPackageInfo> {
        let url = format!("{}/info/{}", AUR_RPC_URL, package_name);
        debug!("Fetching package info from: {}", url);

        let response: RpcResponse = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| ScanError::Network(format!("Failed to fetch package info: {}", e)))?
            .json()
            .await
            .map_err(|e| ScanError::Network(format!("Failed to parse response: {}", e)))?;

        // Validate response type
        if response.response_type == "error" {
            let msg = response.error.unwrap_or_else(|| "Unknown error".to_string());
            return Err(ScanError::Network(format!("AUR API error: {}", msg)));
        }

        if let Some(error) = response.error {
            return Err(ScanError::Network(format!("AUR API error: {}", error)));
        }

        if response.resultcount == 0 {
            return Err(ScanError::NotFound(format!(
                "Package '{}' not found in AUR",
                package_name
            )));
        }

        Ok(response.results.into_iter().next().unwrap())
    }

    /// Search for packages in AUR
    pub async fn search(&self, query: &str) -> Result<Vec<AurPackageInfo>> {
        let url = format!("{}/search/{}", AUR_RPC_URL, query);
        debug!("Searching AUR: {}", url);

        let response: RpcResponse = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| ScanError::Network(format!("Failed to search: {}", e)))?
            .json()
            .await
            .map_err(|e| ScanError::Network(format!("Failed to parse response: {}", e)))?;

        // Validate response type
        if response.response_type == "error" {
            let msg = response.error.unwrap_or_else(|| "Unknown error".to_string());
            return Err(ScanError::Network(format!("AUR API error: {}", msg)));
        }

        if let Some(error) = response.error {
            return Err(ScanError::Network(format!("AUR API error: {}", error)));
        }

        Ok(response.results)
    }

    /// Fetch PKGBUILD by cloning the AUR git repository
    pub async fn fetch_pkgbuild(&self, package_name: &str) -> Result<FetchedPackage> {
        // First get package info to find the package base
        let info = self.get_package_info(package_name).await?;

        info!("Fetching PKGBUILD for {} (base: {})", package_name, info.package_base);

        // Create temp directory
        let temp_dir = TempDir::new()
            .map_err(|e| ScanError::Io(std::io::Error::other(
                format!("Failed to create temp directory: {}", e),
            )))?;

        // Clone the AUR git repo
        let git_url = format!("{}/{}.git", AUR_GIT_URL, info.package_base);
        debug!("Cloning from: {}", git_url);

        let output = tokio::process::Command::new("git")
            .args(["clone", "--depth=1", &git_url, "."])
            .current_dir(temp_dir.path())
            .output()
            .await
            .map_err(|e| ScanError::Io(std::io::Error::other(
                format!("Failed to run git: {}", e),
            )))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ScanError::Network(format!(
                "Failed to clone AUR repo: {}",
                stderr
            )));
        }

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

    /// Check if a package exists in AUR
    pub async fn package_exists(&self, package_name: &str) -> bool {
        self.get_package_info(package_name).await.is_ok()
    }

    /// Get info for multiple packages at once
    pub async fn get_multiple_info(&self, package_names: &[&str]) -> Result<Vec<AurPackageInfo>> {
        if package_names.is_empty() {
            return Ok(Vec::new());
        }

        let args: Vec<String> = package_names
            .iter()
            .map(|n| format!("arg[]={}", n))
            .collect();
        let url = format!("{}/info?{}", AUR_RPC_URL, args.join("&"));

        debug!("Fetching info for {} packages", package_names.len());

        let response: RpcResponse = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| ScanError::Network(format!("Failed to fetch package info: {}", e)))?
            .json()
            .await
            .map_err(|e| ScanError::Network(format!("Failed to parse response: {}", e)))?;

        // Validate response type
        if response.response_type == "error" {
            let msg = response.error.unwrap_or_else(|| "Unknown error".to_string());
            return Err(ScanError::Network(format!("AUR API error: {}", msg)));
        }

        if let Some(error) = response.error {
            return Err(ScanError::Network(format!("AUR API error: {}", error)));
        }

        Ok(response.results)
    }
}

impl Default for AurClient {
    fn default() -> Self {
        Self::new().expect("Failed to create AUR client")
    }
}

/// Find install script in a package directory
fn find_install_script(dir: &Path, package_base: &str) -> Option<PathBuf> {
    // Common patterns for install scripts
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

    // Also check PKGBUILD for install= line
    let pkgbuild_path = dir.join("PKGBUILD");
    if let Ok(content) = std::fs::read_to_string(&pkgbuild_path) {
        for line in content.lines() {
            if let Some(install_file) = line.strip_prefix("install=") {
                let install_file = install_file
                    .trim()
                    .trim_matches(|c| c == '\'' || c == '"');
                let path = dir.join(install_file);
                if path.exists() {
                    return Some(path);
                }
            }
        }
    }

    None
}

/// Check if a package is from AUR (not in official repos)
pub async fn is_aur_package(package_name: &str) -> Result<bool> {
    // Check if it's in official repos using pacman
    let output = tokio::process::Command::new("pacman")
        .args(["-Si", package_name])
        .output()
        .await
        .map_err(ScanError::Io)?;

    // If pacman -Si succeeds, it's in official repos
    if output.status.success() {
        return Ok(false);
    }

    // Check if it exists in AUR
    let client = AurClient::new()?;
    Ok(client.package_exists(package_name).await)
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

    #[tokio::test]
    async fn test_get_package_info() {
        let client = AurClient::new().unwrap();
        // paru is a well-known AUR package
        let info = client.get_package_info("paru").await;
        assert!(info.is_ok());
        let info = info.unwrap();
        assert_eq!(info.name, "paru");
    }

    #[tokio::test]
    async fn test_package_not_found() {
        let client = AurClient::new().unwrap();
        let info = client.get_package_info("this-package-definitely-does-not-exist-12345").await;
        assert!(info.is_err());
    }
}
