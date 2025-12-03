//! Caching module for threat intelligence results

use crate::error::Result;
use serde::{de::DeserializeOwned, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Trait for cache implementations
pub trait Cache: Send + Sync {
    /// Get a cached value
    fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>>;

    /// Set a cached value with TTL
    fn set<T: Serialize>(&self, key: &str, value: &T, ttl: Duration) -> Result<()>;

    /// Clear the cache
    fn clear(&self) -> Result<()>;
}

/// Disk-based cache implementation
pub struct DiskCache {
    directory: PathBuf,
    max_size_bytes: usize,
}

impl DiskCache {
    /// Create a new disk cache
    pub fn new(directory: PathBuf, max_size_mb: usize) -> Result<Self> {
        std::fs::create_dir_all(&directory)?;
        Ok(Self {
            directory,
            max_size_bytes: max_size_mb * 1024 * 1024,
        })
    }

    fn key_to_path(&self, key: &str) -> PathBuf {
        let hash = blake3::hash(key.as_bytes());
        self.directory.join(format!("{}.json", hash.to_hex()))
    }

    /// Enforce cache size limit by removing oldest entries
    fn enforce_size_limit(&self) -> Result<()> {
        if !self.directory.exists() {
            return Ok(());
        }

        let mut entries: Vec<_> = std::fs::read_dir(&self.directory)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|ext| ext == "json").unwrap_or(false))
            .filter_map(|e| {
                let metadata = e.metadata().ok()?;
                let modified = metadata.modified().ok()?;
                Some((e.path(), metadata.len(), modified))
            })
            .collect();

        let total_size: u64 = entries.iter().map(|(_, size, _)| size).sum();

        if total_size as usize <= self.max_size_bytes {
            return Ok(());
        }

        // Sort by modification time (oldest first)
        entries.sort_by_key(|(_, _, modified)| *modified);

        // Remove oldest entries until under limit
        let mut current_size = total_size as usize;
        for (path, size, _) in entries {
            if current_size <= self.max_size_bytes {
                break;
            }
            if std::fs::remove_file(&path).is_ok() {
                current_size -= size as usize;
            }
        }

        Ok(())
    }
}

impl Cache for DiskCache {
    fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let path = self.key_to_path(key);

        if !path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&path)?;

        // Parse cached entry
        #[derive(serde::Deserialize)]
        struct CacheEntry<T> {
            expires_at: i64,
            value: T,
        }

        let entry: CacheEntry<T> = serde_json::from_str(&content)?;

        // Check if expired
        let now = chrono::Utc::now().timestamp();
        if now > entry.expires_at {
            let _ = std::fs::remove_file(&path);
            return Ok(None);
        }

        Ok(Some(entry.value))
    }

    fn set<T: Serialize>(&self, key: &str, value: &T, ttl: Duration) -> Result<()> {
        // Enforce cache size limit before writing
        self.enforce_size_limit()?;

        let path = self.key_to_path(key);

        #[derive(serde::Serialize)]
        struct CacheEntry<'a, T> {
            expires_at: i64,
            value: &'a T,
        }

        let entry = CacheEntry {
            expires_at: chrono::Utc::now().timestamp() + ttl.as_secs() as i64,
            value,
        };

        let content = serde_json::to_string(&entry)?;
        std::fs::write(&path, content)?;

        Ok(())
    }

    fn clear(&self) -> Result<()> {
        if self.directory.exists() {
            for entry in std::fs::read_dir(&self.directory)? {
                let entry = entry?;
                if entry.path().extension().map(|e| e == "json").unwrap_or(false) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        Ok(())
    }
}

/// No-op cache (disabled)
pub struct NoCache;

impl Cache for NoCache {
    fn get<T: DeserializeOwned>(&self, _key: &str) -> Result<Option<T>> {
        Ok(None)
    }

    fn set<T: Serialize>(&self, _key: &str, _value: &T, _ttl: Duration) -> Result<()> {
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        Ok(())
    }
}
