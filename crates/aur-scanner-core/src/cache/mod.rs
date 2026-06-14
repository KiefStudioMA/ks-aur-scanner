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
    /// Create a new disk cache.
    ///
    /// The cache stores security verdicts, so the directory is created (and, if
    /// it already exists, tightened) to `0700` -- owner-only -- to keep another
    /// local user from planting or reading entries. A pre-existing path that is
    /// a symlink is refused outright.
    pub fn new(directory: PathBuf, max_size_mb: usize) -> Result<Self> {
        #[cfg(unix)]
        {
            if let Ok(meta) = std::fs::symlink_metadata(&directory) {
                if meta.file_type().is_symlink() {
                    return Err(crate::error::ScanError::Cache(format!(
                        "refusing to use cache dir {} (it is a symlink)",
                        directory.display()
                    )));
                }
            }
        }
        std::fs::create_dir_all(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            directory,
            max_size_bytes: max_size_mb * 1024 * 1024,
        })
    }

    fn key_to_path(&self, key: &str) -> PathBuf {
        let hash = blake3::hash(key.as_bytes());
        self.directory.join(format!("{}.json", hash.to_hex()))
    }

    /// Write `content` to `path` atomically with `0600` perms: write a sibling
    /// temp file, then rename over the target so a reader never sees a partial
    /// file and the entry is never world-readable.
    fn write_atomic(path: &std::path::Path, content: &str) -> Result<()> {
        let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let tmp = dir.join(format!(".{}.tmp", blake3::hash(content.as_bytes()).to_hex()));
        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(content.as_bytes())?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
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

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };

        // The stored `key` binds the entry to its filename: a file planted at a
        // known `blake3(key).json` path with mismatched contents is rejected
        // rather than trusted. Any deserialization failure is treated as a cache
        // MISS (and the bad file removed), never as an error that could surface
        // attacker-controlled data.
        #[derive(serde::Deserialize)]
        struct CacheEntry<T> {
            key: String,
            expires_at: i64,
            value: T,
        }

        let entry: CacheEntry<T> = match serde_json::from_str(&content) {
            Ok(e) => e,
            Err(_) => {
                let _ = std::fs::remove_file(&path);
                return Ok(None);
            }
        };

        // Expired, or the entry does not actually belong to this key.
        let now = chrono::Utc::now().timestamp();
        if entry.key != key || now > entry.expires_at {
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
            key: &'a str,
            expires_at: i64,
            value: &'a T,
        }

        let entry = CacheEntry {
            key,
            expires_at: chrono::Utc::now().timestamp() + ttl.as_secs() as i64,
            value,
        };

        let content = serde_json::to_string(&entry)?;
        Self::write_atomic(&path, &content)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_dir_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::new(dir.path().join("c"), 8).unwrap();
        cache.set("k", &"v".to_string(), Duration::from_secs(60)).unwrap();
        let got: Option<String> = cache.get("k").unwrap();
        assert_eq!(got.as_deref(), Some("v"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("c")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "cache dir must be owner-only");
        }
    }

    #[test]
    fn rejects_entry_planted_under_a_mismatched_key() {
        // A file placed at blake3(key2).json whose contents claim key1 must not
        // be trusted when read under key2.
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("c");
        let cache = DiskCache::new(cdir.clone(), 8).unwrap();
        // Write a valid entry for "real".
        cache.set("real", &"trusted".to_string(), Duration::from_secs(60)).unwrap();
        // Forge: copy that file's contents to the path for "victim".
        let real_path = cache.key_to_path("real");
        let victim_path = cache.key_to_path("victim");
        std::fs::copy(&real_path, &victim_path).unwrap();
        // Reading "victim" must reject the key-mismatched entry (miss).
        let got: Option<String> = cache.get("victim").unwrap();
        assert!(got.is_none(), "key-bound entry must not satisfy a different key");
    }

    #[test]
    fn corrupt_file_is_a_miss_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::new(dir.path().join("c"), 8).unwrap();
        std::fs::write(cache.key_to_path("k"), "}{ not json").unwrap();
        let got: Result<Option<String>> = cache.get("k");
        assert!(matches!(got, Ok(None)), "corrupt entry must be a clean miss");
    }
}
