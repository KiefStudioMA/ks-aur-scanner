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
    /// Per-user key authenticating stored verdicts (audit ME-2).
    mac_key: [u8; 32],
}

/// On-disk wrapper binding a cache entry to a MAC. The MAC is computed over the
/// exact serialized `data` bytes with the per-user key, so an entry that was not
/// written by this user's scanner (a planted/flipped verdict) fails verification
/// and is treated as a cache MISS rather than trusted data.
#[derive(serde::Serialize, serde::Deserialize)]
struct MacEnvelope {
    /// The serialized inner `CacheEntry` JSON.
    data: String,
    /// Hex BLAKE3 keyed-hash (MAC) of `data` under the cache's per-user key.
    mac: String,
}

/// Filename of the per-user MAC key inside the (0700) cache directory.
const MAC_KEY_FILE: &str = ".mac-key";

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
            // Tighten to owner-only. set_permissions fails (EPERM) if we are not
            // the owner, so a pre-existing dir owned by another user (e.g. a
            // squatted `/tmp/aur-scanner` fallback) is refused here.
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
            // Verify the tighten stuck: a world/group-accessible cache dir (audit
            // ME-2: the /tmp fallback must refuse world-writable) is rejected
            // rather than used to store security verdicts.
            let mode = std::fs::metadata(&directory)?.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(crate::error::ScanError::Cache(format!(
                    "refusing cache dir {} (group/world accessible: mode {:#o})",
                    directory.display(),
                    mode & 0o777
                )));
            }
        }
        let mac_key = load_or_create_mac_key(&directory)?;
        Ok(Self {
            directory,
            max_size_bytes: max_size_mb * 1024 * 1024,
            mac_key,
        })
    }

    /// Compute the verdict MAC over `data` with this cache's per-user key.
    fn mac(&self, data: &[u8]) -> blake3::Hash {
        blake3::keyed_hash(&self.mac_key, data)
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

/// Load the per-user cache MAC key, creating it (32 CSPRNG bytes, `0600`) on
/// first use (audit ME-2).
///
/// The key authenticates stored security verdicts: an entry whose MAC does not
/// verify under this key was not written by this user's scanner, so it is treated
/// as a cache MISS rather than trusted data -- closing the "local writer flips
/// malicious->benign between scan and consume" gap. The key file lives in the
/// `0700` cache dir as `0600`, so another *user* cannot read it to forge an entry.
/// (A same-user process that can read the key is outside this boundary -- the
/// `0700` dir is the cross-user boundary; the MAC additionally defeats a
/// constrained writer that can drop a file but not read the key, and detects
/// tampering/corruption.)
fn load_or_create_mac_key(dir: &std::path::Path) -> Result<[u8; 32]> {
    let key_path = dir.join(MAC_KEY_FILE);
    // Reuse an existing key only if it is a regular file of exactly 32 bytes.
    if let Ok(meta) = std::fs::symlink_metadata(&key_path) {
        if meta.file_type().is_file() {
            if let Ok(bytes) = std::fs::read(&key_path) {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    return Ok(arr);
                }
            }
            // A wrong-sized/garbage key file: regenerate (old entries then miss).
        }
    }
    let key = random_key()?;
    write_key_atomic(&key_path, &key)?;
    Ok(key)
}

/// 32 cryptographically-random bytes for the MAC key.
fn random_key() -> Result<[u8; 32]> {
    let mut buf = [0u8; 32];
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom")
            .map_err(|e| crate::error::ScanError::Cache(format!("no CSPRNG for cache key: {e}")))?;
        f.read_exact(&mut buf)
            .map_err(|e| crate::error::ScanError::Cache(format!("CSPRNG read failed: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        // The cache perm model (0700/0600) is unix-only; on other platforms derive
        // a best-effort process-local key so the cache still functions. The MAC is
        // not a cross-user boundary there (no perm enforcement) -- documented.
        let seed = format!(
            "{:?}|{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH),
            std::process::id()
        );
        buf.copy_from_slice(blake3::hash(seed.as_bytes()).as_bytes());
    }
    Ok(buf)
}

/// Write the MAC key atomically with `0600` perms (mirrors `write_atomic`).
fn write_key_atomic(path: &std::path::Path, key: &[u8; 32]) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let tmp = dir.join(format!(".{}.keytmp", blake3::hash(key).to_hex()));
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
        f.write_all(key)?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

impl Cache for DiskCache {
    fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let path = self.key_to_path(key);

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };

        // Authenticate before trusting: the file is a MAC envelope. An entry whose
        // MAC does not verify under our per-user key (a planted or flipped verdict)
        // is a cache MISS, not data. A non-envelope/old-format file also fails here
        // and is discarded. (audit ME-2)
        let envelope: MacEnvelope = match serde_json::from_str(&content) {
            Ok(e) => e,
            Err(_) => {
                let _ = std::fs::remove_file(&path);
                return Ok(None);
            }
        };
        let expected = self.mac(envelope.data.as_bytes());
        let mac_ok = blake3::Hash::from_hex(&envelope.mac)
            .map(|stored| stored == expected) // blake3 Hash eq is constant-time
            .unwrap_or(false);
        if !mac_ok {
            let _ = std::fs::remove_file(&path);
            return Ok(None);
        }

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

        let entry: CacheEntry<T> = match serde_json::from_str(&envelope.data) {
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

        // Serialize the entry, then bind it to a MAC under the per-user key so a
        // later local tamper (flip malicious->benign) is detected on read and
        // treated as a miss (audit ME-2).
        let data = serde_json::to_string(&entry)?;
        let mac = self.mac(data.as_bytes()).to_hex().to_string();
        let envelope = MacEnvelope { data, mac };
        let content = serde_json::to_string(&envelope)?;
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

    // --- verdict authenticity / MAC (audit ME-2) -----------------------------

    #[test]
    fn tampered_verdict_is_rejected_as_miss() {
        // A local writer flipping the stored value (malicious -> benign) without
        // the key cannot produce a matching MAC, so the entry is a miss.
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::new(dir.path().join("c"), 8).unwrap();
        cache
            .set("k", &"malicious".to_string(), Duration::from_secs(60))
            .unwrap();
        let path = cache.key_to_path("k");
        let mut env: MacEnvelope =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        env.data = env.data.replace("malicious", "benign-x"); // MAC not recomputed
        std::fs::write(&path, serde_json::to_string(&env).unwrap()).unwrap();
        let got: Option<String> = cache.get("k").unwrap();
        assert!(
            got.is_none(),
            "a MAC-invalid (tampered) entry must be a miss"
        );
    }

    #[test]
    fn entry_forged_under_a_different_key_is_rejected() {
        // An envelope whose MAC was computed under an attacker key (not ours) must
        // not be trusted even though it is structurally valid and unexpired.
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::new(dir.path().join("c"), 8).unwrap();
        let inner =
            serde_json::json!({"key": "k", "expires_at": i64::MAX, "value": "benign"}).to_string();
        let attacker_key = [0x41u8; 32];
        let mac = blake3::keyed_hash(&attacker_key, inner.as_bytes())
            .to_hex()
            .to_string();
        let env = MacEnvelope { data: inner, mac };
        std::fs::write(cache.key_to_path("k"), serde_json::to_string(&env).unwrap()).unwrap();
        let got: Option<String> = cache.get("k").unwrap();
        assert!(
            got.is_none(),
            "an entry MAC'd under a foreign key must not be trusted"
        );
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_cache_dir_is_tightened() {
        // A pre-existing world-writable cache dir (a squatted /tmp fallback) must
        // not be used as-is: it is tightened to 0700 (audit ME-2).
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("c");
        std::fs::create_dir(&cdir).unwrap();
        std::fs::set_permissions(&cdir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let _cache = DiskCache::new(cdir.clone(), 8).unwrap();
        let mode = std::fs::metadata(&cdir).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "world-writable cache dir must be tightened to 0700"
        );
    }

    #[test]
    fn mac_key_persists_across_instances_and_is_private() {
        // A second cache over the same dir must reuse the persisted key (so a real
        // entry round-trips), and the key file must be owner-only.
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("c");
        let c1 = DiskCache::new(cdir.clone(), 8).unwrap();
        c1.set("k", &"v".to_string(), Duration::from_secs(60))
            .unwrap();
        let c2 = DiskCache::new(cdir.clone(), 8).unwrap();
        let got: Option<String> = c2.get("k").unwrap();
        assert_eq!(
            got.as_deref(),
            Some("v"),
            "second instance must reuse the persisted key"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(cdir.join(MAC_KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "MAC key file must be owner-only");
        }
    }
}
