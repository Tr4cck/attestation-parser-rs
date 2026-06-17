use crate::trust_anchors::{self, TrustAnchor};
use der::Encode;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Default cache file path under the user's cache directory.
fn default_cache_path() -> PathBuf {
    let mut path = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("attestation-parser-rs");
    path.push("attestation_cache.json");
    path
}

/// The data stored in the cache file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheData {
    /// ISO 8601 timestamp of when this cache was created.
    pub fetched_at: String,
    /// PEM-encoded root certificates (same format as roots.json).
    pub roots: Vec<String>,
    /// Revoked certificate serial numbers (unpadded hex, same format as the status API).
    pub revoked_serials: Vec<String>,
}

// ── Internal helpers that accept an explicit path ─────────────────────────

fn save_cache_at(
    cache_path: &Path,
    roots: &[TrustAnchor],
    revoked_serials: &HashSet<String>,
) -> Result<(), String> {
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create cache directory: {e}"))?;
    }

    let roots_pem: Vec<String> = roots
        .iter()
        .map(|a| {
            let der = a.cert.parsed.to_der().map_err(|e| format!("DER: {e}"))?;
            Ok(pem::encode(&pem::Pem::new("CERTIFICATE", der)))
        })
        .collect::<Result<Vec<String>, String>>()?;

    let data = CacheData {
        fetched_at: chrono::Utc::now().to_rfc3339(),
        roots: roots_pem,
        revoked_serials: revoked_serials.iter().cloned().collect(),
    };

    let json = serde_json::to_string_pretty(&data)
        .map_err(|e| format!("Failed to serialize cache: {e}"))?;

    fs::write(cache_path, json)
        .map_err(|e| format!("Failed to write cache file: {e}"))?;

    Ok(())
}

fn load_cache_at(cache_path: &Path) -> Option<(Vec<TrustAnchor>, HashSet<String>)> {
    let json = fs::read_to_string(cache_path).ok()?;

    let data: CacheData = serde_json::from_str(&json).ok()?;

    let anchors = trust_anchors::load_from_json(&serde_json::to_string(&data.roots).ok()?);
    if anchors.is_empty() {
        return None;
    }

    let revoked: HashSet<String> = data.revoked_serials.into_iter().collect();

    Some((anchors, revoked))
}

fn cache_info_at(cache_path: &Path) -> Option<chrono::Duration> {
    let json = fs::read_to_string(cache_path).ok()?;
    let data: CacheData = serde_json::from_str(&json).ok()?;
    let fetched_at = chrono::DateTime::parse_from_rfc3339(&data.fetched_at).ok()?;
    let age = chrono::Utc::now() - fetched_at.with_timezone(&chrono::Utc);
    Some(age)
}

// ── Public API ────────────────────────────────────────────────────────────

/// Save the fetched roots and revoked serials to the cache file.
pub fn save_cache(
    roots: &[TrustAnchor],
    revoked_serials: &HashSet<String>,
) -> Result<PathBuf, String> {
    let cache_path = default_cache_path();
    save_cache_at(&cache_path, roots, revoked_serials)?;
    Ok(cache_path)
}

/// Load the cached roots and revoked serials.
/// Returns `None` if the cache file does not exist or can't be parsed.
pub fn load_cache() -> Option<(Vec<TrustAnchor>, HashSet<String>)> {
    load_cache_at(&default_cache_path())
}

/// Check if a cache file exists and returns its age.
/// Returns `None` if missing or unparseable.
pub fn cache_info() -> Option<(PathBuf, chrono::Duration)> {
    let cache_path = default_cache_path();
    cache_info_at(&cache_path).map(|age| (cache_path, age))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Create a temporary directory that is cleaned up on drop.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static CNT: AtomicU64 = AtomicU64::new(0);
            let id = CNT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("attest-cache-test-{id}"));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            TempDir { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    // ── CacheData serialization roundtrip ─────────────────────────────────

    #[test]
    fn test_cache_data_roundtrip() {
        let anchors = trust_anchors::google_trust_anchors();
        assert!(!anchors.is_empty(), "roots.json must contain at least one anchor");

        let mut revoked = HashSet::new();
        revoked.insert("deadbeef".to_string());
        revoked.insert("cafebabe".to_string());

        let roots_pem: Vec<String> = anchors
            .iter()
            .map(|a| {
                pem::encode(&pem::Pem::new(
                    "CERTIFICATE",
                    a.cert.parsed.to_der().unwrap(),
                ))
            })
            .collect();

        let data = CacheData {
            fetched_at: chrono::Utc::now().to_rfc3339(),
            roots: roots_pem.clone(),
            revoked_serials: revoked.iter().cloned().collect(),
        };

        let json = serde_json::to_string(&data).unwrap();
        let parsed: CacheData = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.roots.len(), roots_pem.len());
        assert!(parsed.revoked_serials.iter().any(|s| s == "deadbeef"));
        assert!(parsed.revoked_serials.iter().any(|s| s == "cafebabe"));
    }

    #[test]
    fn test_cache_data_empty_revocation() {
        let anchors = trust_anchors::google_trust_anchors();
        let roots_pem: Vec<String> = anchors
            .iter()
            .map(|a| {
                pem::encode(&pem::Pem::new(
                    "CERTIFICATE",
                    a.cert.parsed.to_der().unwrap(),
                ))
            })
            .collect();

        let data = CacheData {
            fetched_at: chrono::Utc::now().to_rfc3339(),
            roots: roots_pem.clone(),
            revoked_serials: vec![],
        };

        let json = serde_json::to_string(&data).unwrap();
        let parsed: CacheData = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.roots.len(), roots_pem.len());
        assert!(parsed.revoked_serials.is_empty());
    }

    // ── File I/O: save + load cycle ───────────────────────────────────────

    #[test]
    fn test_save_and_load_at() {
        let tmp = TempDir::new();
        let cache_path = tmp.join("cache.json");

        let anchors = trust_anchors::google_trust_anchors();
        let mut revoked = HashSet::new();
        revoked.insert("aabbccdd1234".to_string());
        revoked.insert("55667788abcd".to_string());

        save_cache_at(&cache_path, &anchors, &revoked).unwrap();
        assert!(cache_path.exists(), "cache file should be created");

        let (loaded_anchors, loaded_revoked) =
            load_cache_at(&cache_path).expect("should load cache successfully");

        assert_eq!(loaded_anchors.len(), anchors.len());
        assert_eq!(loaded_revoked.len(), 2);
        assert!(loaded_revoked.contains("aabbccdd1234"));
        assert!(loaded_revoked.contains("55667788abcd"));
        assert_eq!(
            loaded_anchors[0].cert.subject_dn(),
            anchors[0].cert.subject_dn()
        );
    }

    #[test]
    fn test_load_cache_missing_file() {
        let tmp = TempDir::new();
        let cache_path = tmp.join("nonexistent.json");
        assert!(load_cache_at(&cache_path).is_none());
    }

    #[test]
    fn test_load_cache_empty_roots() {
        let tmp = TempDir::new();
        let cache_path = tmp.join("empty_roots.json");

        let data = CacheData {
            fetched_at: chrono::Utc::now().to_rfc3339(),
            roots: vec![],
            revoked_serials: vec!["abc123".to_string()],
        };
        fs::write(&cache_path, serde_json::to_string(&data).unwrap()).unwrap();

        assert!(load_cache_at(&cache_path).is_none());
    }

    #[test]
    fn test_load_cache_corrupted_json() {
        let tmp = TempDir::new();
        let cache_path = tmp.join("corrupted.json");
        fs::write(&cache_path, "this is not JSON {{{").unwrap();
        assert!(load_cache_at(&cache_path).is_none());
    }

    // ── cache_info ────────────────────────────────────────────────────────

    #[test]
    fn test_cache_info_valid() {
        let tmp = TempDir::new();
        let cache_path = tmp.join("info.json");

        let data = CacheData {
            fetched_at: chrono::Utc::now().to_rfc3339(),
            roots: vec!["FAKE_PEM".to_string()],
            revoked_serials: vec![],
        };
        fs::write(&cache_path, serde_json::to_string(&data).unwrap()).unwrap();

        let age = cache_info_at(&cache_path).expect("cache_info should return Some");
        assert!(age.num_seconds() >= 0 && age.num_seconds() < 10);
    }

    #[test]
    fn test_cache_info_missing() {
        let tmp = TempDir::new();
        let cache_path = tmp.join("missing_info.json");
        assert!(cache_info_at(&cache_path).is_none());
    }

    #[test]
    fn test_cache_info_invalid_timestamp() {
        let tmp = TempDir::new();
        let cache_path = tmp.join("bad_ts.json");

        let data = serde_json::json!({
            "fetched_at": "not-a-real-date",
            "roots": [],
            "revoked_serials": []
        });
        fs::write(&cache_path, serde_json::to_string(&data).unwrap()).unwrap();

        assert!(cache_info_at(&cache_path).is_none());
    }

    // ── Revocation roundtrip through cache ────────────────────────────────

    #[test]
    fn revocation_roundtrip_through_cache() {
        use crate::cert_chain::Cert;
        use crate::revocation::RevocationChecker;

        // Test: if we cache a known serial as revoked, loading it back
        // and running it through a RevocationChecker should catch it.

        let tmp = TempDir::new();
        let cache_path = tmp.join("revocation_rt.json");

        // We use the software root cert as a test subject since its serial is known.
        let sw_root = crate::trust_anchors::SOFTWARE_ROOT_PEM;
        let sw_cert = Cert::from_der(&pem::parse(sw_root).unwrap().contents()).unwrap();
        let sw_serial = sw_cert.serial_number_hex();

        let anchors = trust_anchors::google_trust_anchors();
        let mut revoked = HashSet::new();
        revoked.insert(sw_serial.clone());

        // Save → load cycle
        save_cache_at(&cache_path, &anchors, &revoked).unwrap();
        let (_loaded_anchors, loaded_revoked) = load_cache_at(&cache_path).unwrap();

        // The loaded revoked set must contain our serial.
        assert!(loaded_revoked.contains(&sw_serial));

        // Verify the checker rejects a revoked cert.
        let checker = RevocationChecker::new(loaded_revoked);
        let result = checker.check(&sw_cert);
        assert!(
            result.is_err(),
            "revoked cert should be rejected, got: {result:?}"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("revoked"),
            "error should mention 'revoked', got: {err_msg}"
        );
    }

    // ── google_cached fallback    // ── google_cached fallback behavior ───────────────────────────────────

    #[test]
    fn google_cached_missing_cache() {
        use crate::verifier::Verifier;

        let verifier = Verifier::google_cached(chrono::Utc::now);

        // Verify the verifier is usable: it should verify a chain without
        // crashing, even though without matching trust anchors it'll fail
        // at path validation.
        let sw_root = crate::trust_anchors::SOFTWARE_ROOT_PEM;
        let sw_int = crate::trust_anchors::SOFTWARE_INTERMEDIATE_PEM;
        let chain = vec![
            pem::parse(sw_int).unwrap().contents().to_vec(),
            pem::parse(sw_root).unwrap().contents().to_vec(),
            pem::parse(sw_root).unwrap().contents().to_vec(),
        ];

        let result = verifier.verify(&chain, None);
        match result {
            crate::VerificationResult::PathValidationFailure { .. } => {
                // Expected: software root is not a Google trust anchor
            }
            other => {
                panic!("expected PathValidationFailure, got: {other:?}");
            }
        }
    }
}
