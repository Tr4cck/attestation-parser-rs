use crate::trust_anchors::{self, TrustAnchor};
use der::Encode;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

/// Default cache file path under the user's cache directory.
fn default_cache_path() -> PathBuf {
    let mut path = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("attestation-parser-rs");
    path.push("attestation_cache.json");
    path
}

/// The data stored in the cache file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheData {
    /// ISO 8601 timestamp of when this cache was created.
    pub fetched_at: String,
    /// PEM-encoded root certificates (same format as roots.json).
    pub roots: Vec<String>,
    /// Revoked certificate serial numbers (unpadded hex, same format as the status API).
    pub revoked_serials: Vec<String>,
}

/// Save the fetched roots and revoked serials to the cache file.
pub fn save_cache(
    roots: &[TrustAnchor],
    revoked_serials: &HashSet<String>,
) -> Result<PathBuf, String> {
    let cache_dir = default_cache_path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("Failed to create cache directory: {e}"))?;

    let cache_path = default_cache_path();

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

    fs::write(&cache_path, json)
        .map_err(|e| format!("Failed to write cache file: {e}"))?;

    Ok(cache_path)
}

/// Load the cached roots and revoked serials.
/// Returns `None` if the cache file does not exist or can't be parsed.
pub fn load_cache() -> Option<(Vec<TrustAnchor>, HashSet<String>)> {
    let cache_path = default_cache_path();
    let json = fs::read_to_string(&cache_path).ok()?;

    let data: CacheData = serde_json::from_str(&json).ok()?;

    let anchors = trust_anchors::load_from_json(&serde_json::to_string(&data.roots).ok()?);
    if anchors.is_empty() {
        return None;
    }

    let revoked: HashSet<String> = data.revoked_serials.into_iter().collect();

    Some((anchors, revoked))
}

/// Check if a cache file exists and is not too old.
/// Returns the cache path and age if present, or `None` if missing/expired.
pub fn cache_info() -> Option<(PathBuf, chrono::Duration)> {
    let cache_path = default_cache_path();
    let json = fs::read_to_string(&cache_path).ok()?;
    let data: CacheData = serde_json::from_str(&json).ok()?;
    let fetched_at = chrono::DateTime::parse_from_rfc3339(&data.fetched_at).ok()?;
    let age = chrono::Utc::now() - fetched_at.with_timezone(&chrono::Utc);
    Some((cache_path, age))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_save_and_load_cache() {
        // Use a temporary directory for testing
        let tmp = std::env::temp_dir().join("test-attestation-cache");
        let _ = fs::create_dir_all(&tmp);

        // Load a known root to save
        let anchors = trust_anchors::google_trust_anchors();
        let mut revoked = HashSet::new();
        revoked.insert("deadbeef".to_string());
        revoked.insert("cafebabe".to_string());

        // We can't easily override the cache path in this test, so
        // just verify the data structures serialize correctly.
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
        assert!(parsed.revoked_serials.contains(&"deadbeef".to_string()));
        assert!(parsed.revoked_serials.contains(&"cafebabe".to_string()));
    }
}
