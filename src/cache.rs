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

/// A single root certificate entry in the cache.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedRoot {
    /// Human-readable identifier (e.g. "google_attestation_root_2022_rsa").
    pub id: String,
    /// SHA-256 fingerprint of the DER-encoded certificate (hex, lowercase).
    #[serde(rename = "sha256Fingerprint")]
    pub sha256_fingerprint: String,
    /// Base64-encoded DER certificate.
    #[serde(rename = "certDerBase64")]
    pub cert_der_base64: String,
}

/// The data stored in the cache file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheData {
    /// ISO 8601 timestamp of when this cache was created.
    pub fetched_at: String,
    /// Root certificate entries (id, fingerprint, base64 DER).
    pub roots: Vec<CachedRoot>,
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

    let roots_entries: Vec<CachedRoot> = roots
        .iter()
        .map(|a| {
            let der = a.cert.parsed.to_der().map_err(|e| format!("DER: {e}"))?;
            let (id, sha256) = trust_anchors::fingerprint_anchor(a);
            Ok(CachedRoot {
                id,
                sha256_fingerprint: sha256,
                cert_der_base64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &der,
                ),
            })
        })
        .collect::<Result<Vec<CachedRoot>, String>>()?;

    let data = CacheData {
        fetched_at: chrono::Utc::now().to_rfc3339(),
        roots: roots_entries,
        revoked_serials: revoked_serials.iter().cloned().collect(),
    };

    let json = serde_json::to_string_pretty(&data)
        .map_err(|e| format!("Failed to serialize cache: {e}"))?;

    fs::write(cache_path, json)
        .map_err(|e| format!("Failed to write cache file: {e}"))?;

    Ok(())
}

fn load_cache_at(cache_path: &Path) -> Option<(Vec<TrustAnchor>, HashSet<String>)> {
    use base64::Engine;

    let json = fs::read_to_string(cache_path).ok()?;

    let data: CacheData = serde_json::from_str(&json).ok()?;

    // Parse each root from base64 DER, verifying the stored fingerprint
    // matches the actual SHA-256 of the DER bytes.
    let anchors: Vec<TrustAnchor> = data
        .roots
        .iter()
        .filter_map(|r| {
            let der = base64::engine::general_purpose::STANDARD
                .decode(&r.cert_der_base64)
                .ok()?;

            // Verify that the stored fingerprint matches the actual DER.
            let actual_sha256 = crate::cert_chain::sha256_hex(&der);
            if actual_sha256 != r.sha256_fingerprint.to_lowercase() {
                eprintln!(
                    "Warning: cached root '{}' has mismatched fingerprint                      (stored: {}, actual: {}). Cache may be tampered with.",
                    r.id,
                    r.sha256_fingerprint,
                    actual_sha256
                );
                return None;
            }

            let cert = crate::cert_chain::Cert::from_der(&der).ok()?;
            Some(TrustAnchor {
                cert,
                name_constraints: None,
            })
        })
        .collect();

    if anchors.is_empty() {
        return None;
    }

    // Verify that the cached roots match the known embedded fingerprints.
    if let Err(e) = trust_anchors::verify_roots_match_embedded(&anchors) {
        eprintln!("Warning: {e}");
        return None;
    }

    let revoked: HashSet<String> = data.revoked_serials.into_iter().collect();

    Some((anchors, revoked))
}

fn cache_info_at(cache_path: &Path) -> Option<(chrono::Duration, usize, usize)> {
    let json = fs::read_to_string(cache_path).ok()?;
    let data: CacheData = serde_json::from_str(&json).ok()?;
    let fetched_at = chrono::DateTime::parse_from_rfc3339(&data.fetched_at).ok()?;
    let age = chrono::Utc::now() - fetched_at.with_timezone(&chrono::Utc);
    Some((age, data.roots.len(), data.revoked_serials.len()))
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
pub fn cache_info() -> Option<(PathBuf, chrono::Duration, usize, usize)> {
    let cache_path = default_cache_path();
    cache_info_at(&cache_path).map(|(age, roots, revoked)| (cache_path, age, roots, revoked))
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
