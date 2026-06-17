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

    /// Build a CachedRoot from a TrustAnchor.
    fn make_cached_root(anchor: &TrustAnchor) -> CachedRoot {
        let der = anchor.cert.parsed.to_der().unwrap();
        let (id, sha256) = trust_anchors::fingerprint_anchor(anchor);
        CachedRoot {
            id,
            sha256_fingerprint: sha256,
            cert_der_base64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &der,
            ),
        }
    }

    // ── CacheData serialization roundtrip ─────────────────────────────────

    #[test]
    fn test_cache_data_roundtrip() {
        let anchors = trust_anchors::google_trust_anchors();
        assert!(!anchors.is_empty());

        let mut revoked = HashSet::new();
        revoked.insert("deadbeef".to_string());
        revoked.insert("cafebabe".to_string());

        let roots_entries: Vec<CachedRoot> = anchors.iter().map(make_cached_root).collect();

        let data = CacheData {
            fetched_at: chrono::Utc::now().to_rfc3339(),
            roots: roots_entries.clone(),
            revoked_serials: revoked.iter().cloned().collect(),
        };

        let json = serde_json::to_string(&data).unwrap();
        let parsed: CacheData = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.roots.len(), roots_entries.len());
        assert!(parsed.revoked_serials.iter().any(|s| s == "deadbeef"));
        assert!(parsed.revoked_serials.iter().any(|s| s == "cafebabe"));
        // Verify fingerprints are present
        for root in &parsed.roots {
            assert!(!root.sha256_fingerprint.is_empty());
            assert!(!root.cert_der_base64.is_empty());
        }
    }

    #[test]
    fn test_cache_data_empty_revocation() {
        let anchors = trust_anchors::google_trust_anchors();
        let roots_entries: Vec<CachedRoot> = anchors.iter().map(make_cached_root).collect();

        let data = CacheData {
            fetched_at: chrono::Utc::now().to_rfc3339(),
            roots: roots_entries.clone(),
            revoked_serials: vec![],
        };

        let json = serde_json::to_string(&data).unwrap();
        let parsed: CacheData = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.roots.len(), roots_entries.len());
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
            roots: vec![CachedRoot {
                id: "test".into(),
                sha256_fingerprint: "aa".into(),
                cert_der_base64: "FAKE".into(),
            }],
            revoked_serials: vec![],
        };
        fs::write(&cache_path, serde_json::to_string(&data).unwrap()).unwrap();

        let (age, roots, revoked) = cache_info_at(&cache_path).expect("cache_info should return Some");
        assert!(age.num_seconds() >= 0 && age.num_seconds() < 10);
        assert_eq!(roots, 1);
        assert_eq!(revoked, 0);
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

        let tmp = TempDir::new();
        let cache_path = tmp.join("revocation_rt.json");

        let sw_root = crate::trust_anchors::SOFTWARE_ROOT_PEM;
        let sw_cert = Cert::from_der(pem::parse(sw_root).unwrap().contents()).unwrap();
        let sw_serial = sw_cert.serial_number_hex();

        let anchors = trust_anchors::google_trust_anchors();
        let mut revoked = HashSet::new();
        revoked.insert(sw_serial.clone());

        save_cache_at(&cache_path, &anchors, &revoked).unwrap();
        let (_loaded_anchors, loaded_revoked) = load_cache_at(&cache_path).unwrap();

        assert!(loaded_revoked.contains(&sw_serial));

        let checker = RevocationChecker::new(loaded_revoked);
        let result = checker.check(&sw_cert);
        assert!(result.is_err(), "revoked cert should be rejected");
        assert!(result.unwrap_err().to_string().contains("revoked"));
    }

    // ── google_cached fallback behavior ───────────────────────────────────

    #[test]
    fn google_cached_missing_cache() {
        use crate::verifier::Verifier;

        let verifier = Verifier::google_cached(chrono::Utc::now);

        let sw_root = crate::trust_anchors::SOFTWARE_ROOT_PEM;
        let sw_int = crate::trust_anchors::SOFTWARE_INTERMEDIATE_PEM;
        let chain = vec![
            pem::parse(sw_int).unwrap().contents().to_vec(),
            pem::parse(sw_root).unwrap().contents().to_vec(),
            pem::parse(sw_root).unwrap().contents().to_vec(),
        ];

        let result = verifier.verify(&chain, None);
        match result {
            crate::VerificationResult::PathValidationFailure { .. } => {}
            other => panic!("expected PathValidationFailure, got: {other:?}"),
        }
    }

    // ── Fingerprint verification (verify_roots_match_embedded) ───────────

    #[test]
    fn verify_roots_accepts_embedded() {
        // Google trust anchors loaded from embedded roots.json must
        // pass the fingerprint check against themselves.
        let anchors = trust_anchors::google_trust_anchors();
        assert!(anchors.len() >= 2, "need at least 2 anchors for meaningful test");

        let result = trust_anchors::verify_roots_match_embedded(&anchors);
        assert!(
            result.is_ok(),
            "embedded roots should match themselves, got: {result:?}"
        );
    }

    #[test]
    fn verify_roots_rejects_tampered() {
        use crate::Cert;

        // Load real anchors, then construct a fake anchor that won't match.
        #[allow(unused_variables)]
        let anchors = trust_anchors::google_trust_anchors();
        let embedded = trust_anchors::embedded_root_sha256s();

        // Create a totally different cert (software root) — it won't be in embedded set.
        let sw_root = crate::trust_anchors::SOFTWARE_ROOT_PEM;
        let sw_cert = Cert::from_der(pem::parse(sw_root).unwrap().contents()).unwrap();
        let sw_sha = crate::cert_chain::sha256_hex(
            &sw_cert.parsed.to_der().unwrap_or_default()
        );
        assert!(
            !embedded.contains(&sw_sha),
            "software root should not be in embedded fingerprint set"
        );

        let tampered = vec![TrustAnchor {
            cert: sw_cert,
            name_constraints: None,
        }];

        let result = trust_anchors::verify_roots_match_embedded(&tampered);
        assert!(result.is_err(), "tampered roots should be rejected");
    }

    #[test]
    fn fingerprint_anchor_produces_valid_output() {
        let anchors = trust_anchors::google_trust_anchors();
        for anchor in &anchors {
            let (id, sha256) = trust_anchors::fingerprint_anchor(anchor);
            assert!(!id.is_empty(), "id should not be empty");
            assert_eq!(sha256.len(), 64, "sha256 should be 64 hex chars");
            assert!(id.starts_with("google_attestation_root_"), "id should follow naming pattern");

            // Verify the fingerprint matches what we compute independently
            let der = anchor.cert.parsed.to_der().unwrap_or_default();
            let expected_sha = crate::cert_chain::sha256_hex(&der);
            assert_eq!(sha256, expected_sha, "fingerprint should match SHA-256 of DER");
        }
    }

    #[test]
    fn load_cache_rejects_wrong_fingerprints() {
        // Write a cache file where sha256Fingerprint doesn't match the
        // embedded set → load_cache_at should return None.
        let tmp = TempDir::new();
        let cache_path = tmp.join("bad_fingerprint.json");

        let data = CacheData {
            fetched_at: chrono::Utc::now().to_rfc3339(),
            roots: vec![CachedRoot {
                id: "fake_root".into(),
                sha256_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
                cert_der_base64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    [0x30, 0x00], // minimal but invalid DER — won't parse to Cert
                ),
            }],
            revoked_serials: vec![],
        };
        fs::write(&cache_path, serde_json::to_string(&data).unwrap()).unwrap();

        // Should fail: either DER parsing fails, or fingerprint doesn't match
        let result = load_cache_at(&cache_path);
        assert!(result.is_none(), "cache with wrong fingerprints should be rejected");
    }

    #[test]
    fn load_cache_rejects_tampered_with_valid_root_but_wrong_fingerprint() {
        // Use a real Google root DER but give it a wrong sha256Fingerprint.
        let tmp = TempDir::new();
        let cache_path = tmp.join("tampered.json");

        let anchors = trust_anchors::google_trust_anchors();
        let real_root = &anchors[0];
        let real_der = real_root.cert.parsed.to_der().unwrap();
        let real_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &real_der,
        );

        let data = CacheData {
            fetched_at: chrono::Utc::now().to_rfc3339(),
            roots: vec![CachedRoot {
                id: real_root.cert.subject_dn(),
                sha256_fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                cert_der_base64: real_b64,
            }],
            revoked_serials: vec![],
        };
        fs::write(&cache_path, serde_json::to_string(&data).unwrap()).unwrap();

        // The DER is valid, but fingerprint won't match embedded → reject
        let result = load_cache_at(&cache_path);
        assert!(result.is_none(), "cache with mismatched fingerprint should be rejected");
    }
