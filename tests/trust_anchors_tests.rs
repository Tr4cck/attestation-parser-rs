use attestation_parser_rs::trust_anchors;

#[test]
fn test_parse_attestation_status() {
    let json = r#"{
        "entries": {
            "00ABC123": {"status": "REVOKED"},
            "00DEF456": {"status": "ACTIVE"},
            "0": {"status": "REVOKED"}
        }
    }"#;

    let revoked = trust_anchors::parse_attestation_status(json).unwrap();
    assert!(revoked.contains("ABC123"));
    assert!(!revoked.contains("DEF456"));
    assert!(revoked.contains("0"));
    assert_eq!(revoked.len(), 2);
}

#[test]
fn test_load_roots_new_format() {
    let json = r#"[{"id":"test","sha256Fingerprint":"abc","certDerBase64":"MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmll"}]"#;
    let anchors = trust_anchors::load_from_json(json);
    assert_eq!(anchors.len(), 0);
}

#[test]
fn test_embedded_root_sha256s() {
    let hashes = trust_anchors::embedded_root_sha256s();
    assert!(!hashes.is_empty(), "should have at least one embedded fingerprint");
    assert!(
        hashes.contains("cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc"),
        "should contain the 2022 RSA root fingerprint"
    );
    assert!(
        hashes.contains("6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0"),
        "should contain the 2025 EC root fingerprint"
    );
}

#[test]
fn test_google_trust_anchors_loads_from_new_format() {
    let anchors = trust_anchors::google_trust_anchors();
    assert!(!anchors.is_empty(), "should load trust anchors from new roots.json format");
}
