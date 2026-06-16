use attestation_parser_rs::*;
use attestation_parser_rs::trust_anchors;
use attestation_parser_rs::extension;

fn load_pem_chain(path: &str) -> Vec<Vec<u8>> {
    let pem_content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![], // skip if testdata not available
    };
    pem::parse_many(&pem_content)
        .unwrap()
        .iter()
        .map(|p| p.contents().to_vec())
        .collect()
}

fn load_pem_certs(pem_strs: &[&str]) -> Vec<Vec<u8>> {
    pem_strs
        .iter()
        .map(|p| pem::parse(p).unwrap().contents().to_vec())
        .collect()
}

// ── Public Google attestation root & intermediate certificates ────────────
// These are the well-known certificates published by Google at
// https://android.googleapis.com/attestation/root





// ── Root & intermediate certificate parsing ───────────────────────────────

#[test]
fn parse_software_root_cert() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();

    assert!(cert.subject_dn().contains("Software Attestation Root"));
    assert!(cert.is_self_issued());
    assert_eq!(cert.serial_number_hex(), "a2059ed10e435b57");
}

#[test]
fn parse_software_intermediate_cert() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_INTERMEDIATE_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();

    assert!(cert.subject_dn().contains("Intermediate"));
    assert!(!cert.is_self_issued());
    assert_eq!(cert.serial_number_hex(), "1001");
}

#[test]
fn software_root_detected() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    assert!(trust_anchors::is_software_root(&cert));
}

#[test]
fn intermediate_not_software_root() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_INTERMEDIATE_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    assert!(!trust_anchors::is_software_root(&cert));
}

// ── Chain structure validation ────────────────────────────────────────────

#[test]
fn chain_too_short_rejected() {
    // Only 2 certs — minimum is 3
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_INTERMEDIATE_PEM, trust_anchors::SOFTWARE_ROOT_PEM]);
    let result = KeyAttestationCertPath::from_der_blobs(certs);
    assert!(result.is_err());
}

#[test]
fn chain_root_not_self_issued_rejected() {
    // Use intermediate as "root" (it's not self-issued)
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_INTERMEDIATE_PEM, trust_anchors::SOFTWARE_ROOT_PEM, trust_anchors::SOFTWARE_INTERMEDIATE_PEM]);
    let result = KeyAttestationCertPath::from_der_blobs(certs);
    assert!(result.is_err());
}

// ── Embedded trust anchors ────────────────────────────────────────────────

#[test]
fn google_trust_anchors_load() {
    let anchors = trust_anchors::google_trust_anchors();
    assert!(!anchors.is_empty(), "Should load at least one trust anchor from roots.json");
}

#[test]
fn google_trust_anchors_exclude_software_root() {
    // Verifier::google() panics if any software root is used as trust anchor.
    // This test verifies the embedded roots.json does not contain the software root.
    let _verifier = Verifier::google(chrono::Utc::now);
}

// ── Revocation parsing ────────────────────────────────────────────────────

#[test]
fn revocation_checker_empty_list() {
    let checker = revocation::RevocationChecker::new(std::collections::HashSet::new());
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    assert!(checker.check(&cert).is_ok());
}

#[test]
fn revocation_checker_revoked_cert() {
    let mut revoked = std::collections::HashSet::new();
    revoked.insert("a2059ed10e435b57".to_string()); // SW root serial

    let checker = revocation::RevocationChecker::new(revoked);
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    assert!(checker.check(&cert).is_err());
}

// ── File-based tests (require keyattestation testdata) ────────────────────

#[test]
fn parse_blueline_sdk28_tee_ec_none() {
    let certs = load_pem_chain("keyattestation/testdata/blueline/sdk28/TEE_EC_NONE.pem");
    if certs.is_empty() { eprintln!("Skipping: keyattestation testdata not found"); return; }
    assert_eq!(certs.len(), 4);

    let cert_path = KeyAttestationCertPath::from_der_blobs(certs).unwrap();
    assert_eq!(cert_path.certificates_with_anchor.len(), 4);
    assert_eq!(cert_path.certificates().len(), 3);

    let ext_value = cert_path
        .leaf_cert()
        .get_extension_value(extension::KEY_DESCRIPTION_OID)
        .unwrap();

    let kd = extension::KeyDescription::parse_from_der(&ext_value)
        .unwrap()
        .unwrap();

    assert_eq!(kd.attestation_security_level, extension::SecurityLevel::TrustedEnvironment);
    assert_eq!(kd.key_mint_security_level, extension::SecurityLevel::TrustedEnvironment);
}

#[test]
fn parse_blueline_sdk28_sb_rsa_none() {
    let certs = load_pem_chain("keyattestation/testdata/blueline/sdk28/SB_RSA_NONE.pem");
    if certs.is_empty() { eprintln!("Skipping: keyattestation testdata not found"); return; }
    assert_eq!(certs.len(), 4);
    let cert_path = KeyAttestationCertPath::from_der_blobs(certs).unwrap();
    assert_eq!(cert_path.certificates_with_anchor.len(), 4);

    let ext_value = cert_path
        .leaf_cert()
        .get_extension_value(extension::KEY_DESCRIPTION_OID)
        .unwrap();

    let kd = extension::KeyDescription::parse_from_der(&ext_value)
        .unwrap()
        .unwrap();

    assert_eq!(kd.attestation_security_level, extension::SecurityLevel::StrongBox);
}

#[test]
fn parse_caiman_sdk36_tee_ec_rkp() {
    let certs = load_pem_chain("keyattestation/testdata/caiman/sdk36/TEE_EC_RKP.pem");
    if certs.is_empty() { eprintln!("Skipping: keyattestation testdata not found"); return; }
    assert_eq!(certs.len(), 5);
    let cert_path = KeyAttestationCertPath::from_der_blobs(certs).unwrap();

    let method = cert_path.provisioning_method();
    eprintln!("Provisioning method: {method:?}");

    let ext_value = cert_path
        .leaf_cert()
        .get_extension_value(extension::KEY_DESCRIPTION_OID)
        .unwrap();

    let kd = extension::KeyDescription::parse_from_der(&ext_value)
        .unwrap()
        .unwrap();

    assert_eq!(kd.attestation_security_level, extension::SecurityLevel::TrustedEnvironment);
}
