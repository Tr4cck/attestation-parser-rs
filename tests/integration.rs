use attestation_parser_rs::*;
use std::path::Path;

fn load_pem_chain(path: &str) -> Vec<Vec<u8>> {
    let pem_content = std::fs::read_to_string(Path::new(path)).unwrap();
    pem::parse_many(&pem_content)
        .unwrap()
        .iter()
        .map(|p| p.contents().to_vec())
        .collect()
}

#[test]
fn parse_blueline_sdk28_tee_ec_none() {
    let certs = load_pem_chain("keyattestation/testdata/blueline/sdk28/TEE_EC_NONE.pem");
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

    // SB = StrongBox, not Software
    assert_eq!(kd.attestation_security_level, extension::SecurityLevel::StrongBox);
}

#[test]
fn parse_caiman_sdk36_tee_ec_rkp() {
    let certs = load_pem_chain("keyattestation/testdata/caiman/sdk36/TEE_EC_RKP.pem");
    assert_eq!(certs.len(), 5);
    let cert_path = KeyAttestationCertPath::from_der_blobs(certs).unwrap();

    // Verify provisioning method is detected
    let method = cert_path.provisioning_method();
    eprintln!("Provisioning method: {method:?}");
    eprintln!("Intermediate DN: {}", cert_path.intermediate_cert().subject_dn());

    let ext_value = cert_path
        .leaf_cert()
        .get_extension_value(extension::KEY_DESCRIPTION_OID)
        .unwrap();

    let kd = extension::KeyDescription::parse_from_der(&ext_value)
        .unwrap()
        .unwrap();

    assert_eq!(kd.attestation_security_level, extension::SecurityLevel::TrustedEnvironment);
}
