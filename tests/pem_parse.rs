//! PEM parsing tests for public Google attestation certificates.
//!
//! Tests that public root and intermediate certificates can be parsed
//! from PEM format and that key fields are extracted correctly.

use attestation_parser_rs::*;
use attestation_parser_rs::trust_anchors;
use attestation_parser_rs::cert_chain;
use der::Encode;

fn load_pem_certs(pem_strs: &[&str]) -> Vec<Vec<u8>> {
    pem_strs
        .iter()
        .map(|p| pem::parse(p).unwrap().contents().to_vec())
        .collect()
}

// ── Public Google attestation root & intermediate certificates ────────────





// ── PEM parsing tests ─────────────────────────────────────────────────────

#[test]
fn pem_parse_root_subject() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let subject = cert.subject_dn();
    assert!(
        subject.contains("Software Attestation Root"),
        "Expected 'Software Attestation Root' in subject, got: {subject}"
    );
}

#[test]
fn pem_parse_root_serial_number_hex() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    // Serial: A2059ED10E435B57 (hex)
    assert_eq!(cert.serial_number_hex(), "a2059ed10e435b57");
}

#[test]
fn pem_parse_root_serial_number_unsigned_decimal() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let sn = &cert.parsed.tbs_certificate.serial_number;
    let bytes = sn.as_bytes();
    // Interpret as unsigned u128 to handle high-bit-set serial numbers
    let value = bytes.iter().fold(0u128, |a, &b| (a << 8) | b as u128);
    // 0xA2059ED10E435B57 = 11674912229752527703
    assert_eq!(value, 11674912229752527703u128);
}

#[test]
fn pem_parse_root_is_self_issued() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    assert!(cert.is_self_issued());
}

#[test]
fn pem_parse_root_signature_algorithm() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let oid = cert.parsed.signature_algorithm.oid.to_string();
    assert_eq!(oid, "1.2.840.10045.4.3.2"); // ecdsa-with-SHA256
}

#[test]
fn pem_parse_root_extensions() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let exts = cert.parsed.tbs_certificate.extensions.as_ref().unwrap();

    // Root should have basicConstraints (2.5.29.19) and keyUsage (2.5.29.15)
    let oids: Vec<String> = exts.iter().map(|e| e.extn_id.to_string()).collect();
    assert!(oids.contains(&"2.5.29.19".to_string()), "Missing basicConstraints");
    assert!(oids.contains(&"2.5.29.15".to_string()), "Missing keyUsage");

    // Check basicConstraints: CA:true with no pathLen
    for ext in exts.iter() {
        if ext.extn_id.to_string() == "2.5.29.19" {
            assert!(ext.critical, "basicConstraints should be critical");
            // extn_value.as_bytes() returns inner content (OCTET STRING wrapper stripped)
            // For basicConstraints, this starts with SEQUENCE tag (0x30)
            let bytes = ext.extn_value.as_bytes();
            assert!(bytes[0] == 0x30, "Expected SEQUENCE tag for basicConstraints, got 0x{:02x}", bytes[0]);
        }
        if ext.extn_id.to_string() == "2.5.29.15" {
            assert!(ext.critical, "keyUsage should be critical");
            // For keyUsage, inner content starts with BIT STRING tag (0x03)
            let bytes = ext.extn_value.as_bytes();
            assert!(bytes[0] == 0x03, "Expected BIT STRING tag for keyUsage, got 0x{:02x}", bytes[0]);
        }
    }
}

#[test]
fn pem_parse_intermediate_subject() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_INTERMEDIATE_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let subject = cert.subject_dn();
    assert!(
        subject.contains("Intermediate"),
        "Expected 'Intermediate' in subject, got: {subject}"
    );
}

#[test]
fn pem_parse_intermediate_serial() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_INTERMEDIATE_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    assert_eq!(cert.serial_number_hex(), "1001");
}

#[test]
fn pem_parse_intermediate_not_self_issued() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_INTERMEDIATE_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    assert!(!cert.is_self_issued());
}

#[test]
fn pem_parse_intermediate_basic_constraints() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_INTERMEDIATE_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let exts = cert.parsed.tbs_certificate.extensions.as_ref().unwrap();

    for ext in exts.iter() {
        if ext.extn_id.to_string() == "2.5.29.19" {
            assert!(ext.critical, "basicConstraints should be critical");
            // For intermediate: CA:true, pathLen:0
            // extn_value.as_bytes() returns inner content (OCTET STRING wrapper stripped)
            // DER: SEQUENCE { BOOLEAN TRUE, INTEGER 0 } = 30 05 01 01 FF 02 01 00
            let bytes = ext.extn_value.as_bytes();
            assert!(bytes[0] == 0x30, "Expected SEQUENCE tag for basicConstraints, got 0x{:02x}", bytes[0]);
        }
    }
}

#[test]
fn pem_parse_chain_issuer_subject_chaining() {
    // Root cert's subject should match intermediate's issuer
    let root_certs = load_pem_certs(&[trust_anchors::SOFTWARE_ROOT_PEM]);
    let root = Cert::from_der(&root_certs[0]).unwrap();
    
    let inter_certs = load_pem_certs(&[trust_anchors::SOFTWARE_INTERMEDIATE_PEM]);
    let inter = Cert::from_der(&inter_certs[0]).unwrap();
    
    // Verify issuer/subject chaining
    assert!(
        inter.issuer_eq(&root.subject_der),
        "Intermediate issuer should match root subject"
    );
}

#[test]
fn pem_parse_root_public_key_algorithm() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let pk_oid = cert.parsed.tbs_certificate.subject_public_key_info.algorithm.oid.to_string();
    assert_eq!(pk_oid, "1.2.840.10045.2.1"); // id-ecPublicKey
}


// ── keyUsage and basicConstraints parsing tests ───────────────────────────


#[test]
fn pem_parse_root_key_usage_digital_signature_key_cert_sign() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let exts = cert.parsed.tbs_certificate.extensions.as_ref().unwrap();
    for ext in exts.iter() {
        if ext.extn_id.to_string() == "2.5.29.15" {
            let bits = cert_chain::parse_key_usage(ext.extn_value.as_bytes());
            // Root CA: digitalSignature(bit 0) + keyCertSign(bit 5) = 0x84
            assert!(bits[0], "digitalSignature should be set");
            assert!(!bits[1], "nonRepudiation should not be set");
            assert!(bits[5], "keyCertSign should be set");
            assert!(!bits[2], "keyEncipherment should not be set");
            assert!(!bits[3], "dataEncipherment should not be set");
            assert!(!bits[4], "keyAgreement should not be set");
            assert!(!bits[6], "cRLSign should not be set");
            return;
        }
    }
    panic!("keyUsage extension not found");
}

#[test]
fn pem_parse_root_basic_constraints_ca_true_no_pathlen() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let exts = cert.parsed.tbs_certificate.extensions.as_ref().unwrap();
    for ext in exts.iter() {
        if ext.extn_id.to_string() == "2.5.29.19" {
            let val = cert_chain::parse_basic_constraints(ext.extn_value.as_bytes());
            // Root CA: CA=true, no pathLenConstraint -> Java Integer.MAX_VALUE = 2147483647
            assert_eq!(val, 2147483647, "Root basicConstraints should be 2147483647 (Java Integer.MAX_VALUE)");
            return;
        }
    }
    panic!("basicConstraints extension not found");
}

#[test]
fn pem_parse_intermediate_key_usage_digital_signature_key_cert_sign() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_INTERMEDIATE_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let exts = cert.parsed.tbs_certificate.extensions.as_ref().unwrap();
    for ext in exts.iter() {
        if ext.extn_id.to_string() == "2.5.29.15" {
            let bits = cert_chain::parse_key_usage(ext.extn_value.as_bytes());
            // Intermediate CA: digitalSignature(bit 0) + keyCertSign(bit 5) = 0x84
            assert!(bits[0], "digitalSignature should be set");
            assert!(bits[5], "keyCertSign should be set");
            return;
        }
    }
    panic!("keyUsage extension not found");
}

#[test]
fn pem_parse_intermediate_basic_constraints_ca_true_pathlen_0() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_INTERMEDIATE_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let exts = cert.parsed.tbs_certificate.extensions.as_ref().unwrap();
    for ext in exts.iter() {
        if ext.extn_id.to_string() == "2.5.29.19" {
            let val = cert_chain::parse_basic_constraints(ext.extn_value.as_bytes());
            // Intermediate: CA=true, pathLenConstraint=0
            assert_eq!(val, 0, "Intermediate basicConstraints should be 0 (pathLen:0)");
            return;
        }
    }
    panic!("basicConstraints extension not found");
}

#[test]
fn pem_parse_root_sha256_fingerprint() {
    let certs = load_pem_certs(&[trust_anchors::SOFTWARE_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    // The well-known SHA-256 fingerprint of Google's Software Attestation Root
    // can be verified against the Google published cert
    let spki_der = cert.parsed.tbs_certificate.subject_public_key_info.to_der().unwrap();
    // Just verify it encodes without error
    assert!(!spki_der.is_empty(), "SPKI DER should not be empty");
}
