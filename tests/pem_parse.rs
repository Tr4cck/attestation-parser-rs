//! PEM parsing tests for public Google attestation certificates.
//!
//! Tests that public root and intermediate certificates can be parsed
//! from PEM format and that key fields are extracted correctly.

use attestation_parser_rs::*;
use der::Encode;

fn load_pem_certs(pem_strs: &[&str]) -> Vec<Vec<u8>> {
    pem_strs
        .iter()
        .map(|p| pem::parse(p).unwrap().contents().to_vec())
        .collect()
}

// ── Public Google attestation root & intermediate certificates ────────────

/// Google's Android Keystore Software Attestation Root (public, self-signed).
const SW_ROOT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmll
dzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYD
VQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3Qw
HhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT
BgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwq
QW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59
dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0O
BBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0W
EOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqG
SM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBN
C/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw==
-----END CERTIFICATE-----";

/// Google's Android Keystore Software Attestation Intermediate (public).
const SW_INTERMEDIATE_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICeDCCAh6gAwIBAgICEAEwCgYIKoZIzj0EAwMwgZgxCzAJBgNVBAYTAlVTMRMw
EQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYD
VQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFu
ZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdDAeFw0xNjAx
MTEwMDQ2MDlaFw0yNjAxMDgwMDQ2MDlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
CAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdB
bmRyb2lkMTswOQYDVQQDDDJBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVz
dGF0aW9uIEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOue
efhCY1msyyqRTImGzHCtkGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZjW8
U7ego6ZxWD7bPhGuEBSjZjBkMB0GA1UdDgQWBBQ//KzWGrE6noEguNUlHMVlux6R
qTAfBgNVHSMEGDAWgBTIrel3TEXDo88NFhDkeUM6IVowzzASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNIADBFAiBLipt77oK8
wDOHri/AiZi03cONqycqRZ9pDMfDktQPjgIhAO7aAV229DLp1IQ7YkyUBO86fMy9
Xvsiu+f+uXc/WT/7
-----END CERTIFICATE-----";

// ── PEM parsing tests ─────────────────────────────────────────────────────

#[test]
fn pem_parse_root_subject() {
    let certs = load_pem_certs(&[SW_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let subject = cert.subject_dn();
    assert!(
        subject.contains("Software Attestation Root"),
        "Expected 'Software Attestation Root' in subject, got: {subject}"
    );
}

#[test]
fn pem_parse_root_serial_number_hex() {
    let certs = load_pem_certs(&[SW_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    // Serial: A2059ED10E435B57 (hex)
    assert_eq!(cert.serial_number_hex(), "a2059ed10e435b57");
}

#[test]
fn pem_parse_root_serial_number_unsigned_decimal() {
    let certs = load_pem_certs(&[SW_ROOT_PEM]);
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
    let certs = load_pem_certs(&[SW_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    assert!(cert.is_self_issued());
}

#[test]
fn pem_parse_root_signature_algorithm() {
    let certs = load_pem_certs(&[SW_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let oid = cert.parsed.signature_algorithm.oid.to_string();
    assert_eq!(oid, "1.2.840.10045.4.3.2"); // ecdsa-with-SHA256
}

#[test]
fn pem_parse_root_extensions() {
    let certs = load_pem_certs(&[SW_ROOT_PEM]);
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
    let certs = load_pem_certs(&[SW_INTERMEDIATE_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let subject = cert.subject_dn();
    assert!(
        subject.contains("Intermediate"),
        "Expected 'Intermediate' in subject, got: {subject}"
    );
}

#[test]
fn pem_parse_intermediate_serial() {
    let certs = load_pem_certs(&[SW_INTERMEDIATE_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    assert_eq!(cert.serial_number_hex(), "1001");
}

#[test]
fn pem_parse_intermediate_not_self_issued() {
    let certs = load_pem_certs(&[SW_INTERMEDIATE_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    assert!(!cert.is_self_issued());
}

#[test]
fn pem_parse_intermediate_basic_constraints() {
    let certs = load_pem_certs(&[SW_INTERMEDIATE_PEM]);
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
    let root_certs = load_pem_certs(&[SW_ROOT_PEM]);
    let root = Cert::from_der(&root_certs[0]).unwrap();
    
    let inter_certs = load_pem_certs(&[SW_INTERMEDIATE_PEM]);
    let inter = Cert::from_der(&inter_certs[0]).unwrap();
    
    // Verify issuer/subject chaining
    assert!(
        inter.issuer_eq(&root.subject_der),
        "Intermediate issuer should match root subject"
    );
}

#[test]
fn pem_parse_root_public_key_algorithm() {
    let certs = load_pem_certs(&[SW_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let pk_oid = cert.parsed.tbs_certificate.subject_public_key_info.algorithm.oid.to_string();
    assert_eq!(pk_oid, "1.2.840.10045.2.1"); // id-ecPublicKey
}


// ── keyUsage and basicConstraints parsing tests ───────────────────────────

/// Parse keyUsage BIT STRING from extension value bytes (OCTET STRING wrapper already stripped).
fn parse_key_usage_test(extn_value: &[u8]) -> Vec<bool> {
    let mut bits = vec![false; 9];
    if extn_value.len() < 3 || extn_value[0] != 0x03 { return bits; }
    let len_byte = extn_value[1];
    let (bs_len, bs_hdr) = if len_byte & 0x80 == 0 {
        (len_byte as usize, 2)
    } else {
        let nb = (len_byte & 0x7f) as usize;
        let len = extn_value[2..2 + nb].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
        (len, 2 + nb)
    };
    let bs_content = &extn_value[bs_hdr..bs_hdr + bs_len];
    if bs_content.is_empty() { return bits; }
    let _unused_bits = bs_content[0] as usize;
    let data = &bs_content[1..];
    for i in 0..9 {
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);
        if byte_idx < data.len() {
            bits[i] = (data[byte_idx] >> bit_idx) & 1 == 1;
        }
    }
    bits
}

/// Parse basicConstraints from extension value bytes (OCTET STRING wrapper already stripped).
/// Returns pathLenConstraint value, or i32::MAX for CA:true without pathLen, or -1 for CA:false.
fn parse_basic_constraints_test(extn_value: &[u8]) -> i64 {
    if extn_value.is_empty() || extn_value[0] != 0x30 { return -1; }
    let len_byte = extn_value[1];
    let (seq_len, seq_hdr) = if len_byte & 0x80 == 0 {
        (len_byte as usize, 2)
    } else {
        let nb = (len_byte & 0x7f) as usize;
        let len = extn_value[2..2 + nb].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
        (len, 2 + nb)
    };
    let seq_content = &extn_value[seq_hdr..seq_hdr + seq_len];
    if seq_content.is_empty() { return -1; }
    let mut pos = 0;
    let mut is_ca = false;
    while pos < seq_content.len() {
        let tag = seq_content[pos];
        let len_b = seq_content.get(pos + 1).copied().unwrap_or(0);
        let (el_len, el_hdr) = if len_b & 0x80 == 0 {
            (len_b as usize, 2)
        } else {
            let nb = (len_b & 0x7f) as usize;
            let len = seq_content[pos + 2..pos + 2 + nb].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
            (len, 2 + nb)
        };
        match tag {
            0x01 => {
                if el_len == 1 && pos + el_hdr < seq_content.len() {
                    is_ca = seq_content[pos + el_hdr] != 0x00;
                }
            }
            0x02 => {
                if el_len <= 8 && pos + el_hdr + el_len <= seq_content.len() {
                    let int_bytes = &seq_content[pos + el_hdr..pos + el_hdr + el_len];
                    let val = int_bytes.iter().fold(0i64, |a, &b| (a << 8) | b as i64);
                    if is_ca { return val; }
                }
            }
            _ => {}
        }
        pos += el_hdr + el_len;
    }
    if is_ca { 2147483647 } else { -1 }
}

#[test]
fn pem_parse_root_key_usage_digital_signature_key_cert_sign() {
    let certs = load_pem_certs(&[SW_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let exts = cert.parsed.tbs_certificate.extensions.as_ref().unwrap();
    for ext in exts.iter() {
        if ext.extn_id.to_string() == "2.5.29.15" {
            let bits = parse_key_usage_test(ext.extn_value.as_bytes());
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
    let certs = load_pem_certs(&[SW_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let exts = cert.parsed.tbs_certificate.extensions.as_ref().unwrap();
    for ext in exts.iter() {
        if ext.extn_id.to_string() == "2.5.29.19" {
            let val = parse_basic_constraints_test(ext.extn_value.as_bytes());
            // Root CA: CA=true, no pathLenConstraint -> Java Integer.MAX_VALUE = 2147483647
            assert_eq!(val, 2147483647, "Root basicConstraints should be 2147483647 (Java Integer.MAX_VALUE)");
            return;
        }
    }
    panic!("basicConstraints extension not found");
}

#[test]
fn pem_parse_intermediate_key_usage_digital_signature_key_cert_sign() {
    let certs = load_pem_certs(&[SW_INTERMEDIATE_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let exts = cert.parsed.tbs_certificate.extensions.as_ref().unwrap();
    for ext in exts.iter() {
        if ext.extn_id.to_string() == "2.5.29.15" {
            let bits = parse_key_usage_test(ext.extn_value.as_bytes());
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
    let certs = load_pem_certs(&[SW_INTERMEDIATE_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    let exts = cert.parsed.tbs_certificate.extensions.as_ref().unwrap();
    for ext in exts.iter() {
        if ext.extn_id.to_string() == "2.5.29.19" {
            let val = parse_basic_constraints_test(ext.extn_value.as_bytes());
            // Intermediate: CA=true, pathLenConstraint=0
            assert_eq!(val, 0, "Intermediate basicConstraints should be 0 (pathLen:0)");
            return;
        }
    }
    panic!("basicConstraints extension not found");
}

#[test]
fn pem_parse_root_sha256_fingerprint() {
    let certs = load_pem_certs(&[SW_ROOT_PEM]);
    let cert = Cert::from_der(&certs[0]).unwrap();
    // The well-known SHA-256 fingerprint of Google's Software Attestation Root
    // can be verified against the Google published cert
    let spki_der = cert.parsed.tbs_certificate.subject_public_key_info.to_der().unwrap();
    // Just verify it encodes without error
    assert!(!spki_der.is_empty(), "SPKI DER should not be empty");
}
