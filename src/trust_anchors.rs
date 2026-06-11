use crate::cert_chain::Cert;
use crate::error::KeyAttestationError;
use std::collections::HashSet;

/// A trust anchor for certificate path validation.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    pub cert: Cert,
    pub name_constraints: Option<Vec<u8>>,
}

/// Google's attestation root certificate URL.
pub const GOOGLE_ROOT_URL: &str = "https://android.googleapis.com/attestation/root";

/// Google's attestation certificate status (revocation) URL.
pub const GOOGLE_STATUS_URL: &str = "https://android.googleapis.com/attestation/status";

/// Parse a PEM certificate string into a TrustAnchor.
fn parse_anchor(pem: &str) -> Option<TrustAnchor> {
    let pem = pem::parse(pem).ok()?;
    let cert = Cert::from_der(pem.contents()).ok()?;
    Some(TrustAnchor {
        cert,
        name_constraints: None,
    })
}

/// Load trust anchors from a roots.json-format string (array of PEM strings).
pub fn load_from_json(json: &str) -> Vec<TrustAnchor> {
    let Ok(pems) = serde_json::from_str::<Vec<String>>(json) else {
        return vec![];
    };
    pems.iter().filter_map(|pem| parse_anchor(pem)).collect()
}

/// Fetch Google's attestation root certificates from the official URL.
///
/// See: https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
pub fn fetch_google_roots() -> Result<Vec<TrustAnchor>, String> {
    let response = ureq::get(GOOGLE_ROOT_URL)
        .call()
        .map_err(|e| format!("Failed to fetch root certificates: {e}"))?;

    let body = response
        .into_string()
        .map_err(|e| format!("Failed to read response body: {e}"))?;

    let anchors = load_from_json(&body);
    if anchors.is_empty() {
        return Err("No valid root certificates found in response".into());
    }
    Ok(anchors)
}

/// Retrieve Google's root certificates from the embedded roots.json mirror.
pub fn google_trust_anchors() -> Vec<TrustAnchor> {
    let roots_json = include_str!("../roots.json");
    load_from_json(roots_json)
}

/// The software root certificate used by Android Key Attestation.
pub const SOFTWARE_ROOT_PEM: &str =
    "-----BEGIN CERTIFICATE-----\n\
MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQG\n\
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmll\n\
dzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYD\n\
VQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3Qw\n\
HhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMx\n\
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT\n\
BgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwq\n\
QW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYH\n\
KoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59\n\
dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0O\n\
BBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0W\n\
EOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqG\n\
SM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBN\n\
C/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw==\n\
-----END CERTIFICATE-----";

/// Load the software root certificate.
pub fn software_root() -> Result<Cert, KeyAttestationError> {
    let pem = pem::parse(SOFTWARE_ROOT_PEM).map_err(|e| {
        KeyAttestationError::ChainParsing(format!("Failed to parse SOFTWARE_ROOT PEM: {e}"))
    })?;
    Cert::from_der(pem.contents())
}

/// Check if a certificate's public key matches the software root's public key.
pub fn is_software_root(cert: &Cert) -> bool {
    if let Ok(sw) = software_root() {
        cert.parsed.tbs_certificate.subject_public_key_info
            == sw.parsed.tbs_certificate.subject_public_key_info
    } else {
        false
    }
}

/// Fetch Google's certificate revocation status list.
///
/// Queries `https://android.googleapis.com/attestation/status` and returns
/// the set of revoked certificate serial numbers (unpadded hex).
///
/// The response format is:
/// ```json
/// {
///   "entries": {
///     "<serial_number>": {"status": "REVOKED"},
///     ...
///   }
/// }
/// ```
///
/// See: https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status
pub fn fetch_revoked_serials() -> Result<HashSet<String>, String> {
    let response = ureq::get(GOOGLE_STATUS_URL)
        .call()
        .map_err(|e| format!("Failed to fetch revocation status: {e}"))?;

    let body = response
        .into_string()
        .map_err(|e| format!("Failed to read response body: {e}"))?;

    parse_attestation_status(&body)
}

/// Parse attestation status JSON into a set of revoked serial numbers.
///
/// Only entries with `"status": "REVOKED"` are included.
/// Serial numbers are normalised to unpadded hex.
pub fn parse_attestation_status(json: &str) -> Result<HashSet<String>, String> {
    #[derive(serde::Deserialize)]
    struct StatusEntry {
        status: String,
    }

    #[derive(serde::Deserialize)]
    struct StatusFile {
        entries: std::collections::HashMap<String, StatusEntry>,
    }

    let status_file: StatusFile = serde_json::from_str(json)
        .map_err(|e| format!("Failed to parse revocation status JSON: {e}"))?;

    let revoked: HashSet<String> = status_file
        .entries
        .into_iter()
        .filter(|(_, v)| v.status == "REVOKED")
        .map(|(k, _)| {
            let trimmed = k.trim_start_matches('0');
            if trimmed.is_empty() {
                "0".to_string()
            } else {
                trimmed.to_string()
            }
        })
        .collect();

    Ok(revoked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_attestation_status() {
        let json = r#"{
            "entries": {
                "00ABC123": {"status": "REVOKED"},
                "00DEF456": {"status": "ACTIVE"},
                "0": {"status": "REVOKED"}
            }
        }"#;

        let revoked = parse_attestation_status(json).unwrap();
        assert!(revoked.contains("ABC123"));
        assert!(!revoked.contains("DEF456"));
        assert!(revoked.contains("0"));
        assert_eq!(revoked.len(), 2);
    }

    #[test]
    fn test_load_roots_from_json() {
        let json = r#"["-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQG\nEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmll\ndzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYD\nVQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3Qw\nHhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMx\nEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT\nBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwq\nQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYH\nKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59\ndx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0O\nBBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0W\nEOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqG\nSM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBN\nC/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw==\n-----END CERTIFICATE-----"]"#;
        let anchors = load_from_json(json);
        assert_eq!(anchors.len(), 1);
    }
}
