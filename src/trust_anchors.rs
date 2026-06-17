use crate::cert_chain::Cert;
use crate::error::KeyAttestationError;
use base64::Engine;
use der::Encode;
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
fn parse_anchor_pem(pem_str: &str) -> Option<TrustAnchor> {
    let pem = pem::parse(pem_str).ok()?;
    let cert = Cert::from_der(pem.contents()).ok()?;
    Some(TrustAnchor {
        cert,
        name_constraints: None,
    })
}

/// Parse a base64-encoded DER certificate into a TrustAnchor.
fn parse_anchor_b64(b64: &str) -> Option<TrustAnchor> {
    let der = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let cert = Cert::from_der(&der).ok()?;
    Some(TrustAnchor {
        cert,
        name_constraints: None,
    })
}

/// Load trust anchors from the new roots.json format
/// (array of `{"id", "sha256Fingerprint", "certDerBase64"}` objects).
/// Also accepts the old format (array of PEM strings) for backward compatibility.
pub fn load_from_json(json: &str) -> Vec<TrustAnchor> {
    // Try new format first: array of objects
    if let Ok(objs) = serde_json::from_str::<Vec<serde_json::Value>>(json) {
        if objs.first().and_then(|o| o.get("certDerBase64")).is_some() {
            return objs
                .iter()
                .filter_map(|o| {
                    o.get("certDerBase64")
                        .and_then(|v| v.as_str())
                        .and_then(parse_anchor_b64)
                })
                .collect();
        }
    }
    // Fallback: old format — array of PEM strings
    let Ok(pems) = serde_json::from_str::<Vec<String>>(json) else {
        return vec![];
    };
    pems.iter().filter_map(|pem| parse_anchor_pem(pem)).collect()
}

/// SHA-256 fingerprints of the embedded Google root certificates.
///
/// These are read directly from the embedded `roots.json` at compile time
/// and serve as the trusted baseline for verifying root certificates
/// loaded from cache or the network.
pub fn embedded_root_sha256s() -> &'static HashSet<String> {
    use std::sync::OnceLock;
    static SHA256S: OnceLock<HashSet<String>> = OnceLock::new();
    SHA256S.get_or_init(|| {
        let roots_json: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../roots.json")).unwrap_or_default();
        roots_json
            .iter()
            .filter_map(|o| {
                o.get("sha256Fingerprint")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_lowercase())
            })
            .collect()
    })
}

/// Verify that at least one of the given trust anchors matches a known
/// embedded root (by SHA-256 of the DER-encoded certificate). If none
/// match, the source (cache file or network response) may have been
/// tampered with or is corrupted.
pub fn verify_roots_match_embedded(anchors: &[TrustAnchor]) -> Result<(), String> {
    let embedded = embedded_root_sha256s();
    if embedded.is_empty() {
        return Ok(());
    }
    let any_match = anchors.iter().any(|a| {
        let sha = crate::cert_chain::sha256_hex(
            &a.cert.parsed.to_der().unwrap_or_default(),
        );
        embedded.contains(&sha)
    });
    if any_match {
        Ok(())
    } else {
        Err(format!(
            "None of the {} loaded root certificates match the {} known embedded roots. \
             The data source may be tampered with.",
            anchors.len(),
            embedded.len()
        ))
    }
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
    verify_roots_match_embedded(&anchors)?;
    Ok(anchors)
}

/// Retrieve Google's root certificates from the embedded roots.json mirror.
pub fn google_trust_anchors() -> Vec<TrustAnchor> {
    let roots_json = include_str!("../roots.json");
    load_from_json(roots_json)
}

/// Compute the SHA-256 fingerprint and an ID string for a trust anchor.
/// Returns `(id, sha256_hex)` where `id` is a human-readable identifier
/// derived from the certificate's subject and algorithm.
pub fn fingerprint_anchor(anchor: &TrustAnchor) -> (String, String) {
    let der = anchor.cert.parsed.to_der().unwrap_or_default();
    let sha256 = crate::cert_chain::sha256_hex(&der);

    let dn = anchor.cert.subject_dn();
    let cn = dn
        .split(',')
        .find(|p| p.trim().starts_with("CN="))
        .map(|p| p.trim().trim_start_matches("CN=").trim())
        .unwrap_or("Google Root");

    let sig_oid = anchor.cert.parsed.signature_algorithm.oid.to_string();
    let algo = if sig_oid.contains("ecdsa") || sig_oid.contains("ec") {
        "EC"
    } else {
        "RSA"
    };

    let id = format!("google_attestation_root_{cn}_{algo}")
        .replace(' ', "_")
        .to_lowercase();

    (id, sha256)
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
/// The software intermediate certificate used by Android Key Attestation (public).
/// Serial: 1001, ECDSA P-256, valid 2016-01-11 to 2026-01-08.
/// Issued by the Software Attestation Root.
pub const SOFTWARE_INTERMEDIATE_PEM: &str =
    "-----BEGIN CERTIFICATE-----\n\
MIICeDCCAh6gAwIBAgICEAEwCgYIKoZIzj0EAwMwgZgxCzAJBgNVBAYTAlVTMRMw\n\
EQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYD\n\
VQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFu\n\
ZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdDAeFw0xNjAx\n\
MTEwMDQ2MDlaFw0yNjAxMDgwMDQ2MDlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE\n\
CAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdB\n\
bmRyb2lkMTswOQYDVQQDDDJBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVz\n\
dGF0aW9uIEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOue\n\
efhCY1msyyqRTImGzHCtkGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZjW8\n\
U7ego6ZxWD7bPhGuEBSjZjBkMB0GA1UdDgQWBBQ//KzWGrE6noEguNUlHMVlux6R\n\
qTAfBgNVHSMEGDAWgBTIrel3TEXDo88NFhDkeUM6IVowzzASBgNVHRMBAf8ECDAG\n\
AQH/AgEAMA4GA1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNIADBFAiBLipt77oK8\n\
wDOHri/AiZi03cONqycqRZ9pDMfDktQPjgIhAO7aAV229DLp1IQ7YkyUBO86fMy9\n\
Xvsiu+f+uXc/WT/7\n\
-----END CERTIFICATE-----";


static SOFTWARE_ROOT_CACHE: std::sync::OnceLock<Result<Cert, String>> = std::sync::OnceLock::new();

/// Load the software root certificate (cached after first call).
pub fn software_root() -> Result<&'static Cert, KeyAttestationError> {
    match SOFTWARE_ROOT_CACHE.get_or_init(|| {
        match pem::parse(SOFTWARE_ROOT_PEM) {
            Ok(p) => match Cert::from_der(p.contents()) {
                Ok(c) => Ok(c),
                Err(e) => Err(e.to_string()),
            },
            Err(e) => Err(format!("Failed to parse SOFTWARE_ROOT PEM: {e}")),
        }
    }) {
        Ok(cert) => Ok(cert),
        Err(e) => Err(KeyAttestationError::ChainParsing(e.clone())),
    }
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
