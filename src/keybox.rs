use crate::error::KeyAttestationError;
use quick_xml::events::Event;
use quick_xml::Reader;

/// A single keybox entry, corresponding to a `<Keybox>` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keybox {
    /// The `DeviceID` attribute on the `<Keybox>` element.
    pub device_id: String,
    /// All `<Key>` entries inside this keybox.
    pub keys: Vec<KeyEntry>,
}

/// A single key entry, corresponding to a `<Key>` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    /// The `algorithm` attribute on the `<Key>` element (e.g. "ecdsa", "rsa").
    pub algorithm: String,
    /// The raw PEM text of the private key.
    pub private_key_pem: String,
    /// The raw PEM text of each certificate in the chain (leaf first).
    pub certificates_pem: Vec<String>,
}

impl KeyEntry {
    /// Convert the PEM certificate chain to DER blobs, suitable for
    /// feeding directly to [`crate::Verifier::verify`] or
    /// [`crate::cert_chain::KeyAttestationCertPath::from_der_blobs`].
    pub fn cert_chain_der(&self) -> Result<Vec<Vec<u8>>, KeyAttestationError> {
        self.certificates_pem
            .iter()
            .map(|pem_str| {
                pem::parse(pem_str)
                    .map(|p| p.contents().to_vec())
                    .map_err(|e| {
                        KeyAttestationError::ChainParsing(format!(
                            "Failed to parse certificate PEM in keybox (algorithm={}): {e}",
                            self.algorithm,
                        ))
                    })
            })
            .collect()
    }

    /// Convert the private key PEM to DER bytes.
    pub fn private_key_der(&self) -> Result<Vec<u8>, KeyAttestationError> {
        pem::parse(&self.private_key_pem)
            .map(|p| p.contents().to_vec())
            .map_err(|e| {
                KeyAttestationError::ChainParsing(format!(
                    "Failed to parse private key PEM in keybox (algorithm={}): {e}",
                    self.algorithm,
                ))
            })
    }
}

// ── Errors specific to keybox XML parsing ──────────────────────────────────

/// Errors that can occur during keybox XML parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyboxParseError {
    /// An XML parsing error from the underlying parser.
    XmlError(String),
    /// The `NumberOfCertificates` count does not match the actual number of
    /// `<Certificate>` elements found.
    CertificateCountMismatch {
        expected: usize,
        actual: usize,
        algorithm: String,
    },
}

impl std::fmt::Display for KeyboxParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::XmlError(msg) => write!(f, "XML parse error: {msg}"),
            Self::CertificateCountMismatch { expected, actual, algorithm } => {
                write!(
                    f,
                    "Certificate count mismatch for algorithm '{algorithm}': \
                     expected {expected}, got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for KeyboxParseError {}

impl From<quick_xml::Error> for KeyboxParseError {
    fn from(e: quick_xml::Error) -> Self {
        Self::XmlError(e.to_string())
    }
}

// ── Public API ─────────────────────────────────────────────────────────────

/// Parse a keybox XML string into a list of [`Keybox`] entries.
///
/// The input should be the raw XML content of an Android Attestation keybox file.
pub fn parse_keybox_xml(xml: &str) -> Result<Vec<Keybox>, KeyboxParseError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut keyboxes: Vec<Keybox> = Vec::new();

    // State machine variables
    let mut current_keybox: Option<Keybox> = None;
    let mut current_key: Option<KeyEntry> = None;
    let mut inside_private_key = false;
    let mut inside_cert = false;
    let mut inside_cert_chain = false;
    let mut inside_number_of_certs = false;
    let mut expected_cert_count: Option<usize> = None;
    let mut current_cert_text = String::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(ref e) => {
                let tag_name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                match tag_name.as_str() {
                    "AndroidAttestation" => {
                        // Root element — nothing to do
                    }
                    "Keybox" => {
                        let device_id = e
                            .try_get_attribute("DeviceID")?
                            .map(|a| String::from_utf8_lossy(a.value.as_ref()).to_string())
                            .unwrap_or_default();
                        current_keybox = Some(Keybox {
                            device_id,
                            keys: Vec::new(),
                        });
                    }
                    "Key" => {
                        let algorithm = e
                            .try_get_attribute("algorithm")?
                            .map(|a| String::from_utf8_lossy(a.value.as_ref()).to_string())
                            .unwrap_or_default();
                        current_key = Some(KeyEntry {
                            algorithm,
                            private_key_pem: String::new(),
                            certificates_pem: Vec::new(),
                        });
                        expected_cert_count = None;
                        current_cert_text.clear();
                    }
                    "PrivateKey" => {
                        inside_private_key = true;
                    }
                    "CertificateChain" => {
                        inside_cert_chain = true;
                    }
                    "NumberOfCertificates" => {
                        inside_number_of_certs = true;
                    }
                    "Certificate" => {
                        inside_cert = true;
                        current_cert_text.clear();
                    }
                    _ => {}
                }
            }
            Event::Text(ref e) => {
                let text = e.unescape()?.to_string();

                if inside_number_of_certs {
                    if let Ok(count) = text.trim().parse::<usize>() {
                        expected_cert_count = Some(count);
                    }
                } else if inside_cert && inside_cert_chain {
                    current_cert_text.push_str(&text);
                } else if inside_private_key {
                    if let Some(ref mut key) = current_key {
                        key.private_key_pem.push_str(&text);
                    }
                }
            }
            Event::End(ref e) => {
                let tag_name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                match tag_name.as_str() {
                    "AndroidAttestation" => {
                        // End of root element
                    }
                    "Keybox" => {
                        if let Some(kb) = current_keybox.take() {
                            keyboxes.push(kb);
                        }
                    }
                    "Key" => {
                        if let Some(key) = current_key.take() {
                            // Verify certificate count matches
                            if let Some(expected) = expected_cert_count {
                                let actual = key.certificates_pem.len();
                                if actual != expected {
                                    return Err(KeyboxParseError::CertificateCountMismatch {
                                        expected,
                                        actual,
                                        algorithm: key.algorithm.clone(),
                                    });
                                }
                            }
                            if let Some(ref mut kb) = current_keybox {
                                kb.keys.push(key);
                            } else {
                                eprintln!(
                                    "Warning: <Key algorithm={}> found outside any <Keybox> — skipped",
                                    key.algorithm
                                );
                            }
                        }
                        expected_cert_count = None;
                        current_cert_text.clear();
                    }
                    "PrivateKey" => {
                        inside_private_key = false;
                    }
                    "CertificateChain" => {
                        inside_cert_chain = false;
                        expected_cert_count = None;
                    }
                    "NumberOfCertificates" => {
                        inside_number_of_certs = false;
                    }
                    "Certificate" => {
                        inside_cert = false;
                        if let Some(ref mut key) = current_key {
                            key.certificates_pem.push(
                                current_cert_text.trim().to_string(),
                            );
                        } else {
                            eprintln!(
                                "Warning: <Certificate> found outside any <Key> — skipped"
                            );
                        }
                        current_cert_text.clear();
                    }
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }

        buf.clear();
    }

    Ok(keyboxes)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_KEYBOX: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<AndroidAttestation>
    <NumberOfKeyboxes>1</NumberOfKeyboxes>
    <Keybox DeviceID="TestDevice">
        <Key algorithm="ecdsa">
            <PrivateKey format="pem">
-----BEGIN EC PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END EC PRIVATE KEY-----
            </PrivateKey>
            <CertificateChain>
                <NumberOfCertificates>1</NumberOfCertificates>
                <Certificate format="pem">
-----BEGIN CERTIFICATE-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END CERTIFICATE-----
                </Certificate>
            </CertificateChain>
        </Key>
    </Keybox>
</AndroidAttestation>"#;

    #[test]
    fn test_parse_single_keybox_with_ecdsa() {
        let result = parse_keybox_xml(SAMPLE_KEYBOX).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].device_id, "TestDevice");
        assert_eq!(result[0].keys.len(), 1);
        assert_eq!(result[0].keys[0].algorithm, "ecdsa");
        assert!(result[0].keys[0].private_key_pem.contains("BEGIN EC PRIVATE KEY"));
        assert_eq!(result[0].keys[0].certificates_pem.len(), 1);
    }

    #[test]
    fn test_cert_chain_der_fails_on_fake_data() {
        let result = parse_keybox_xml(SAMPLE_KEYBOX).unwrap();
        let der_result = result[0].keys[0].cert_chain_der();
        assert!(der_result.is_ok()); // pem::parse succeeds (valid base64)
        assert_eq!(der_result.unwrap().len(), 1);
    }

    #[test]
    fn test_private_key_der_roundtrip() {
        let result = parse_keybox_xml(SAMPLE_KEYBOX).unwrap();
        let der_result = result[0].keys[0].private_key_der();
        assert!(der_result.is_ok());
    }

    #[test]
    fn test_empty_xml() {
        let result = parse_keybox_xml("<?xml version=\"1.0\"?><AndroidAttestation></AndroidAttestation>");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_missing_device_id_defaults_to_empty() {
        let xml = r#"<?xml version="1.0"?>
<AndroidAttestation>
    <NumberOfKeyboxes>1</NumberOfKeyboxes>
    <Keybox>
        <Key algorithm="rsa">
            <PrivateKey format="pem">-----BEGIN-----</PrivateKey>
            <CertificateChain>
                <NumberOfCertificates>0</NumberOfCertificates>
            </CertificateChain>
        </Key>
    </Keybox>
</AndroidAttestation>"#;
        let result = parse_keybox_xml(xml).unwrap();
        assert_eq!(result[0].device_id, "");
    }
}