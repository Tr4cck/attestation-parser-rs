use crate::error::KeyAttestationError;
use crate::extension;
use x509_cert::Certificate;
use der::{Decode, Encode};

#[derive(Debug, Clone)]
pub struct Cert {
    pub parsed: Certificate,
    pub tbs_der: Vec<u8>,
    /// DER-encoded issuer Name for comparison.
    pub issuer_der: Vec<u8>,
    /// DER-encoded subject Name for comparison.
    pub subject_der: Vec<u8>,
}

impl Cert {
    pub fn from_der(bytes: &[u8]) -> Result<Self, KeyAttestationError> {
        let parsed = Certificate::from_der(bytes).map_err(|e| {
            KeyAttestationError::ChainParsing(format!("Failed to parse certificate: {e}"))
        })?;
        let tbs_der = parsed.tbs_certificate.to_der().map_err(|e| {
            KeyAttestationError::ChainParsing(format!("Failed to encode TBSCertificate: {e}"))
        })?;
        let issuer_der = parsed.tbs_certificate.issuer.to_der().map_err(|e| {
            KeyAttestationError::ChainParsing(format!("Failed to encode issuer DN: {e}"))
        })?;
        let subject_der = parsed.tbs_certificate.subject.to_der().map_err(|e| {
            KeyAttestationError::ChainParsing(format!("Failed to encode subject DN: {e}"))
        })?;
        Ok(Self { parsed, tbs_der, issuer_der, subject_der })
    }

    /// Format as RFC 1779-like string for display/provisioning parsing.
    pub fn issuer_dn(&self) -> String {
        name_to_string(&self.parsed.tbs_certificate.issuer)
    }

    pub fn subject_dn(&self) -> String {
        name_to_string(&self.parsed.tbs_certificate.subject)
    }

    /// Compare issuer DER encoding for name chaining.
    pub fn issuer_eq(&self, subject_der: &[u8]) -> bool {
        self.issuer_der == subject_der
    }

    pub fn serial_number_hex(&self) -> String {
        let hex_str = hex::encode(self.parsed.tbs_certificate.serial_number.as_bytes())
            .to_ascii_lowercase();
        let trimmed: &str = hex_str.trim_start_matches('0');
        if trimmed.is_empty() { "0".into() } else { trimmed.to_string() }
    }

    pub fn is_self_issued(&self) -> bool {
        self.issuer_der == self.subject_der
    }

    pub fn has_attestation_extension(&self) -> bool {
        self.parsed
            .tbs_certificate
            .extensions
            .as_ref()
            .map(|exts| {
                exts.iter().any(|ext| {
                    ext.extn_id.to_string() == extension::KEY_DESCRIPTION_OID && !ext.critical
                })
            })
            .unwrap_or(false)
    }

    pub fn get_extension_value(&self, oid: &str) -> Option<Vec<u8>> {
        self.parsed
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|exts| exts.iter().find(|ext| ext.extn_id.to_string() == oid))
            .map(|ext| ext.extn_value.as_bytes().to_vec())
    }
}

/// Format a Name as an RFC 1779-like string by converting to Display.
fn name_to_string(name: &x509_cert::name::Name) -> String {
    // Use Display trait of Name which produces a reasonable DN string
    name.to_string()
}

fn parse_dn(dn: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for part in dn.split(',') {
        let kv: Vec<&str> = part.trim().splitn(2, '=').collect();
        if kv.len() == 2 {
            map.insert(kv[0].trim().to_string(), kv[1].trim().to_string());
        }
    }
    map
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisioningMethod {
    Unknown,
    FactoryProvisioned,
    RemotelyProvisioned,
}

pub struct KeyAttestationCertPath {
    pub certificates_with_anchor: Vec<Cert>,
}

impl KeyAttestationCertPath {
    pub fn from_der_blobs(certs: Vec<Vec<u8>>) -> Result<Self, KeyAttestationError> {
        if certs.len() < 3 {
            return Err(KeyAttestationError::ChainParsing(
                "At least 3 certificates are required".into(),
            ));
        }

        let parsed: Vec<Cert> = certs
            .iter()
            .map(|der| Cert::from_der(der))
            .collect::<Result<Vec<_>, _>>()?;

        if !parsed.last().unwrap().is_self_issued() {
            return Err(KeyAttestationError::ChainParsing(
                "Root certificate not found (last cert must be self-issued)".into(),
            ));
        }

        Ok(Self { certificates_with_anchor: parsed })
    }

    pub fn leaf_cert(&self) -> &Cert { &self.certificates_with_anchor[0] }
    pub fn attestation_cert(&self) -> &Cert { &self.certificates_with_anchor[1] }
    pub fn intermediate_cert(&self) -> &Cert {
        // The certificate immediately before the root (last non-root).
        &self.certificates_with_anchor[self.certificates_with_anchor.len() - 2]
    }

    pub fn certificates(&self) -> &[Cert] {
        &self.certificates_with_anchor[..self.certificates_with_anchor.len() - 1]
    }

    pub fn serial_numbers(&self) -> Vec<String> {
        self.certificates_with_anchor.iter().map(|c| c.serial_number_hex()).collect()
    }

    pub fn provisioning_method(&self) -> ProvisioningMethod {
        if self.is_factory_provisioned() {
            ProvisioningMethod::FactoryProvisioned
        } else if self.is_remotely_provisioned() {
            ProvisioningMethod::RemotelyProvisioned
        } else {
            ProvisioningMethod::Unknown
        }
    }

    pub fn security_level(&self) -> crate::extension::SecurityLevel {
        match self.provisioning_method() {
            ProvisioningMethod::FactoryProvisioned => {
                let dn = self.intermediate_cert().subject_dn();
                let parsed = parse_dn(&dn);
                parsed.get("OID.2.5.4.12")
                    .map(|t| dn_title_to_security_level(t))
                    .unwrap_or(crate::extension::SecurityLevel::Software)
            }
            ProvisioningMethod::RemotelyProvisioned => {
                let dn = self.attestation_cert().subject_dn();
                let parsed = parse_dn(&dn);
                parsed.get("O").map(|o| org_to_security_level(o))
                    .unwrap_or(crate::extension::SecurityLevel::Software)
            }
            ProvisioningMethod::Unknown => crate::extension::SecurityLevel::Software,
        }
    }

    fn is_factory_provisioned(&self) -> bool {
        let dn = self.intermediate_cert().subject_dn();
        let parsed = parse_dn(&dn);
        parsed.contains_key("OID.2.5.4.5")
            && parsed.get("OID.2.5.4.12")
                .is_some_and(|t| *t == "TEE" || *t == "StrongBox")
    }

    fn is_remotely_provisioned(&self) -> bool {
        let dn = self.intermediate_cert().subject_dn();
        let parsed = parse_dn(&dn);
        parsed.get("CN") == Some(&"Droid CA2".to_string())
            && parsed.get("O") == Some(&"Google LLC".to_string())
    }
}

fn dn_title_to_security_level(title: &str) -> crate::extension::SecurityLevel {
    match title {
        "TEE" => crate::extension::SecurityLevel::TrustedEnvironment,
        "StrongBox" => crate::extension::SecurityLevel::StrongBox,
        _ => crate::extension::SecurityLevel::Software,
    }
}

fn org_to_security_level(org: &str) -> crate::extension::SecurityLevel {
    match org {
        "TEE" => crate::extension::SecurityLevel::TrustedEnvironment,
        "StrongBox" => crate::extension::SecurityLevel::StrongBox,
        _ => crate::extension::SecurityLevel::Software,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dn() {
        let dn = "CN=Test, O=Google LLC, OID.2.5.4.5=123456";
        let parsed = parse_dn(dn);
        assert_eq!(parsed.get("CN"), Some(&"Test".to_string()));
        assert_eq!(parsed.get("O"), Some(&"Google LLC".to_string()));
    }
}
