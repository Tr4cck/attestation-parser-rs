use crate::error::KeyAttestationError;

/// Provisioning information parsed from the certificate extension
/// OID 1.3.6.1.4.1.11129.2.1.30
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisioningInfoMap {
    pub certificates_issued: u32,
}

impl ProvisioningInfoMap {
    /// Parse from raw DER-encoded extension value bytes.
    /// The bytes are the value of the extension (ASN.1 OCTET STRING wrapping CBOR).
    pub fn parse_from_der(bytes: &[u8]) -> Result<Option<Self>, KeyAttestationError> {
        use der::Decode;

        // Unwrap ASN.1 OCTET STRING
        let inner = der::asn1::OctetString::from_der(bytes)
            .map_err(|e| KeyAttestationError::ExtensionParsing {
                message: format!("ProvisioningInfo: failed to unwrap OCTET STRING: {e}"),
                reason: None,
            })?;

        Self::parse_from_cbor(inner.as_bytes())
    }

    /// Parse from raw CBOR bytes.
    pub fn parse_from_cbor(data: &[u8]) -> Result<Option<Self>, KeyAttestationError> {
        let cbor_value: ciborium::value::Value =
            ciborium::from_reader(data).map_err(|e| {
                KeyAttestationError::ExtensionParsing {
                    message: format!("ProvisioningInfo: CBOR decode error: {e}"),
                    reason: None,
                }
            })?;

        let map = match cbor_value {
            ciborium::value::Value::Map(m) => m,
            _ => {
                return Err(KeyAttestationError::ExtensionParsing {
                    message: "ProvisioningInfo: Expected CBOR map".into(),
                    reason: None,
                })
            }
        };

        let mut certificates_issued: Option<u32> = None;
        for (key, val) in map {
            let key_num = match key {
                ciborium::value::Value::Integer(i) => i,
                _ => continue,
            };
            if key_num == 1.into() {
                let val_int = match val {
                    ciborium::value::Value::Integer(i) => i,
                    _ => {
                        return Err(KeyAttestationError::ExtensionParsing {
                            message: "ProvisioningInfo: Expected integer value for key 1".into(),
                            reason: None,
                        })
                    }
                };
                certificates_issued = Some(
                    val_int
                        .try_into()
                        .map_err(|_| KeyAttestationError::ExtensionParsing {
                            message: "ProvisioningInfo: integer overflow".into(),
                            reason: None,
                        })?,
                );
            }
        }

        match certificates_issued {
            Some(c) => Ok(Some(Self { certificates_issued: c })),
            None => Err(KeyAttestationError::ExtensionParsing {
                message: "ProvisioningInfo: missing required field certificates_issued (key 1)"
                    .into(),
                reason: None,
            }),
        }
    }
}
