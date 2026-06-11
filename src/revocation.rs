use crate::cert_chain::Cert;
use crate::error::{KeyAttestationError, KeyAttestationReason};
use std::collections::HashSet;

/// Checks whether certificates in a chain have been revoked.
pub struct RevocationChecker {
    revoked_serials: HashSet<String>,
}

impl RevocationChecker {
    pub fn new(revoked_serials: HashSet<String>) -> Self {
        Self { revoked_serials }
    }

    /// Check a single certificate against the revocation list.
    /// Returns Ok(()) if not revoked, Err if revoked.
    pub fn check(&self, cert: &Cert) -> Result<(), KeyAttestationError> {
        let serial = cert.serial_number_hex();
        if self.revoked_serials.contains(&serial) {
            Err(KeyAttestationError::PathValidation {
                message: format!("Certificate has been revoked: {serial}"),
                reason: KeyAttestationReason::Revoked,
            })
        } else {
            Ok(())
        }
    }
}
