use crate::cert_chain::{KeyAttestationCertPath, ProvisioningMethod};
use crate::constraint::{ConstraintConfig, ConstraintResult};
use crate::extension::{DeviceIdentity, KeyDescription, SecurityLevel, VerifiedBootState};
use crate::revocation::RevocationChecker;
use crate::trust_anchors::TrustAnchor;
use crate::validator;
use der::Encode;

use std::collections::HashSet;

/// The result of verifying an Android Key Attestation certificate chain.
#[derive(Debug)]
pub enum VerificationResult {
    Success {
        public_key_der: Vec<u8>,
        challenge: Vec<u8>,
        security_level: SecurityLevel,
        verified_boot_state: VerifiedBootState,
        device_locked: bool,
        device_information: Option<crate::provisioning::ProvisioningInfoMap>,
        attested_device_ids: Box<DeviceIdentity>,
    },
    ChallengeMismatch,
    /// Certificate chain is structurally invalid (wrong number of certs, malformed DER, etc.).
    ChainParsingFailure {
        message: String,
    },
    /// Certificate validation failed: signature, name chaining, expiry, revocation, or trust anchor.
    PathValidationFailure {
        message: String,
    },
    /// The key attestation extension (1.3.6.1.4.1.11129.2.1.17) is missing or unparseable.
    ExtensionParsingFailure {
        message: String,
    },
    /// A constraint on the key description was violated (e.g. security level, origin).
    ConstraintViolation {
        label: String,
        message: String,
    },
}

/// Strict verifier for Android Key Attestation.
///
/// Always validates against Google's production trust anchors and checks for revoked
/// certificates. The three mandatory checks are:
/// 1. Certificate chain validation (signatures, name chaining, expiry, extension expectations)
/// 2. Google trust anchor check (chain must trace to a Google root)
/// 3. Revocation check (certificates must not appear in Google's revocation list)
pub struct Verifier<IS>
where
    IS: Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync,
{
    trust_anchors: Vec<TrustAnchor>,
    revoked_serials: HashSet<String>,
    instant_source: IS,
    constraint_config: ConstraintConfig,
}

impl<IS> Verifier<IS>
where
    IS: Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync,
{
    /// Create a strict verifier with Google production trust anchors.
    ///
    /// The trust anchors are loaded from the embedded `roots.json`.
    /// Software attestation roots are rejected as trust anchors.
    ///
    /// No revocation data is loaded. Use [`google_cached`] or [`google_live`] for
    /// revocation-aware verification.
    pub fn google(instant_source: IS) -> Self {
        let anchors = crate::trust_anchors::google_trust_anchors();
        for anchor in &anchors {
            if crate::trust_anchors::is_software_root(&anchor.cert) {
                panic!("Software attestation root cannot be used as a trust anchor");
            }
        }
        Self {
            trust_anchors: anchors,
            revoked_serials: HashSet::new(),
            instant_source,
            constraint_config: ConstraintConfig::default(),
        }
    }

    /// Create a strict verifier with Google trust anchors and a revocation list.
    pub fn google_with_revocation(instant_source: IS, revoked_serials: HashSet<String>) -> Self {
        let mut v = Self::google(instant_source);
        v.revoked_serials = revoked_serials;
        v
    }

    /// Create a strict verifier that fetches Google trust anchors and revocation status
    /// from the official Android attestation endpoints.
    ///
    /// Fetches roots from `https://android.googleapis.com/attestation/root`
    /// and revoked serials from `https://android.googleapis.com/attestation/status`.
    ///
    /// On success, also saves the fetched data to the local cache so that
    /// [`google_cached`] can use it in future offline sessions.
    ///
    /// Returns an error string if either fetch fails (fail-closed).
    pub fn google_live(instant_source: IS) -> Result<Self, String> {
        let anchors = crate::trust_anchors::fetch_google_roots()?;
        let revoked = crate::trust_anchors::fetch_revoked_serials()?;

        for anchor in &anchors {
            if crate::trust_anchors::is_software_root(&anchor.cert) {
                return Err("Software attestation root cannot be used as a trust anchor".into());
            }
        }

        // Save the fetched data to the local cache for offline use.
        if let Err(e) = crate::cache::save_cache(&anchors, &revoked) {
            eprintln!("Warning: failed to save attestation cache: {e}");
        }

        Ok(Self {
            trust_anchors: anchors,
            revoked_serials: revoked,
            instant_source,
            constraint_config: ConstraintConfig::default(),
        })
    }

    /// Create a strict verifier using cached revocation data.
    ///
    /// Loads trust anchors and revoked serial numbers from the local cache file
    /// (saved by a previous `--live` invocation). If the cache is missing or invalid,
    /// falls back to the embedded trust anchors with an empty revocation list
    /// (same as [`google`]).
    ///
    /// This provides offline revocation checking without network requests.
    pub fn google_cached(instant_source: IS) -> Self {
        match crate::cache::load_cache() {
            Some((cached_anchors, revoked)) => {
                for anchor in &cached_anchors {
                    if crate::trust_anchors::is_software_root(&anchor.cert) {
                        eprintln!("Warning: cache contains software root as trust anchor, ignoring cache");
                        return Self::google(instant_source);
                    }
                }
                Self {
                    trust_anchors: cached_anchors,
                    revoked_serials: revoked,
                    instant_source,
                    constraint_config: ConstraintConfig::default(),
                }
            }
            None => {
                eprintln!("No attestation cache found; using embedded trust anchors with no revocation data.");
                eprintln!("Run with --live once to download and cache the latest revocation list.");
                Self::google(instant_source)
            }
        }
    }

    /// Create a verifier with custom trust anchors (must include at least one non-software anchor).
    ///
    /// Panics if any software root is used as a trust anchor.
    pub fn with_anchors(
        trust_anchors: Vec<TrustAnchor>,
        revoked_serials: HashSet<String>,
        instant_source: IS,
    ) -> Self {
        for anchor in &trust_anchors {
            if crate::trust_anchors::is_software_root(&anchor.cert) {
                panic!("Software attestation root cannot be used as a trust anchor");
            }
        }
        Self {
            trust_anchors,
            revoked_serials,
            instant_source,
            constraint_config: ConstraintConfig::default(),
        }
    }

    pub fn with_constraint_config(mut self, config: ConstraintConfig) -> Self {
        self.constraint_config = config;
        self
    }

    /// Verify a certificate chain (DER-encoded certificates, leaf first, root last).
    ///
    /// Performs all three mandatory strict checks:
    /// 1. Certificate chain validation
    /// 2. Google trust anchor check
    /// 3. Revocation check
    pub fn verify(
        &self,
        chain: &[Vec<u8>],
        expected_challenge: Option<&[u8]>,
    ) -> VerificationResult {
        let cert_path = match KeyAttestationCertPath::from_der_blobs(chain.to_vec()) {
            Ok(cp) => cp,
            Err(e) => {
                return VerificationResult::ChainParsingFailure {
                    message: e.to_string(),
                };
            }
        };

        let revocation_checker = RevocationChecker::new(self.revoked_serials.clone());
        let date = (self.instant_source)();

        let _public_key_der = match validator::validate(
            &cert_path,
            &self.trust_anchors,
            &revocation_checker,
            &date,
        ) {
            Ok(pk) => pk,
            Err(e) => {
                return VerificationResult::PathValidationFailure {
                    message: e.to_string(),
                };
            }
        };

        let device_information =
            if cert_path.provisioning_method() == ProvisioningMethod::RemotelyProvisioned {
                cert_path
                    .attestation_cert()
                    .get_extension_value(crate::extension::PROVISIONING_INFO_OID)
                    .and_then(|bytes| {
                        crate::provisioning::ProvisioningInfoMap::parse_from_der(&bytes).ok()
                    })
                    .flatten()
            } else {
                None
            };

        let key_description = {
            let ext_value = cert_path
                .leaf_cert()
                .get_extension_value(crate::extension::KEY_DESCRIPTION_OID);

            let ext_bytes = match ext_value {
                Some(b) => b,
                None => {
                    return VerificationResult::ExtensionParsingFailure {
                        message: "Key attestation extension not found".into(),
                    };
                }
            };

            match KeyDescription::parse_from_der(&ext_bytes) {
                Ok(Some(kd)) => kd,
                Ok(None) => {
                    return VerificationResult::ExtensionParsingFailure {
                        message: "Key attestation extension not found (null)".into(),
                    };
                }
                Err(e) => {
                    return VerificationResult::ExtensionParsingFailure {
                        message: e.to_string(),
                    };
                }
            }
        };

        if let Some(expected) = expected_challenge {
            if key_description.attestation_challenge != expected {
                return VerificationResult::ChallengeMismatch;
            }
        }

        for constraint in self.constraint_config.get_constraints() {
            match constraint.check(&key_description) {
                ConstraintResult::Satisfied => {}
                ConstraintResult::Violated(msg) => {
                    return VerificationResult::ConstraintViolation {
                        label: constraint.label().to_string(),
                        message: msg,
                    };
                }
            }
        }

        let security_level = min_security_level(
            key_description.attestation_security_level,
            key_description.key_mint_security_level,
        );
        let root_of_trust = &key_description.hardware_enforced.root_of_trust;
        let verified_boot_state = root_of_trust
            .as_ref()
            .map(|r| r.verified_boot_state)
            .unwrap_or(VerifiedBootState::Unverified);
        let device_locked = root_of_trust
            .as_ref()
            .map(|r| r.device_locked)
            .unwrap_or(false);

        VerificationResult::Success {
            public_key_der: cert_path
                .leaf_cert()
                .parsed
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap_or_default(),
            challenge: key_description.attestation_challenge.clone(),
            security_level,
            verified_boot_state,
            device_locked,
            device_information,
            attested_device_ids: Box::new(DeviceIdentity::parse_from(&key_description)),
        }
    }
}

fn min_security_level(a: SecurityLevel, b: SecurityLevel) -> SecurityLevel {
    use std::cmp::Ordering;
    match (a as i32).cmp(&(b as i32)) {
        Ordering::Less => a,
        _ => b,
    }
}
