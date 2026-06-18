use crate::cert_chain::{Cert, KeyAttestationCertPath, ProvisioningMethod};
use crate::error::{KeyAttestationError, KeyAttestationReason};
use crate::revocation::RevocationChecker;
use crate::trust_anchors::TrustAnchor;

use der::Encode;
use der::Decode as _;

pub fn validate(
    cert_path: &KeyAttestationCertPath,
    trust_anchors: &[TrustAnchor],
    revocation_checker: &RevocationChecker,
    date: &chrono::DateTime<chrono::Utc>,
) -> Result<Vec<u8>, KeyAttestationError> {
    let cert_list: Vec<&Cert> = cert_path.certificates().iter().rev().collect();
    let first_issuer_der = &cert_list.first().unwrap().issuer_der;

    let mut last_error: Option<KeyAttestationError> = None;

    for anchor in trust_anchors {
        // Compare DER-encoded subject of anchor == DER-encoded issuer of first cert
        if anchor.cert.subject_der != *first_issuer_der {
            continue;
        }

        match validate_with_anchor(cert_path, anchor, revocation_checker, date, &cert_list) {
            Ok(pk) => {
                // Defense-in-depth: cross-verify the actual root certificate's
                // SHA-256 against the embedded fingerprint baseline (roots.json).
                // The anchor identity is confirmed (subject DER match), and the
                // signature chain is verified. This extra check ensures the root
                // cert bytes match a known Google root — catching subtle
                // attacks or corruption that the identity+signature checks miss.
                let root_der = anchor.cert.parsed.to_der().map_err(|e| {
                    KeyAttestationError::PathValidation {
                        message: format!("Failed to encode anchor for fingerprint check: {e}"),
                        reason: KeyAttestationReason::Unspecified,
                    }
                })?;
                let root_sha256 = crate::cert_chain::sha256_hex(&root_der);
                let known = crate::trust_anchors::embedded_root_sha256s();
                if !known.is_empty() && !known.contains(&root_sha256) {
                    return Err(KeyAttestationError::PathValidation {
                        message: format!(
                            "Trust anchor SHA-256 {} does not match any known Google root \
                             fingerprint. The trust anchor may be tampered with.",
                            root_sha256
                        ),
                        reason: KeyAttestationReason::NoTrustAnchor,
                    });
                }
                return Ok(pk);
            }
            Err(e) => {
                last_error = Some(e);
            }
        }
    }

    if crate::trust_anchors::is_software_root(cert_path.intermediate_cert()) {
        return Err(KeyAttestationError::PathValidation {
            message: "Chain terminates in a software root and no matching trust anchor was found"
                .into(),
            reason: KeyAttestationReason::NoTrustAnchor,
        });
    }

    Err(last_error.unwrap_or_else(|| KeyAttestationError::PathValidation {
        message: "No matching trust anchor found".into(),
        reason: KeyAttestationReason::NoTrustAnchor,
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    FactoryIntermediate,
    RkpIntermediate,
    RkpServer,
    Attestation,
    Target,
}

fn validate_with_anchor(
    cert_path: &KeyAttestationCertPath,
    anchor: &TrustAnchor,
    revocation_checker: &RevocationChecker,
    date: &chrono::DateTime<chrono::Utc>,
    cert_list: &[&Cert],
) -> Result<Vec<u8>, KeyAttestationError> {
    let mut prev_pub_key_bytes = anchor
        .cert
        .parsed
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| KeyAttestationError::PathValidation {
            message: format!("Failed to encode anchor SPKI: {e}"),
            reason: KeyAttestationReason::Unspecified,
        })?;

    let mut prev_subject_der = anchor.cert.subject_der.clone();
    let mut step: Option<Step> = None;
    let mut prev_was_target = false;
    let total_certs = cert_list.len();

    // Collect all errors across the chain instead of short-circuiting on
    // the first one. Users see the full picture in a single verification run.
    let mut errors: Vec<KeyAttestationError> = Vec::new();

    for (idx, cert) in cert_list.iter().enumerate() {
        let remaining = total_certs - (idx + 1);
        step = Some(determine_step(step, cert_path, total_certs));

        // Reject trailing certs after the target (chain extension attack prevention)
        if step == Some(Step::Target) && prev_was_target {
            errors.push(KeyAttestationError::PathValidation {
                message: "Unexpected certificate after the target certificate".into(),
                reason: KeyAttestationReason::ChainExtendedForKey,
            });
        }
        prev_was_target = step == Some(Step::Target);

        // Name chaining: issuer of current cert must equal subject of previous
        if !cert.issuer_eq(&prev_subject_der) {
            errors.push(KeyAttestationError::PathValidation {
                message: format!(
                    "Subject/Issuer name chaining check failed (cert {})",
                    idx
                ),
                reason: KeyAttestationReason::NameChaining,
            });
        }

        // Signature verification
        if let Err(e) = verify_signature(cert, &prev_pub_key_bytes) {
            errors.push(e);
        }

        // Validity check (skip for target/leaf)
        if remaining > 0 {
            if let Err(e) = verify_validity(cert, date, cert_path.provisioning_method()) {
                errors.push(e);
            }
        }

        // Revocation check (always enforced)
        if let Err(e) = revocation_checker.check(cert) {
            errors.push(e);
        }

        // Step expectations
        if let Err(e) = verify_expectations(cert, step.unwrap()) {
            errors.push(e);
        }

        // Update for next iteration (always advance through the chain
        // regardless of whether the current cert had errors).
        prev_pub_key_bytes = match cert
            .parsed
            .tbs_certificate
            .subject_public_key_info
            .to_der()
        {
            Ok(spki) => spki,
            Err(e) => {
                errors.push(KeyAttestationError::PathValidation {
                    message: format!("Failed to encode SPKI: {e}"),
                    reason: KeyAttestationReason::Unspecified,
                });
                // Can't continue — we need this SPKI for the next iteration.
                return Err(join_path_errors(&errors));
            }
        };
        prev_subject_der = cert.subject_der.clone();
    }

    // If any errors were collected, return them all joined.
    if !errors.is_empty() {
        return Err(join_path_errors(&errors));
    }

    cert_path
        .leaf_cert()
        .parsed
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| KeyAttestationError::PathValidation {
            message: format!("Failed to encode leaf SPKI: {e}"),
            reason: KeyAttestationReason::Unspecified,
        })
}

/// Join multiple path validation errors into a single multi-message error.
/// The primary reason comes from the first error for categorisation.
fn join_path_errors(errors: &[KeyAttestationError]) -> KeyAttestationError {
    let count = errors.len();
    let messages: Vec<String> = errors
        .iter()
        .map(|e| format!("  - {}", e))
        .collect();
    let primary_reason = match errors.first() {
        Some(KeyAttestationError::PathValidation { reason, .. }) => reason.clone(),
        _ => KeyAttestationReason::Unspecified,
    };
    KeyAttestationError::PathValidation {
        message: format!(
            "{} path validation error(s):\n{}",
            count,
            messages.join("\n")
        ),
        reason: primary_reason,
    }
}

fn determine_step(current: Option<Step>, cert_path: &KeyAttestationCertPath, total_certs: usize) -> Step {
    match current {
        None => {
            if cert_path.provisioning_method() == ProvisioningMethod::RemotelyProvisioned {
                Step::RkpIntermediate
            } else if cert_path.provisioning_method() == ProvisioningMethod::FactoryProvisioned
                // Kotlin: certPath.certificatesWithAnchor.size == 4 (includes root)
                // Rust: total_certs excludes root, so 4-cert chain = 3 non-root certs
                || total_certs == 3
            {
                Step::FactoryIntermediate
            } else if cert_path.certificates_with_anchor.len() == 3 {
                // 3-cert chain = software (root + attestation + target), no intermediate
                Step::Attestation
            } else {
                Step::Attestation
            }
        }
        Some(Step::RkpIntermediate) => Step::RkpServer,
        Some(Step::RkpServer) => Step::Attestation,
        Some(Step::FactoryIntermediate) => Step::Attestation,
        Some(Step::Attestation) => Step::Target,
        // Reject trailing certs after the target (chain extension attack prevention)
        Some(Step::Target) => Step::Target,
    }
}

fn verify_signature(cert: &Cert, issuer_spki_der: &[u8]) -> Result<(), KeyAttestationError> {
    let sig_alg_oid = cert.parsed.signature_algorithm.oid.to_string();
    let sig_bytes = cert.parsed.signature.raw_bytes();

    match sig_alg_oid.as_str() {
        "1.2.840.10045.4.3.2" => ecdsa_verify_sha256(&cert.tbs_der, sig_bytes, issuer_spki_der),
        "1.2.840.10045.4.3.3" => ecdsa_verify_sha384(&cert.tbs_der, sig_bytes, issuer_spki_der),
        "1.2.840.10045.4.3.4" => ecdsa_verify_sha512(&cert.tbs_der, sig_bytes, issuer_spki_der),
        "1.2.840.113549.1.1.11" => rsa_verify_sha256(&cert.tbs_der, sig_bytes, issuer_spki_der),
        "1.2.840.113549.1.1.12" => rsa_verify_sha384(&cert.tbs_der, sig_bytes, issuer_spki_der),
        "1.2.840.113549.1.1.13" => rsa_verify_sha512(&cert.tbs_der, sig_bytes, issuer_spki_der),
        _ => Err(KeyAttestationError::PathValidation {
            message: format!("Unsupported signature algorithm: {sig_alg_oid}"),
            reason: KeyAttestationReason::Unspecified,
        }),
    }
}

/// Parse SPKI and extract raw key bytes for ECDSA verification.
fn get_ecdsa_key_bytes(issuer_spki_der: &[u8]) -> Result<Vec<u8>, KeyAttestationError> {
    let spki = x509_cert::spki::SubjectPublicKeyInfo::<der::Any, der::asn1::BitString>::from_der(issuer_spki_der)
        .map_err(|e| KeyAttestationError::PathValidation {
            message: format!("Failed to parse issuer SPKI: {e}"),
            reason: KeyAttestationReason::InvalidSignature,
        })?;
    Ok(spki.subject_public_key.raw_bytes().to_vec())
}

/// ECDSA verification with SHA-256. Curve detected from key size.
fn ecdsa_verify_sha256(tbs_der: &[u8], sig_bytes: &[u8], issuer_spki_der: &[u8]) -> Result<(), KeyAttestationError> {
    use digest::Digest;
    let mut hasher = sha2::Sha256::new();
    Digest::update(&mut hasher, tbs_der);
    let hash = hasher.finalize();
    let key_bytes = get_ecdsa_key_bytes(issuer_spki_der)?;
    ecdsa_verify_impl(&hash, sig_bytes, &key_bytes)
}

/// ECDSA verification with SHA-384. Curve detected from key size.
fn ecdsa_verify_sha384(tbs_der: &[u8], sig_bytes: &[u8], issuer_spki_der: &[u8]) -> Result<(), KeyAttestationError> {
    use digest::Digest;
    let mut hasher = sha2::Sha384::new();
    Digest::update(&mut hasher, tbs_der);
    let hash = hasher.finalize();
    let key_bytes = get_ecdsa_key_bytes(issuer_spki_der)?;
    ecdsa_verify_impl(&hash, sig_bytes, &key_bytes)
}

/// ECDSA verification with SHA-512. Curve detected from key size.
fn ecdsa_verify_sha512(tbs_der: &[u8], sig_bytes: &[u8], issuer_spki_der: &[u8]) -> Result<(), KeyAttestationError> {
    use digest::Digest;
    let mut hasher = sha2::Sha512::new();
    Digest::update(&mut hasher, tbs_der);
    let hash = hasher.finalize();
    let key_bytes = get_ecdsa_key_bytes(issuer_spki_der)?;
    ecdsa_verify_impl(&hash, sig_bytes, &key_bytes)
}

/// Unified ECDSA verification: detects curve from uncompressed key point size
/// and verifies the signature against the hash.
fn ecdsa_verify_impl(hash: &[u8], sig_bytes: &[u8], key_bytes: &[u8]) -> Result<(), KeyAttestationError> {
    use ecdsa::signature::Verifier;

    match key_bytes.len() {
        65 => {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes).map_err(|e| {
                KeyAttestationError::PathValidation {
                    message: format!("Failed to create P-256 verifying key: {e}"),
                    reason: KeyAttestationReason::InvalidSignature,
                }
            })?;
            let sig = p256::ecdsa::Signature::from_der(sig_bytes).map_err(|e| {
                KeyAttestationError::PathValidation {
                    message: format!("Failed to parse ECDSA signature: {e}"),
                    reason: KeyAttestationReason::InvalidSignature,
                }
            })?;
            vk.verify(hash, &sig).map_err(|e| {
                KeyAttestationError::PathValidation {
                    message: format!("Signature verification failed: {e}"),
                    reason: KeyAttestationReason::InvalidSignature,
                }
            })
        }
        97 => {
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes).map_err(|e| {
                KeyAttestationError::PathValidation {
                    message: format!("Failed to create P-384 verifying key: {e}"),
                    reason: KeyAttestationReason::InvalidSignature,
                }
            })?;
            let sig = p384::ecdsa::Signature::from_der(sig_bytes).map_err(|e| {
                KeyAttestationError::PathValidation {
                    message: format!("Failed to parse ECDSA signature: {e}"),
                    reason: KeyAttestationReason::InvalidSignature,
                }
            })?;
            vk.verify(hash, &sig).map_err(|e| {
                KeyAttestationError::PathValidation {
                    message: format!("Signature verification failed: {e}"),
                    reason: KeyAttestationReason::InvalidSignature,
                }
            })
        }
        133 => {
            let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes).map_err(|e| {
                KeyAttestationError::PathValidation {
                    message: format!("Failed to create P-521 verifying key: {e}"),
                    reason: KeyAttestationReason::InvalidSignature,
                }
            })?;
            let sig = p521::ecdsa::Signature::from_der(sig_bytes).map_err(|e| {
                KeyAttestationError::PathValidation {
                    message: format!("Failed to parse ECDSA signature: {e}"),
                    reason: KeyAttestationReason::InvalidSignature,
                }
            })?;
            vk.verify(hash, &sig).map_err(|e| {
                KeyAttestationError::PathValidation {
                    message: format!("Signature verification failed: {e}"),
                    reason: KeyAttestationReason::InvalidSignature,
                }
            })
        }
        _ => Err(KeyAttestationError::PathValidation {
            message: format!("Unsupported EC key size: {} bytes", key_bytes.len()),
            reason: KeyAttestationReason::InvalidSignature,
        }),
    }
}

fn rsa_verify_sha256(tbs_der: &[u8], sig_bytes: &[u8], issuer_spki_der: &[u8]) -> Result<(), KeyAttestationError> {
    use digest::Digest;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;

    let mut hasher = sha2::Sha256::new();
    Digest::update(&mut hasher, tbs_der);
    let hash = hasher.finalize();

    let rsa_pk = RsaPublicKey::from_public_key_der(issuer_spki_der).map_err(|e| {
        KeyAttestationError::PathValidation {
            message: format!("Failed to parse RSA public key: {e}"),
            reason: KeyAttestationReason::InvalidSignature,
        }
    })?;

    let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes).map_err(|e| {
        KeyAttestationError::PathValidation {
            message: format!("Failed to parse RSA signature: {e}"),
            reason: KeyAttestationReason::InvalidSignature,
        }
    })?;

    let vk = VerifyingKey::<sha2::Sha256>::new(rsa_pk);
    vk.verify(&hash, &sig).map_err(|e| {
        KeyAttestationError::PathValidation {
            message: format!("RSA signature verification failed: {e}"),
            reason: KeyAttestationReason::InvalidSignature,
        }
    })
}

fn rsa_verify_sha384(tbs_der: &[u8], sig_bytes: &[u8], issuer_spki_der: &[u8]) -> Result<(), KeyAttestationError> {
    use digest::Digest;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;

    let mut hasher = sha2::Sha384::new();
    Digest::update(&mut hasher, tbs_der);
    let hash = hasher.finalize();

    let rsa_pk = RsaPublicKey::from_public_key_der(issuer_spki_der).map_err(|e| {
        KeyAttestationError::PathValidation {
            message: format!("Failed to parse RSA public key: {e}"),
            reason: KeyAttestationReason::InvalidSignature,
        }
    })?;

    let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes).map_err(|e| {
        KeyAttestationError::PathValidation {
            message: format!("Failed to parse RSA signature: {e}"),
            reason: KeyAttestationReason::InvalidSignature,
        }
    })?;

    let vk = VerifyingKey::<sha2::Sha384>::new(rsa_pk);
    vk.verify(&hash, &sig).map_err(|e| {
        KeyAttestationError::PathValidation {
            message: format!("RSA signature verification failed: {e}"),
            reason: KeyAttestationReason::InvalidSignature,
        }
    })
}

fn rsa_verify_sha512(tbs_der: &[u8], sig_bytes: &[u8], issuer_spki_der: &[u8]) -> Result<(), KeyAttestationError> {
    use digest::Digest;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;

    let mut hasher = sha2::Sha512::new();
    Digest::update(&mut hasher, tbs_der);
    let hash = hasher.finalize();

    let rsa_pk = RsaPublicKey::from_public_key_der(issuer_spki_der).map_err(|e| {
        KeyAttestationError::PathValidation {
            message: format!("Failed to parse RSA public key: {e}"),
            reason: KeyAttestationReason::InvalidSignature,
        }
    })?;

    let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes).map_err(|e| {
        KeyAttestationError::PathValidation {
            message: format!("Failed to parse RSA signature: {e}"),
            reason: KeyAttestationReason::InvalidSignature,
        }
    })?;

    let vk = VerifyingKey::<sha2::Sha512>::new(rsa_pk);
    vk.verify(&hash, &sig).map_err(|e| {
        KeyAttestationError::PathValidation {
            message: format!("RSA signature verification failed: {e}"),
            reason: KeyAttestationReason::InvalidSignature,
        }
    })
}

fn verify_validity(
    cert: &Cert,
    date: &chrono::DateTime<chrono::Utc>,
    provisioning: ProvisioningMethod,
) -> Result<(), KeyAttestationError> {
    let validity = &cert.parsed.tbs_certificate.validity;
    let not_before = time_to_chrono(&validity.not_before);
    let not_after = time_to_chrono(&validity.not_after);

    if let Some(nb) = not_before {
        if *date < nb {
            return Err(KeyAttestationError::PathValidation {
                message: "Certificate not yet valid".into(),
                reason: KeyAttestationReason::NotYetValid,
            });
        }
    }

    if let Some(na) = not_after {
        if *date > na {
            if provisioning == ProvisioningMethod::FactoryProvisioned {
                return Ok(());
            }
            return Err(KeyAttestationError::PathValidation {
                message: "Certificate has expired".into(),
                reason: KeyAttestationReason::Expired,
            });
        }
    }

    Ok(())
}

fn time_to_chrono(time: &x509_cert::time::Time) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::TimeZone;
    let s = time.to_string();
    // Expected formats: "YYMMDDHHMMSSZ" (UtcTime) or "YYYYMMDDHHMMSSZ" (GeneralTime)
    match s.len() {
        13 => {
            // UtcTime: "YYMMDDHHMMSSZ"
            let y2: i32 = s[..2].parse().ok()?;
            let year = if y2 >= 50 { 1900 + y2 } else { 2000 + y2 };
            let month: u32 = s[2..4].parse().ok()?;
            let day: u32 = s[4..6].parse().ok()?;
            let hour: u32 = s[6..8].parse().ok()?;
            let min: u32 = s[8..10].parse().ok()?;
            let sec: u32 = s[10..12].parse().ok()?;
            chrono::Utc.with_ymd_and_hms(year, month, day, hour, min, sec).single()
        }
        15 => {
            // GeneralTime: "YYYYMMDDHHMMSSZ"
            let year: i32 = s[..4].parse().ok()?;
            let month: u32 = s[4..6].parse().ok()?;
            let day: u32 = s[6..8].parse().ok()?;
            let hour: u32 = s[8..10].parse().ok()?;
            let min: u32 = s[10..12].parse().ok()?;
            let sec: u32 = s[12..14].parse().ok()?;
            chrono::Utc.with_ymd_and_hms(year, month, day, hour, min, sec).single()
        }
        _ => {
            // Unknown format - fail closed
            eprintln!("Warning: unknown time format, length {}, treating as expired", s.len());
            None
        }
    }
}

fn verify_expectations(cert: &Cert, step: Step) -> Result<(), KeyAttestationError> {
    match step {
        Step::Target => {
            if !cert.has_attestation_extension() {
                return Err(KeyAttestationError::PathValidation {
                    message: "Target certificate does not contain an attestation extension".into(),
                    reason: KeyAttestationReason::TargetMissingAttestationExtension,
                });
            }
        }
        _ => {
            if cert.has_attestation_extension() {
                return Err(KeyAttestationError::PathValidation {
                    message: "Non-target cert contains attestation extension".into(),
                    reason: KeyAttestationReason::ChainExtendedWithFakeAttestationExtension,
                });
            }
        }
    }
    Ok(())
}
