use std::fmt;

/// Reasons specific to key attestation chain validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAttestationReason {
    ChainExtendedForKey,
    TargetMissingAttestationExtension,
    ChainExtendedWithFakeAttestationExtension,
    ConstraintViolation,
    UnknownTagNumber,
    NoTrustAnchor,
    NameChaining,
    InvalidSignature,
    NotYetValid,
    Expired,
    Revoked,
    Unspecified,
}

impl fmt::Display for KeyAttestationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainExtendedForKey => {
                write!(f, "Certificate chain contains a certificate after the target")
            }
            Self::TargetMissingAttestationExtension => {
                write!(f, "Target certificate missing attestation extension")
            }
            Self::ChainExtendedWithFakeAttestationExtension => {
                write!(f, "Non-target certificate contains attestation extension")
            }
            Self::ConstraintViolation => write!(f, "Constraint violation"),
            Self::UnknownTagNumber => write!(f, "Unknown tag number in AuthorizationList"),
            Self::NoTrustAnchor => write!(f, "No matching trust anchor found"),
            Self::NameChaining => write!(f, "Subject/Issuer name chaining check failed"),
            Self::InvalidSignature => write!(f, "Signature check failed"),
            Self::NotYetValid => write!(f, "Certificate not yet valid"),
            Self::Expired => write!(f, "Certificate has expired"),
            Self::Revoked => write!(f, "Certificate has been revoked"),
            Self::Unspecified => write!(f, "Unspecified validation error"),
        }
    }
}

/// Errors that can occur during key attestation verification.
#[derive(Debug)]
pub enum KeyAttestationError {
    /// Certificate chain parsing failure (e.g., too few certificates, invalid DER).
    ChainParsing(String),
    /// Certificate path validation failure (signature, name chaining, expiry, etc.).
    PathValidation {
        message: String,
        reason: KeyAttestationReason,
    },
    /// Extension parsing failure (malformed attestation extension).
    ExtensionParsing {
        message: String,
        reason: Option<KeyAttestationReason>,
    },
    /// Challenge mismatch.
    ChallengeMismatch,
    /// Constraint violation.
    ConstraintViolation {
        label: String,
        message: String,
    },
    /// Software attestation unsupported.
    SoftwareAttestationUnsupported,
}

impl fmt::Display for KeyAttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainParsing(msg) => write!(f, "Chain parsing error: {msg}"),
            Self::PathValidation { message, reason } => {
                write!(f, "Path validation error: {message} ({reason})")
            }
            Self::ExtensionParsing { message, .. } => {
                write!(f, "Extension parsing error: {message}")
            }
            Self::ChallengeMismatch => write!(f, "Challenge mismatch"),
            Self::ConstraintViolation { label, message } => {
                write!(f, "Constraint violation [{label}]: {message}")
            }
            Self::SoftwareAttestationUnsupported => {
                write!(f, "Software attestation unsupported")
            }
        }
    }
}

impl std::error::Error for KeyAttestationError {}
