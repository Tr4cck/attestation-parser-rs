use crate::extension::{KeyDescription, Origin, SecurityLevel};

/// Result of applying a constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintResult {
    Satisfied,
    Violated(String),
}

/// A constraint that can be checked against a KeyDescription.
pub trait Constraint: Send + Sync {
    fn label(&self) -> &str;
    fn check(&self, desc: &KeyDescription) -> ConstraintResult;
}

// --- Attribute Constraints ---

/// Type alias for attribute mappers used in constraint checks.
type AttrMapper<T> = Box<dyn Fn(&KeyDescription) -> Option<T> + Send + Sync>;

pub struct AttributeConstraint<T> {
    pub label: String,
    pub expected: Option<T>,
    mapper: AttrMapper<T>,
}

impl<T: PartialEq + std::fmt::Debug + 'static> AttributeConstraint<T> {
    pub fn strict(label: &str, expected: T, mapper: impl Fn(&KeyDescription) -> Option<T> + Send + Sync + 'static) -> Self {
        Self {
            label: label.into(),
            expected: Some(expected),
            mapper: Box::new(mapper),
        }
    }

    pub fn not_null(label: &str, mapper: impl Fn(&KeyDescription) -> Option<T> + Send + Sync + 'static) -> Self {
        Self {
            label: label.into(),
            expected: None,
            mapper: Box::new(mapper),
        }
    }
}

impl<T: PartialEq + std::fmt::Debug + Send + Sync + 'static> Constraint for AttributeConstraint<T> {
    fn label(&self) -> &str {
        &self.label
    }

    fn check(&self, desc: &KeyDescription) -> ConstraintResult {
        let value = (self.mapper)(desc);
        match &self.expected {
            Some(expected) => {
                if value.as_ref() == Some(expected) {
                    ConstraintResult::Satisfied
                } else {
                    ConstraintResult::Violated(format!(
                        "{} violates constraint: value={:?}, expected={:?}",
                        self.label, value, expected
                    ))
                }
            }
            None => {
                if value.is_some() {
                    ConstraintResult::Satisfied
                } else {
                    ConstraintResult::Violated(format!("{} violates constraint: value is null", self.label))
                }
            }
        }
    }
}

// --- Security Level Constraints ---

#[derive(Debug, Clone)]
pub enum SecurityLevelConstraint {
    Strict(SecurityLevel),
    NotSoftware,
    Consistent,
}

impl SecurityLevelConstraint {
    fn get_failure_message(&self, desc: &KeyDescription) -> String {
        format!(
            "Security level violates constraint: \
             keyMintSecurityLevel={:?}, attestationSecurityLevel={:?}, config={:?}",
            desc.key_mint_security_level, desc.attestation_security_level, self
        )
    }
}

impl Constraint for SecurityLevelConstraint {
    fn label(&self) -> &str {
        "Security level"
    }

    fn check(&self, desc: &KeyDescription) -> ConstraintResult {
        let satisfied = match self {
            Self::Strict(expected) => {
                desc.key_mint_security_level == *expected
                    && desc.attestation_security_level == *expected
            }
            Self::NotSoftware => {
                desc.key_mint_security_level == desc.attestation_security_level
                    && desc.attestation_security_level != SecurityLevel::Software
            }
            Self::Consistent => {
                desc.attestation_security_level == desc.key_mint_security_level
            }
        };

        if satisfied {
            ConstraintResult::Satisfied
        } else {
            ConstraintResult::Violated(self.get_failure_message(desc))
        }
    }
}

// --- Tag Order Constraint ---

pub enum TagOrderConstraint {
    Strict,
}

impl Constraint for TagOrderConstraint {
    fn label(&self) -> &str {
        "Tag order"
    }

    fn check(&self, desc: &KeyDescription) -> ConstraintResult {
        if desc.software_enforced.are_tags_ordered && desc.hardware_enforced.are_tags_ordered {
            ConstraintResult::Satisfied
        } else {
            ConstraintResult::Violated(
                "Authorization list tags must be in ascending order".into(),
            )
        }
    }
}

// --- Ignored Constraint ---

pub struct IgnoredConstraint;

impl Constraint for IgnoredConstraint {
    fn label(&self) -> &str {
        "Ignored"
    }

    fn check(&self, _desc: &KeyDescription) -> ConstraintResult {
        ConstraintResult::Satisfied
    }
}

// --- Constraint Config ---

pub struct ConstraintConfig {
    key_origin: Box<dyn Constraint>,
    security_level: Box<dyn Constraint>,
    root_of_trust: Box<dyn Constraint>,
    additional_constraints: Vec<Box<dyn Constraint>>,
}

impl Default for ConstraintConfig {
    fn default() -> Self {
        Self {
            key_origin: Box::new(AttributeConstraint::strict(
                "Origin",
                Origin::Generated,
                |d| d.hardware_enforced.origin,
            )),
            security_level: Box::new(SecurityLevelConstraint::NotSoftware),
            root_of_trust: Box::new(AttributeConstraint::<()>::not_null(
                "Root of trust",
                |d| {
                    d.hardware_enforced.root_of_trust.as_ref().map(|_| ())
                },
            )),
            additional_constraints: vec![],
        }
    }
}

impl ConstraintConfig {
    pub fn builder() -> ConstraintConfigBuilder {
        ConstraintConfigBuilder::new()
    }

    pub fn get_constraints(&self) -> Vec<&dyn Constraint> {
        let mut v: Vec<&dyn Constraint> = vec![
            self.key_origin.as_ref(),
            self.security_level.as_ref(),
            self.root_of_trust.as_ref(),
        ];
        for c in &self.additional_constraints {
            v.push(c.as_ref());
        }
        v
    }
}

pub struct ConstraintConfigBuilder {
    key_origin: Option<Box<dyn Constraint>>,
    security_level: Option<Box<dyn Constraint>>,
    root_of_trust: Option<Box<dyn Constraint>>,
    additional_constraints: Vec<Box<dyn Constraint>>,
}

impl ConstraintConfigBuilder {
    pub fn new() -> Self {
        Self {
            key_origin: None,
            security_level: None,
            root_of_trust: None,
            additional_constraints: vec![],
        }
    }

    pub fn key_origin(mut self, c: impl Constraint + 'static) -> Self {
        self.key_origin = Some(Box::new(c));
        self
    }

    pub fn security_level(mut self, c: impl Constraint + 'static) -> Self {
        self.security_level = Some(Box::new(c));
        self
    }

    pub fn root_of_trust(mut self, c: impl Constraint + 'static) -> Self {
        self.root_of_trust = Some(Box::new(c));
        self
    }

    pub fn additional_constraint(mut self, c: impl Constraint + 'static) -> Self {
        self.additional_constraints.push(Box::new(c));
        self
    }

    pub fn build(self) -> ConstraintConfig {
        let defaults = ConstraintConfig::default();
        ConstraintConfig {
            key_origin: self.key_origin.unwrap_or(defaults.key_origin),
            security_level: self.security_level.unwrap_or(defaults.security_level),
            root_of_trust: self.root_of_trust.unwrap_or(defaults.root_of_trust),
            additional_constraints: self.additional_constraints,
        }
    }
}

impl Default for ConstraintConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}
