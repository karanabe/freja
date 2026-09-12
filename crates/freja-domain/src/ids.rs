use std::{error::Error, fmt, num::NonZeroU64};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAXIMUM_TEXT_IDENTIFIER_BYTES: usize = 128;

macro_rules! uuid_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a new opaque identifier using a random UUID.
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Returns the underlying UUID.
            pub fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

uuid_id!(
    SessionId,
    "An opaque identifier assigned to every accepted connection."
);
uuid_id!(
    TransactionId,
    "An opaque identifier assigned to every HTTP request/response exchange."
);

/// A validation error for a human-readable domain identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    /// A textual identifier contained no bytes.
    Empty {
        /// Human-readable identifier category used in diagnostics.
        kind: &'static str,
    },
    /// A textual identifier exceeded its stable byte limit.
    TooLong {
        /// Human-readable identifier category used in diagnostics.
        kind: &'static str,
        /// Maximum accepted UTF-8 byte length.
        maximum: usize,
    },
    /// A textual identifier contained a character outside its stable alphabet.
    InvalidCharacter {
        /// Human-readable identifier category used in diagnostics.
        kind: &'static str,
        /// Offending character.
        character: char,
    },
    /// Policy generation zero was supplied even though zero is reserved.
    ZeroPolicyGeneration,
    /// Audit sequence zero was supplied even though segments begin at one.
    ZeroAuditSequence,
}

impl fmt::Display for IdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { kind } => write!(formatter, "{kind} must not be empty"),
            Self::TooLong { kind, maximum } => {
                write!(formatter, "{kind} must not exceed {maximum} bytes")
            }
            Self::InvalidCharacter { kind, character } => {
                write!(formatter, "{kind} contains invalid character {character:?}")
            }
            Self::ZeroPolicyGeneration => formatter.write_str("policy generation must be non-zero"),
            Self::ZeroAuditSequence => formatter.write_str("audit sequence must be non-zero"),
        }
    }
}

impl Error for IdError {}

macro_rules! string_id {
    ($name:ident, $kind:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validates and constructs an identifier.
            ///
            /// # Errors
            ///
            /// Returns [`IdError`] when the value is empty, too long, or
            /// contains a character outside the stable identifier alphabet.
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                let value = value.into();
                validate_string_id(&value, $kind)?;
                Ok(Self(value))
            }

            /// Returns the identifier as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

string_id!(
    RuleId,
    "rule ID",
    "A stable identifier for an ACL or inspection rule."
);
string_id!(
    DetectorId,
    "detector ID",
    "A stable identifier for an inspection detector."
);

fn validate_string_id(value: &str, kind: &'static str) -> Result<(), IdError> {
    if value.is_empty() {
        return Err(IdError::Empty { kind });
    }
    if value.len() > MAXIMUM_TEXT_IDENTIFIER_BYTES {
        return Err(IdError::TooLong {
            kind,
            maximum: MAXIMUM_TEXT_IDENTIFIER_BYTES,
        });
    }
    if let Some(character) = value.chars().find(|character| {
        !character.is_ascii_alphanumeric() && !matches!(character, '-' | '_' | '.')
    }) {
        return Err(IdError::InvalidCharacter { kind, character });
    }
    Ok(())
}

/// Monotonically increasing identity of a compiled policy snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct PolicyGeneration(NonZeroU64);

impl PolicyGeneration {
    /// Initial generation used before the first compatible policy reload.
    pub const INITIAL: Self = Self(NonZeroU64::MIN);

    /// Creates a non-zero policy generation.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::ZeroPolicyGeneration`] when `value` is zero.
    pub const fn new(value: u64) -> Result<Self, IdError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(IdError::ZeroPolicyGeneration),
        }
    }

    /// Returns the numeric generation.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl Default for PolicyGeneration {
    fn default() -> Self {
        Self::INITIAL
    }
}

impl TryFrom<u64> for PolicyGeneration {
    type Error = IdError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PolicyGeneration> for u64 {
    fn from(value: PolicyGeneration) -> Self {
        value.get()
    }
}

impl fmt::Display for PolicyGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

/// Monotonic sequence number within one audit stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct AuditSequence(NonZeroU64);

impl AuditSequence {
    /// First record position in a fresh audit segment.
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// Creates a non-zero sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::ZeroAuditSequence`] when `value` is zero.
    pub const fn new(value: u64) -> Result<Self, IdError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(IdError::ZeroAuditSequence),
        }
    }

    /// Returns the numeric sequence.
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next sequence, or `None` after the maximum value.
    pub const fn checked_next(self) -> Option<Self> {
        match self.get().checked_add(1) {
            Some(value) => match NonZeroU64::new(value) {
                Some(value) => Some(Self(value)),
                None => None,
            },
            None => None,
        }
    }
}

impl TryFrom<u64> for AuditSequence {
    type Error = IdError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<AuditSequence> for u64 {
    fn from(value: AuditSequence) -> Self {
        value.get()
    }
}

impl fmt::Display for AuditSequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::{AuditSequence, PolicyGeneration};

    #[test]
    fn audit_sequence_is_non_zero_and_checked() {
        assert!(AuditSequence::new(0).is_err());
        assert!(serde_json::from_str::<AuditSequence>("0").is_err());
        assert_eq!(AuditSequence::FIRST.get(), 1);
        assert_eq!(
            AuditSequence::FIRST.checked_next().map(AuditSequence::get),
            Some(2)
        );
        assert_eq!(AuditSequence::new(u64::MAX).unwrap().checked_next(), None);
    }

    #[test]
    fn policy_generation_deserialization_preserves_non_zero_invariant() {
        assert!(PolicyGeneration::new(0).is_err());
        assert!(serde_json::from_str::<PolicyGeneration>("0").is_err());
        assert_eq!(PolicyGeneration::default(), PolicyGeneration::INITIAL);
    }
}
