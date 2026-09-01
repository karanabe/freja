use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    if value.len() > 128 {
        return Err(IdError::TooLong { kind, maximum: 128 });
    }
    if let Some(character) = value.chars().find(|character| {
        !character.is_ascii_alphanumeric() && !matches!(character, '-' | '_' | '.')
    }) {
        return Err(IdError::InvalidCharacter { kind, character });
    }
    Ok(())
}

/// Monotonically increasing identity of a compiled policy snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyGeneration(u64);

impl PolicyGeneration {
    /// Creates a non-zero policy generation.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::ZeroPolicyGeneration`] when `value` is zero.
    pub fn new(value: u64) -> Result<Self, IdError> {
        if value == 0 {
            return Err(IdError::ZeroPolicyGeneration);
        }
        Ok(Self(value))
    }

    /// Returns the numeric generation.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl Default for PolicyGeneration {
    fn default() -> Self {
        Self(1)
    }
}

impl fmt::Display for PolicyGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Monotonic sequence number within one audit stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditSequence(u64);

impl AuditSequence {
    /// Creates a sequence number.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric sequence.
    pub const fn get(self) -> u64 {
        self.0
    }
}
