use std::{
    error::Error,
    fmt, fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use freja_domain::AuditSequence;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::RecordHash;

/// Ed25519 signature over one audit record hash and its segment sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    covers_sequence: AuditSequence,
    record_hash: RecordHash,
    #[serde(
        rename = "public_key_hex",
        serialize_with = "serialize_hex",
        deserialize_with = "deserialize_hex"
    )]
    public_key: [u8; 32],
    #[serde(
        rename = "signature_hex",
        serialize_with = "serialize_hex",
        deserialize_with = "deserialize_hex"
    )]
    signature: [u8; 64],
}

impl SignedCheckpoint {
    /// Returns the last ordinary record covered by the signature.
    pub const fn covers_sequence(&self) -> AuditSequence {
        self.covers_sequence
    }

    /// Returns the covered record hash, which commits to the preceding chain.
    pub const fn record_hash(&self) -> RecordHash {
        self.record_hash
    }

    /// Returns the fixed-size Ed25519 public verification key.
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns the fixed-size Ed25519 signature.
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Verifies this checkpoint independently of local secret material.
    pub fn verifies(&self) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(&self.public_key) else {
            return false;
        };
        verifying_key
            .verify_strict(
                &checkpoint_message(self.covers_sequence, self.record_hash),
                &Signature::from_bytes(&self.signature),
            )
            .is_ok()
    }
}

/// Secret-bearing Ed25519 checkpoint signer with a redacted debug view.
#[derive(Clone)]
pub struct CheckpointSigner(SigningKey);

impl fmt::Debug for CheckpointSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CheckpointSigner([REDACTED])")
    }
}

impl CheckpointSigner {
    /// Creates a signer from an Ed25519 32-byte secret seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    /// Returns the public verification key as lower-case hexadecimal.
    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.0.verifying_key().to_bytes())
    }

    /// Loads a hexadecimal seed from a permission-protected file.
    ///
    /// # Errors
    ///
    /// Returns [`CheckpointKeyError`] for file, permission, encoding, or size
    /// failures.
    pub fn load_hex_seed(path: impl AsRef<Path>) -> Result<Self, CheckpointKeyError> {
        let path = path.as_ref();
        validate_checkpoint_key_permissions(path)?;
        let input = fs::read_to_string(path).map_err(|source| CheckpointKeyError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let decoded = hex::decode(input.trim()).map_err(CheckpointKeyError::Hex)?;
        let seed: [u8; 32] = decoded
            .try_into()
            .map_err(|_| CheckpointKeyError::InvalidLength)?;
        Ok(Self::from_seed(seed))
    }

    /// Signs one already-written chain position.
    pub fn sign_checkpoint(
        &self,
        sequence: AuditSequence,
        record_hash: RecordHash,
    ) -> SignedCheckpoint {
        let signature = self.0.sign(&checkpoint_message(sequence, record_hash));
        SignedCheckpoint {
            covers_sequence: sequence,
            record_hash,
            public_key: self.0.verifying_key().to_bytes(),
            signature: signature.to_bytes(),
        }
    }
}

/// Optional periodic checkpoint generation policy.
#[derive(Debug, Clone)]
pub struct CheckpointSchedule {
    pub(super) signer: CheckpointSigner,
    pub(super) interval: NonZeroU64,
}

impl CheckpointSchedule {
    /// Creates a non-zero checkpoint interval measured in ordinary events.
    ///
    /// # Errors
    ///
    /// Returns [`CheckpointKeyError::ZeroInterval`] for zero.
    pub fn new(signer: CheckpointSigner, interval: u64) -> Result<Self, CheckpointKeyError> {
        let interval = NonZeroU64::new(interval).ok_or(CheckpointKeyError::ZeroInterval)?;
        Ok(Self { signer, interval })
    }
}

/// Protected checkpoint signing-key setup failure.
#[derive(Debug)]
pub enum CheckpointKeyError {
    /// The signing-seed file or its metadata could not be read.
    Read {
        /// Requested key path.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// A Unix key file was accessible to group or other users.
    InsecurePermissions {
        /// Insecure key path.
        path: PathBuf,
        /// Observed Unix permission bits.
        mode: u32,
    },
    /// The signing seed was not valid hexadecimal.
    Hex(hex::FromHexError),
    /// The decoded seed was not exactly 32 bytes.
    InvalidLength,
    /// A checkpoint schedule used an interval of zero.
    ZeroInterval,
}

impl fmt::Display for CheckpointKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, .. } => {
                write!(
                    formatter,
                    "failed to read checkpoint key {}",
                    path.display()
                )
            }
            Self::InsecurePermissions { path, mode } => write!(
                formatter,
                "checkpoint key {} has insecure permissions {mode:o}",
                path.display()
            ),
            Self::Hex(_) => formatter.write_str("checkpoint key is not hexadecimal"),
            Self::InvalidLength => {
                formatter.write_str("checkpoint key must contain exactly 32 bytes")
            }
            Self::ZeroInterval => formatter.write_str("checkpoint interval must be non-zero"),
        }
    }
}

impl Error for CheckpointKeyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Hex(source) => Some(source),
            Self::InsecurePermissions { .. } | Self::InvalidLength | Self::ZeroInterval => None,
        }
    }
}

pub(super) fn checkpoint_message(sequence: AuditSequence, record_hash: RecordHash) -> Vec<u8> {
    let mut message = b"freja-audit-checkpoint-v1\0".to_vec();
    message.extend_from_slice(&sequence.get().to_be_bytes());
    message.extend_from_slice(record_hash.as_bytes());
    message
}

fn serialize_hex<const N: usize, S>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

fn deserialize_hex<'de, const N: usize, D>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let decoded = hex::decode(value).map_err(D::Error::custom)?;
    decoded
        .try_into()
        .map_err(|_| D::Error::custom(format_args!("expected {N} bytes")))
}

#[cfg(unix)]
fn validate_checkpoint_key_permissions(path: &Path) -> Result<(), CheckpointKeyError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|source| CheckpointKeyError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(CheckpointKeyError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_checkpoint_key_permissions(_path: &Path) -> Result<(), CheckpointKeyError> {
    Ok(())
}
