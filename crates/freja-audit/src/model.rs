use std::{
    collections::BTreeMap,
    fmt,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use freja_domain::{
    AuditSequence, Decision, Direction, Finding, PolicyGeneration, Protocol, ReplayFacts,
    SessionId, TransactionId,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};

use crate::SignedCheckpoint;

/// Behavior the data plane applies when an audit event cannot be queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditFailurePolicy {
    FailOpen,
    #[default]
    FailClosed,
}

/// Milliseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixMillis(u64);

impl UnixMillis {
    /// Samples the system clock. Times before the Unix epoch are clamped to zero.
    pub fn now() -> Self {
        let milliseconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        let Ok(milliseconds) = u64::try_from(milliseconds) else {
            return Self(u64::MAX);
        };
        Self(milliseconds)
    }

    /// Creates a deterministic timestamp, primarily for replay and tests.
    pub const fn from_millis(value: u64) -> Self {
        Self(value)
    }

    /// Returns milliseconds since the Unix epoch.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Stable SHA-256 digest serialized as lower-case hexadecimal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordHash(pub(super) [u8; 32]);

impl RecordHash {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for RecordHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl Serialize for RecordHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for RecordHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let decoded = hex::decode(&value).map_err(D::Error::custom)?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| D::Error::custom("record hash must contain 32 bytes"))?;
        Ok(Self(bytes))
    }
}

/// Versioned audit event payloads. Full raw bodies are deliberately absent;
/// explicitly enabled capture can add only bounded directional prefixes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_type", content = "event", rename_all = "kebab-case")]
pub enum AuditEvent {
    ConnectionAccepted {
        client: String,
        listener: String,
    },
    TargetResolved {
        requested_host: String,
        resolved_addresses: Vec<IpAddr>,
    },
    AclEvaluated {
        decision: Decision,
    },
    HttpRequestObserved {
        method: String,
        target: String,
        headers: BTreeMap<String, Vec<String>>,
    },
    HttpResponseObserved {
        status: u16,
        headers: BTreeMap<String, Vec<String>>,
    },
    ProxyAuthentication {
        outcome: String,
    },
    SignedCheckpoint {
        checkpoint: SignedCheckpoint,
    },
    FindingDetected {
        finding: Finding,
    },
    InspectionEvaluated {
        decision: Decision,
    },
    ReplayFactsObserved {
        facts: ReplayFacts,
    },
    PayloadPrefixCaptured {
        direction: Direction,
        protocol: Protocol,
        bytes_hex: String,
    },
    HookExecuted {
        stage: String,
        outcome: String,
    },
    ManualModification {
        action: String,
    },
    TlsCertificateGenerated {
        hostname: String,
        cache_hit: bool,
    },
    TlsInterceptionEstablished {
        hostname: String,
        alpn: Option<String>,
    },
    ActionExecuted {
        decision: Decision,
    },
    TunnelClosed {
        client_to_upstream_bytes: u64,
        upstream_to_client_bytes: u64,
        outcome: String,
    },
    FlowClosed {
        client_to_upstream_bytes: u64,
        upstream_to_client_bytes: u64,
        outcome: String,
    },
}

/// Correlation and policy identity attached to one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditContext {
    pub occurred_at: UnixMillis,
    pub session_id: SessionId,
    pub transaction_id: Option<TransactionId>,
    pub policy_generation: PolicyGeneration,
}

/// Schema version 1 JSONL record with a hash link to its predecessor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub schema_version: u16,
    pub sequence: AuditSequence,
    pub occurred_at: UnixMillis,
    pub session_id: SessionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<TransactionId>,
    pub policy_generation: PolicyGeneration,
    pub event: AuditEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<RecordHash>,
    pub record_hash: RecordHash,
}

impl AuditRecord {
    /// Recomputes and verifies this record's canonical SHA-256 hash.
    pub fn verifies_hash(&self) -> bool {
        let unsigned = UnsignedAuditRecord {
            schema_version: self.schema_version,
            sequence: self.sequence,
            occurred_at: self.occurred_at,
            session_id: self.session_id,
            transaction_id: self.transaction_id,
            policy_generation: self.policy_generation,
            event: &self.event,
            previous_hash: self.previous_hash,
        };
        serde_json::to_vec(&unsigned)
            .is_ok_and(|canonical| RecordHash(Sha256::digest(canonical).into()) == self.record_hash)
    }
}

#[derive(Serialize)]
pub(super) struct UnsignedAuditRecord<'a> {
    pub(super) schema_version: u16,
    pub(super) sequence: AuditSequence,
    pub(super) occurred_at: UnixMillis,
    pub(super) session_id: SessionId,
    pub(super) transaction_id: Option<TransactionId>,
    pub(super) policy_generation: PolicyGeneration,
    pub(super) event: &'a AuditEvent,
    pub(super) previous_hash: Option<RecordHash>,
}
