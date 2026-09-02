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
    /// Preserve forwarding and return an explicit error when the channel is unavailable.
    FailOpen,
    /// Apply backpressure until the critical event is accepted; this is the default.
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
    /// Returns the raw SHA-256 digest bytes.
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
    /// A listener admitted a new transport connection.
    ConnectionAccepted {
        /// Peer socket address after transport acceptance.
        client: String,
        /// Local listener socket address.
        listener: String,
    },
    /// DNS produced candidate addresses that each require destination-policy evaluation.
    TargetResolved {
        /// Client-requested hostname or address.
        requested_host: String,
        /// Complete set of candidate addresses observed for this resolution.
        resolved_addresses: Vec<IpAddr>,
    },
    /// Ordered access-control policy produced an explainable decision.
    AclEvaluated {
        /// Action and trace for the evaluated lifecycle stage.
        decision: Decision,
    },
    /// Normalized HTTP request metadata was observed before forwarding.
    HttpRequestObserved {
        /// Normalized HTTP method.
        method: String,
        /// Request target after secret redaction.
        target: String,
        /// Header values after credential-bearing fields are redacted.
        headers: BTreeMap<String, Vec<String>>,
    },
    /// HTTP response metadata was observed before downstream commitment.
    HttpResponseObserved {
        /// Upstream HTTP status code.
        status: u16,
        /// Header values after credential-bearing fields are redacted.
        headers: BTreeMap<String, Vec<String>>,
    },
    /// A proxy authentication attempt completed without recording credentials.
    ProxyAuthentication {
        /// Secret-free result such as success or failure.
        outcome: String,
    },
    /// An Ed25519 checkpoint was inserted into the audit stream.
    SignedCheckpoint {
        /// Publicly verifiable signature over the preceding chain position.
        checkpoint: SignedCheckpoint,
    },
    /// An inspection detector produced an observation without directly enforcing it.
    FindingDetected {
        /// Detector metadata and hashed evidence.
        finding: Finding,
    },
    /// Inspection policy converted a finding into an explainable decision.
    InspectionEvaluated {
        /// Action and trace derived from the finding.
        decision: Decision,
    },
    /// Owned facts were retained for deterministic offline policy replay.
    ReplayFactsObserved {
        /// Sanitized lifecycle facts used during replay.
        facts: ReplayFacts,
    },
    /// Explicitly enabled capture retained a bounded payload prefix.
    PayloadPrefixCaptured {
        /// Direction from which bytes were captured.
        direction: Direction,
        /// Protocol semantics of the original flow.
        protocol: Protocol,
        /// Captured bytes encoded as hexadecimal; may contain sensitive payload data.
        bytes_hex: String,
    },
    /// An in-process typed hook completed.
    HookExecuted {
        /// Request, response, or TCP hook stage.
        stage: String,
        /// Secret-free completion, failure, or timeout result.
        outcome: String,
    },
    /// An operator supplied an interactive interception decision.
    ManualModification {
        /// Stable action category without raw replacement content.
        action: String,
    },
    /// An operator started a fresh HTTP/1.1 flow from a retained repeat workspace.
    HttpRepeatStarted {
        /// Session that supplied the original bounded request snapshot.
        source_session_id: SessionId,
        /// HTTP exchange that supplied the original bounded request snapshot.
        source_transaction_id: TransactionId,
    },
    /// A per-host leaf certificate was selected for TLS interception.
    TlsCertificateGenerated {
        /// Intercepted hostname; configuration must explicitly allow it.
        hostname: String,
        /// Whether the certificate came from the bounded in-memory cache.
        cache_hit: bool,
    },
    /// Downstream and upstream TLS handshakes completed for an intercepted host.
    TlsInterceptionEstablished {
        /// Intercepted hostname.
        hostname: String,
        /// Negotiated application protocol, if either side selected one.
        alpn: Option<String>,
    },
    /// Enforcement executed a previously recorded policy decision.
    ActionExecuted {
        /// Executed action and its original trace.
        decision: Decision,
    },
    /// A CONNECT tunnel ended after successful HTTP commitment.
    TunnelClosed {
        /// Bytes relayed from client to upstream.
        client_to_upstream_bytes: u64,
        /// Bytes relayed from upstream to client.
        upstream_to_client_bytes: u64,
        /// Secret-free termination category.
        outcome: String,
    },
    /// A non-CONNECT flow reached its terminal lifecycle event.
    FlowClosed {
        /// Bytes relayed from client to upstream.
        client_to_upstream_bytes: u64,
        /// Bytes relayed from upstream to client.
        upstream_to_client_bytes: u64,
        /// Secret-free termination category.
        outcome: String,
    },
}

/// Correlation and policy identity attached to one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditContext {
    /// Event timestamp sampled or restored by the producer.
    pub occurred_at: UnixMillis,
    /// Connection correlation identity.
    pub session_id: SessionId,
    /// HTTP exchange identity when the event belongs to one transaction.
    pub transaction_id: Option<TransactionId>,
    /// Immutable policy snapshot active when the event occurred.
    pub policy_generation: PolicyGeneration,
}

/// Versioned JSONL record with a hash link to its predecessor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Wire schema version; newly written records use `2`.
    pub schema_version: u16,
    /// Monotonic position assigned by one sink, beginning at one.
    pub sequence: AuditSequence,
    /// Milliseconds since the Unix epoch.
    pub occurred_at: UnixMillis,
    /// Connection correlation identity.
    pub session_id: SessionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// HTTP exchange identity when applicable.
    pub transaction_id: Option<TransactionId>,
    /// Policy snapshot associated with the event.
    pub policy_generation: PolicyGeneration,
    /// Redacted typed event payload.
    pub event: AuditEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Hash of the preceding record, or `None` for the segment's first record.
    pub previous_hash: Option<RecordHash>,
    /// SHA-256 over the canonical record fields excluding this field.
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
