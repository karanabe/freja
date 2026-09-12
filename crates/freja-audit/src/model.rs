use std::{
    collections::BTreeMap,
    fmt,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use freja_domain::{
    AuditSequence, Decision, Direction, Finding, HttpStatusCode, PolicyGeneration, Protocol,
    ReplayFacts, SessionId, TransactionId,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};

use crate::SignedCheckpoint;

/// Numeric audit JSON schema version retained on every record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditSchemaVersion(u16);

impl AuditSchemaVersion {
    /// Original replay schema without HTTP repeat events.
    pub const V1: Self = Self(1);
    /// Current schema with bounded HTTP repeat audit events.
    pub const V2: Self = Self(2);
    /// Schema emitted by new audit sinks.
    pub const CURRENT: Self = Self::V2;

    /// Preserves a version read from the wire, including a future unsupported value.
    pub const fn from_wire(value: u16) -> Self {
        Self(value)
    }

    /// Returns the numeric wire representation.
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Reports whether this version is supported by the replay engine.
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::V1 | Self::V2)
    }
}

impl From<u16> for AuditSchemaVersion {
    fn from(value: u16) -> Self {
        Self::from_wire(value)
    }
}

impl From<AuditSchemaVersion> for u16 {
    fn from(value: AuditSchemaVersion) -> Self {
        value.get()
    }
}

impl fmt::Display for AuditSchemaVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Credential-free result of proxy authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticationOutcome {
    /// The supplied credentials matched the configured digest.
    Accepted,
    /// Credentials were absent or did not match.
    Rejected,
}

/// Typed automatic-hook stage recorded by the audit stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditHookStage {
    /// HTTP request head hook.
    HttpRequestHead,
    /// HTTP request body hook.
    HttpRequestBody,
    /// HTTP response head hook.
    HttpResponseHead,
    /// HTTP response body hook.
    HttpResponseBody,
    /// Client-to-upstream TCP chunk hook.
    TcpClientChunk,
    /// Upstream-to-client TCP chunk hook.
    TcpUpstreamChunk,
}

/// Secret-free completion state for an automatic hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookOutcome {
    /// The hook returned a mutation plan within its budget.
    Completed,
    /// The hook failed or exceeded its budget.
    Failed,
}

/// Operator action category recorded without edited content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManualModificationAction {
    /// Forward the request unchanged.
    Continue,
    /// Reject the request.
    Reject,
    /// Apply a header-only edit.
    EditHeaders,
    /// Replace the request body.
    ReplaceBody,
    /// Apply an atomic header-and-body edit.
    ModifyRequest,
    /// Abandon a draft modification and forward the original request.
    CancelModification,
    /// Interactive interception failed before returning a decision.
    Failed,
}

/// Stable terminal category for a tunnel or non-CONNECT flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FlowOutcome {
    /// Relay or HTTP processing completed normally.
    Completed,
    /// The relay reached its idle deadline.
    IdleTimeout,
    /// Process shutdown ended the flow.
    Shutdown,
    /// Streaming inspection stopped the relay.
    InspectionBlocked,
    /// Destination or HTTP policy denied the flow.
    PolicyDenied,
    /// A second detour would have formed a loop.
    DetourLoop,
    /// DNS lookup failed or returned no candidates.
    DnsFailure,
    /// DNS lookup exceeded its deadline.
    DnsTimeout,
    /// No authorized upstream address accepted a connection.
    ConnectFailure,
    /// Upstream connection establishment exceeded its deadline.
    ConnectTimeout,
    /// Relay input or output failed.
    RelayFailure,
    /// Critical audit publication failed.
    AuditFailure,
    /// Automatic or interactive hook processing failed.
    HookFailure,
    /// A runtime error had no more specific public category.
    RuntimeFailure,
    /// SOCKS username/password authentication failed.
    AuthenticationFailed,
    /// SOCKS negotiation or request parsing failed.
    SocksProtocolError,
    /// The listener's connection semaphore was saturated.
    ConnectionLimit,
    /// An HTTP connection task failed.
    HttpError,
    /// A committed CONNECT tunnel failed outside relay I/O.
    TunnelFailure,
    /// The downstream TLS client rejected or aborted its handshake.
    TlsClientRejected,
    /// The downstream TLS handshake exceeded its deadline.
    TlsClientTimeout,
    /// Upstream TLS authentication or negotiation failed.
    TlsUpstreamRejected,
    /// Downstream and upstream ALPN selections were incompatible.
    TlsAlpnRejected,
    /// The intercepted upstream did not respond before its deadline.
    TlsUpstreamTimeout,
    /// A repeat draft violated the repeat request contract.
    RepeatInvalidRequest,
    /// Current policy denied a repeat request.
    RepeatPolicyDenied,
    /// DNS resolution failed for a repeat request.
    RepeatDnsFailed,
    /// Upstream TCP establishment failed for a repeat request.
    RepeatConnectFailed,
    /// Upstream TLS establishment failed for a repeat request.
    RepeatTlsFailed,
    /// The repeated HTTP exchange failed upstream.
    RepeatUpstreamFailed,
    /// Inspection or mutation failed for a repeat request.
    RepeatInspectionFailed,
    /// Critical audit publication failed for a repeat request.
    RepeatAuditFailed,
    /// Shutdown interrupted a repeat request.
    RepeatShutdown,
    /// A repeat request failed outside the public categories above.
    RepeatInternalFailure,
}

/// Behavior the data plane applies when an audit event cannot be queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditFailurePolicy {
    /// Preserve forwarding and return an explicit error when the channel is unavailable.
    FailOpen,
    /// Apply backpressure until the critical event is accepted; this is the default.
    #[default]
    FailClosed,
}

/// Milliseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
        status: HttpStatusCode,
        /// Header values after credential-bearing fields are redacted.
        headers: BTreeMap<String, Vec<String>>,
    },
    /// A proxy authentication attempt completed without recording credentials.
    ProxyAuthentication {
        /// Secret-free accepted or rejected result.
        outcome: AuthenticationOutcome,
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
        stage: AuditHookStage,
        /// Secret-free completed or failed result.
        outcome: HookOutcome,
    },
    /// An operator supplied an interactive interception decision.
    ManualModification {
        /// Stable action category without raw replacement content.
        action: ManualModificationAction,
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
        outcome: FlowOutcome,
    },
    /// A non-CONNECT flow reached its terminal lifecycle event.
    FlowClosed {
        /// Bytes relayed from client to upstream.
        client_to_upstream_bytes: u64,
        /// Bytes relayed from upstream to client.
        upstream_to_client_bytes: u64,
        /// Secret-free termination category.
        outcome: FlowOutcome,
    },
}

/// Correlation and policy identity attached to one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditContext {
    occurred_at: UnixMillis,
    session_id: SessionId,
    transaction_id: Option<TransactionId>,
    policy_generation: PolicyGeneration,
}

impl AuditContext {
    /// Creates the complete correlation context for one audit event.
    pub const fn new(
        occurred_at: UnixMillis,
        session_id: SessionId,
        transaction_id: Option<TransactionId>,
        policy_generation: PolicyGeneration,
    ) -> Self {
        Self {
            occurred_at,
            session_id,
            transaction_id,
            policy_generation,
        }
    }

    /// Returns the event timestamp sampled or restored by the producer.
    pub const fn occurred_at(self) -> UnixMillis {
        self.occurred_at
    }

    /// Returns the connection correlation identity.
    pub const fn session_id(self) -> SessionId {
        self.session_id
    }

    /// Returns the HTTP exchange identity when applicable.
    pub const fn transaction_id(self) -> Option<TransactionId> {
        self.transaction_id
    }

    /// Returns the immutable policy snapshot active for the event.
    pub const fn policy_generation(self) -> PolicyGeneration {
        self.policy_generation
    }

    /// Replaces the policy identity when an evaluation used a newer snapshot.
    #[must_use]
    pub const fn with_policy_generation(mut self, policy_generation: PolicyGeneration) -> Self {
        self.policy_generation = policy_generation;
        self
    }
}

/// Versioned JSONL record with a hash link to its predecessor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    schema_version: AuditSchemaVersion,
    sequence: AuditSequence,
    occurred_at: UnixMillis,
    session_id: SessionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    transaction_id: Option<TransactionId>,
    policy_generation: PolicyGeneration,
    event: AuditEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_hash: Option<RecordHash>,
    record_hash: RecordHash,
}

impl AuditRecord {
    #[allow(clippy::too_many_arguments)]
    pub(super) const fn from_parts(
        schema_version: AuditSchemaVersion,
        sequence: AuditSequence,
        occurred_at: UnixMillis,
        session_id: SessionId,
        transaction_id: Option<TransactionId>,
        policy_generation: PolicyGeneration,
        event: AuditEvent,
        previous_hash: Option<RecordHash>,
        record_hash: RecordHash,
    ) -> Self {
        Self {
            schema_version,
            sequence,
            occurred_at,
            session_id,
            transaction_id,
            policy_generation,
            event,
            previous_hash,
            record_hash,
        }
    }

    /// Returns the wire schema version recorded for this event.
    pub const fn schema_version(&self) -> AuditSchemaVersion {
        self.schema_version
    }

    /// Returns the monotonic position assigned by the segment sink.
    pub const fn sequence(&self) -> AuditSequence {
        self.sequence
    }

    /// Returns the event timestamp.
    pub const fn occurred_at(&self) -> UnixMillis {
        self.occurred_at
    }

    /// Returns the connection correlation identity.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the HTTP exchange identity when applicable.
    pub const fn transaction_id(&self) -> Option<TransactionId> {
        self.transaction_id
    }

    /// Returns the policy snapshot associated with the event.
    pub const fn policy_generation(&self) -> PolicyGeneration {
        self.policy_generation
    }

    /// Returns the redacted typed event payload.
    pub const fn event(&self) -> &AuditEvent {
        &self.event
    }

    /// Returns the preceding record hash, or `None` for the first record.
    pub const fn previous_hash(&self) -> Option<RecordHash> {
        self.previous_hash
    }

    /// Returns the canonical hash of this record.
    pub const fn record_hash(&self) -> RecordHash {
        self.record_hash
    }

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
    pub(super) schema_version: AuditSchemaVersion,
    pub(super) sequence: AuditSequence,
    pub(super) occurred_at: UnixMillis,
    pub(super) session_id: SessionId,
    pub(super) transaction_id: Option<TransactionId>,
    pub(super) policy_generation: PolicyGeneration,
    pub(super) event: &'a AuditEvent,
    pub(super) previous_hash: Option<RecordHash>,
}
