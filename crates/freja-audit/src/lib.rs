#![forbid(unsafe_code)]

//! Typed, redacted, hash-chained JSONL security audit records.

use std::{
    collections::{BTreeMap, HashSet},
    error::Error,
    fmt, fs,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use freja_domain::{
    AuditSequence, Decision, Direction, Finding, PolicyGeneration, Protocol, ReplayFacts,
    SanitizedHeaders, SessionId, TransactionId,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use url::{Url, form_urlencoded};

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
pub struct RecordHash([u8; 32]);

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

/// Ed25519 signature over one audit record hash and its segment sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    pub covers_sequence: AuditSequence,
    pub record_hash: RecordHash,
    pub public_key_hex: String,
    pub signature_hex: String,
}

impl SignedCheckpoint {
    /// Verifies this checkpoint independently of local secret material.
    pub fn verifies(&self) -> bool {
        let Ok(public_key) = hex::decode(&self.public_key_hex) else {
            return false;
        };
        let Ok(public_key): Result<[u8; 32], _> = public_key.try_into() else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key) else {
            return false;
        };
        let Ok(signature) = hex::decode(&self.signature_hex) else {
            return false;
        };
        let Ok(signature): Result<[u8; 64], _> = signature.try_into() else {
            return false;
        };
        verifying_key
            .verify_strict(
                &checkpoint_message(self.covers_sequence, self.record_hash),
                &Signature::from_bytes(&signature),
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
            public_key_hex: self.verifying_key_hex(),
            signature_hex: hex::encode(signature.to_bytes()),
        }
    }
}

/// Optional periodic checkpoint generation policy.
#[derive(Debug, Clone)]
pub struct CheckpointSchedule {
    signer: CheckpointSigner,
    interval: u64,
}

impl CheckpointSchedule {
    /// Creates a non-zero checkpoint interval measured in ordinary events.
    ///
    /// # Errors
    ///
    /// Returns [`CheckpointKeyError::ZeroInterval`] for zero.
    pub fn new(signer: CheckpointSigner, interval: u64) -> Result<Self, CheckpointKeyError> {
        if interval == 0 {
            return Err(CheckpointKeyError::ZeroInterval);
        }
        Ok(Self { signer, interval })
    }
}

/// Protected checkpoint signing-key setup failure.
#[derive(Debug)]
pub enum CheckpointKeyError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    InsecurePermissions {
        path: PathBuf,
        mode: u32,
    },
    Hex(hex::FromHexError),
    InvalidLength,
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

#[derive(Serialize)]
struct UnsignedAuditRecord<'a> {
    schema_version: u16,
    sequence: AuditSequence,
    occurred_at: UnixMillis,
    session_id: SessionId,
    transaction_id: Option<TransactionId>,
    policy_generation: PolicyGeneration,
    event: &'a AuditEvent,
    previous_hash: Option<RecordHash>,
}

/// Central secret redaction policy used before audit serialization.
#[derive(Debug, Clone)]
pub struct Redactor {
    query_parameters: HashSet<String>,
}

impl Redactor {
    /// Creates a redactor. Query parameter names are matched case-insensitively.
    pub fn new(parameters: impl IntoIterator<Item = String>) -> Self {
        Self {
            query_parameters: parameters
                .into_iter()
                .map(|parameter| parameter.to_ascii_lowercase())
                .collect(),
        }
    }

    /// Replaces standard credential-bearing header values.
    pub fn redact_headers(&self, headers: &mut BTreeMap<String, Vec<String>>) {
        for (name, values) in headers {
            if is_secret_header(name) {
                *values = vec!["[REDACTED]".to_owned()];
            }
        }
    }

    /// Redacts configured query parameter values in absolute or origin-form targets.
    pub fn redact_target(&self, target: &str) -> String {
        match Url::parse(target) {
            Ok(mut url) => {
                let has_userinfo = !url.username().is_empty() || url.password().is_some();
                if has_userinfo
                    && (url.set_username("[REDACTED]").is_err() || url.set_password(None).is_err())
                {
                    return "[REDACTED URL WITH USERINFO]".to_owned();
                }
                let pairs = url
                    .query_pairs()
                    .map(|(name, value)| (name.into_owned(), value.into_owned()))
                    .collect::<Vec<_>>();
                if pairs.is_empty() && !has_userinfo {
                    return target.to_owned();
                }
                if !pairs.is_empty() {
                    url.set_query(None);
                    let mut query = url.query_pairs_mut();
                    for (name, value) in pairs {
                        let value = if self.is_secret_parameter(&name) {
                            "[REDACTED]"
                        } else {
                            &value
                        };
                        query.append_pair(&name, value);
                    }
                }
                url.into()
            }
            Err(_) => self.redact_origin_form(target),
        }
    }

    /// Applies all event-specific redaction before hashing and persistence.
    pub fn redact_event(&self, event: &mut AuditEvent) {
        match event {
            AuditEvent::HttpRequestObserved {
                target, headers, ..
            } => {
                *target = self.redact_target(target);
                self.redact_headers(headers);
            }
            AuditEvent::HttpResponseObserved { headers, .. } => self.redact_headers(headers),
            AuditEvent::ReplayFactsObserved {
                facts: ReplayFacts::HttpRequest(facts),
            } => {
                *facts = freja_domain::HttpRequestFacts::new(
                    facts.target().clone(),
                    facts.method(),
                    self.redact_target(facts.path()),
                    redact_sanitized_headers(facts.headers()),
                );
            }
            AuditEvent::ReplayFactsObserved {
                facts: ReplayFacts::HttpResponse(facts),
            } => {
                *facts = freja_domain::HttpResponseFacts::new(
                    facts.target().clone(),
                    facts.status(),
                    redact_sanitized_headers(facts.headers()),
                );
            }
            _ => {}
        }
    }

    fn redact_origin_form(&self, target: &str) -> String {
        let (without_fragment, fragment) = target
            .split_once('#')
            .map_or((target, None), |(left, right)| (left, Some(right)));
        let Some((path, raw_query)) = without_fragment.split_once('?') else {
            return target.to_owned();
        };
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
            let value = if self.is_secret_parameter(&name) {
                "[REDACTED]"
            } else {
                value.as_ref()
            };
            serializer.append_pair(&name, value);
        }
        let query = serializer.finish();
        fragment.map_or_else(
            || format!("{path}?{query}"),
            |fragment| format!("{path}?{query}#{fragment}"),
        )
    }

    fn is_secret_parameter(&self, name: &str) -> bool {
        self.query_parameters.contains(&name.to_ascii_lowercase())
    }
}

fn is_secret_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
    )
}

fn redact_sanitized_headers(headers: &SanitizedHeaders) -> SanitizedHeaders {
    SanitizedHeaders::new(headers.iter().map(|(name, values)| {
        let values = if is_secret_header(name) {
            vec![b"[REDACTED]".to_vec()]
        } else {
            values.to_vec()
        };
        (name.to_owned(), values)
    }))
}

/// JSON encoding or sink I/O failure. A partial write permanently poisons the sink.
#[derive(Debug)]
pub enum AuditError {
    Serialize(serde_json::Error),
    Write(std::io::Error),
    SinkPoisoned,
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialize(_) => formatter.write_str("failed to serialize audit record"),
            Self::Write(_) => formatter.write_str("failed to write audit record"),
            Self::SinkPoisoned => {
                formatter.write_str("audit sink is poisoned after an earlier partial write")
            }
        }
    }
}

impl Error for AuditError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialize(source) => Some(source),
            Self::Write(source) => Some(source),
            Self::SinkPoisoned => None,
        }
    }
}

/// Stateful JSONL writer that owns sequence and hash-chain continuity.
pub struct JsonlAuditSink<W> {
    writer: W,
    redactor: Redactor,
    next_sequence: u64,
    previous_hash: Option<RecordHash>,
    poisoned: bool,
}

impl<W: Write> JsonlAuditSink<W> {
    /// Creates a fresh audit segment beginning at sequence one.
    pub const fn new(writer: W, redactor: Redactor) -> Self {
        Self {
            writer,
            redactor,
            next_sequence: 1,
            previous_hash: None,
            poisoned: false,
        }
    }

    /// Redacts, hashes, and appends exactly one JSON object and newline.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] when JSON encoding or output fails, or when an
    /// earlier partial output failure has poisoned this sink.
    pub fn write_event(
        &mut self,
        context: AuditContext,
        mut event: AuditEvent,
    ) -> Result<AuditRecord, AuditError> {
        if self.poisoned {
            return Err(AuditError::SinkPoisoned);
        }
        self.redactor.redact_event(&mut event);
        let sequence = AuditSequence::new(self.next_sequence);
        let unsigned = UnsignedAuditRecord {
            schema_version: 1,
            sequence,
            occurred_at: context.occurred_at,
            session_id: context.session_id,
            transaction_id: context.transaction_id,
            policy_generation: context.policy_generation,
            event: &event,
            previous_hash: self.previous_hash,
        };
        let canonical = serde_json::to_vec(&unsigned).map_err(AuditError::Serialize)?;
        let record_hash = RecordHash(Sha256::digest(canonical).into());
        let record = AuditRecord {
            schema_version: 1,
            sequence,
            occurred_at: context.occurred_at,
            session_id: context.session_id,
            transaction_id: context.transaction_id,
            policy_generation: context.policy_generation,
            event,
            previous_hash: self.previous_hash,
            record_hash,
        };
        let mut line = serde_json::to_vec(&record).map_err(AuditError::Serialize)?;
        line.push(b'\n');
        if let Err(source) = self.writer.write_all(&line) {
            self.poisoned = true;
            return Err(AuditError::Write(source));
        }
        self.previous_hash = Some(record_hash);
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(record)
    }

    /// Flushes buffered bytes to the underlying writer.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] when flushing fails or this sink is poisoned.
    pub fn flush(&mut self) -> Result<(), AuditError> {
        if self.poisoned {
            return Err(AuditError::SinkPoisoned);
        }
        self.writer.flush().map_err(AuditError::Write)
    }

    /// Returns the underlying writer after all pending records have been handled.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

/// Drains a bounded audit receiver into one JSONL sink on a blocking worker.
///
/// This function uses `blocking_recv` and must not run directly on an async
/// executor worker. Bootstrap code should call it through `spawn_blocking` or a
/// dedicated thread.
///
/// # Errors
///
/// Returns [`AuditError`] when writing or flushing any record fails.
pub fn drain_jsonl<W: Write>(
    receiver: mpsc::Receiver<AuditEnvelope>,
    writer: W,
    redactor: Redactor,
) -> Result<(), AuditError> {
    drain_jsonl_with_checkpoints(receiver, writer, redactor, None)
}

/// Drains audit events and optionally inserts periodic Ed25519 checkpoints.
///
/// # Errors
///
/// Returns [`AuditError`] when writing or flushing any record fails.
pub fn drain_jsonl_with_checkpoints<W: Write>(
    mut receiver: mpsc::Receiver<AuditEnvelope>,
    writer: W,
    redactor: Redactor,
    checkpoint: Option<&CheckpointSchedule>,
) -> Result<(), AuditError> {
    let mut sink = JsonlAuditSink::new(writer, redactor);
    let mut ordinary_events = 0_u64;
    while let Some(envelope) = receiver.blocking_recv() {
        let record = sink.write_event(envelope.context, envelope.event)?;
        ordinary_events = ordinary_events.saturating_add(1);
        sink.flush()?;
        if let Some(schedule) = &checkpoint
            && ordinary_events.is_multiple_of(schedule.interval)
        {
            let checkpoint = schedule
                .signer
                .sign_checkpoint(record.sequence, record.record_hash);
            sink.write_event(
                envelope.context,
                AuditEvent::SignedCheckpoint { checkpoint },
            )?;
            sink.flush()?;
        }
    }
    Ok(())
}

fn checkpoint_message(sequence: AuditSequence, record_hash: RecordHash) -> Vec<u8> {
    let mut message = b"freja-audit-checkpoint-v1\0".to_vec();
    message.extend_from_slice(&sequence.get().to_be_bytes());
    message.extend_from_slice(record_hash.as_bytes());
    message
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

/// Owned event sent through the bounded audit publisher.
#[derive(Debug, Clone)]
pub struct AuditEnvelope {
    pub context: AuditContext,
    pub event: AuditEvent,
}

/// An explicit audit delivery failure; critical records are never silently discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishError {
    ChannelClosed,
    CapacityExhausted,
}

impl fmt::Display for PublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChannelClosed => formatter.write_str("audit channel is closed"),
            Self::CapacityExhausted => formatter.write_str("audit channel capacity is exhausted"),
        }
    }
}

impl Error for PublishError {}

/// Sender side of a bounded audit channel with explicit fail-open/fail-closed behavior.
#[derive(Debug, Clone)]
pub struct AuditPublisher {
    sender: mpsc::Sender<AuditEnvelope>,
    failure_policy: AuditFailurePolicy,
    rejected_events: Arc<AtomicU64>,
}

/// Failure to create an audit channel with a valid finite capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditChannelError {
    ZeroCapacity,
}

impl fmt::Display for AuditChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCapacity => formatter.write_str("audit channel capacity must be non-zero"),
        }
    }
}

impl Error for AuditChannelError {}

impl AuditPublisher {
    /// Creates a separate bounded publisher and its single-consumer receiver.
    ///
    /// # Errors
    ///
    /// Returns [`AuditChannelError::ZeroCapacity`] when `capacity` is zero.
    pub fn channel(
        capacity: usize,
        failure_policy: AuditFailurePolicy,
    ) -> Result<(Self, mpsc::Receiver<AuditEnvelope>), AuditChannelError> {
        if capacity == 0 {
            return Err(AuditChannelError::ZeroCapacity);
        }
        let (sender, receiver) = mpsc::channel(capacity);
        Ok((
            Self {
                sender,
                failure_policy,
                rejected_events: Arc::new(AtomicU64::new(0)),
            },
            receiver,
        ))
    }

    /// Publishes an event. Fail-closed waits for capacity; fail-open returns an explicit error.
    ///
    /// # Errors
    ///
    /// Returns [`PublishError`] when the consumer is closed, or when fail-open
    /// delivery finds the bounded channel at capacity.
    pub async fn publish(&self, envelope: AuditEnvelope) -> Result<(), PublishError> {
        match self.failure_policy {
            AuditFailurePolicy::FailClosed => self
                .sender
                .send(envelope)
                .await
                .map_err(|_| PublishError::ChannelClosed),
            AuditFailurePolicy::FailOpen => self.sender.try_send(envelope).map_err(|error| {
                self.rejected_events.fetch_add(1, Ordering::Relaxed);
                match error {
                    mpsc::error::TrySendError::Full(_) => PublishError::CapacityExhausted,
                    mpsc::error::TrySendError::Closed(_) => PublishError::ChannelClosed,
                }
            }),
        }
    }

    /// Number of fail-open events rejected due to channel failure or saturation.
    pub fn rejected_events(&self) -> u64 {
        self.rejected_events.load(Ordering::Relaxed)
    }

    /// Returns the delivery policy bootstrap selected for this publisher.
    pub const fn failure_policy(&self) -> AuditFailurePolicy {
        self.failure_policy
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io::{self, Write},
        sync::mpsc,
        time::Duration,
    };

    use freja_domain::{
        HttpRequestFacts, PolicyGeneration, Port, Protocol, ReplayFacts, RequestedTargetFacts,
        ResolvedTargetFacts, SanitizedHeaders, SessionId, TargetHost, TransactionId,
    };

    use super::{
        AuditContext, AuditEnvelope, AuditEvent, CheckpointSigner, JsonlAuditSink, Redactor,
        UnixMillis, drain_jsonl,
    };

    struct FlushReporter(mpsc::SyncSender<()>);

    impl Write for FlushReporter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0
                .send(())
                .map_err(|_| io::Error::other("flush observer closed"))
        }
    }

    fn context(transaction_id: Option<TransactionId>) -> AuditContext {
        AuditContext {
            occurred_at: UnixMillis::from_millis(42),
            session_id: SessionId::new(),
            transaction_id,
            policy_generation: PolicyGeneration::default(),
        }
    }

    #[test]
    fn secrets_are_redacted_before_hashing_and_writing() {
        let mut sink = JsonlAuditSink::new(
            Vec::new(),
            Redactor::new(["token".to_owned(), "password".to_owned()]),
        );
        let event = AuditEvent::HttpRequestObserved {
            method: "GET".to_owned(),
            target: "http://alice:userinfo-secret@example.test/path?token=secret&ok=yes".to_owned(),
            headers: BTreeMap::from([
                ("Authorization".to_owned(), vec!["Bearer secret".to_owned()]),
                ("Accept".to_owned(), vec!["application/json".to_owned()]),
            ]),
        };

        sink.write_event(context(Some(TransactionId::new())), event)
            .unwrap();
        let requested = RequestedTargetFacts::new(
            "127.0.0.1".parse().unwrap(),
            TargetHost::parse("example.test").unwrap(),
            Port::new(80).unwrap(),
            Protocol::Http,
        );
        let replay = ReplayFacts::HttpRequest(HttpRequestFacts::new(
            ResolvedTargetFacts::new(requested, "192.0.2.1".parse().unwrap()),
            "GET",
            "/replay?password=replay-secret",
            SanitizedHeaders::new([(
                "authorization".to_owned(),
                vec![b"Bearer replay-secret".to_vec()],
            )]),
        ));
        sink.write_event(
            context(Some(TransactionId::new())),
            AuditEvent::ReplayFactsObserved { facts: replay },
        )
        .unwrap();
        let output = String::from_utf8(sink.into_inner()).unwrap();

        assert!(!output.contains("Bearer secret"));
        assert!(!output.contains("alice"));
        assert!(!output.contains("userinfo-secret"));
        assert!(!output.contains("token=secret"));
        assert!(output.contains("%5BREDACTED%5D"));
        assert!(output.contains("application/json"));
        assert!(!output.contains("replay-secret"));
    }

    #[test]
    fn records_form_a_sequence_and_hash_chain() {
        let mut sink = JsonlAuditSink::new(Vec::new(), Redactor::new(Vec::new()));
        let first = sink
            .write_event(
                context(None),
                AuditEvent::ConnectionAccepted {
                    client: "127.0.0.1:40000".to_owned(),
                    listener: "127.0.0.1:8080".to_owned(),
                },
            )
            .unwrap();
        let second = sink
            .write_event(
                context(None),
                AuditEvent::FlowClosed {
                    client_to_upstream_bytes: 10,
                    upstream_to_client_bytes: 20,
                    outcome: "completed".to_owned(),
                },
            )
            .unwrap();

        assert_eq!(first.sequence.get(), 1);
        assert_eq!(second.sequence.get(), 2);
        assert_eq!(second.previous_hash, Some(first.record_hash));
    }

    #[test]
    fn signed_checkpoint_detects_hash_or_signature_changes() {
        let mut sink = JsonlAuditSink::new(Vec::new(), Redactor::new(Vec::new()));
        let record = sink
            .write_event(
                context(None),
                AuditEvent::ConnectionAccepted {
                    client: "127.0.0.1:40000".to_owned(),
                    listener: "127.0.0.1:8080".to_owned(),
                },
            )
            .unwrap();
        let signer = CheckpointSigner::from_seed([7_u8; 32]);
        let checkpoint = signer.sign_checkpoint(record.sequence, record.record_hash);
        assert!(checkpoint.verifies());

        let mut tampered = checkpoint;
        tampered.signature_hex.replace_range(0..2, "00");
        assert!(!tampered.verifies());
    }

    #[test]
    fn drain_flushes_each_event_before_the_channel_closes() {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let (flush_sender, flush_receiver) = mpsc::sync_channel(1);
        let task = std::thread::spawn(move || {
            drain_jsonl(
                receiver,
                FlushReporter(flush_sender),
                Redactor::new(Vec::new()),
            )
        });
        sender
            .blocking_send(AuditEnvelope {
                context: context(None),
                event: AuditEvent::ConnectionAccepted {
                    client: "127.0.0.1:40000".to_owned(),
                    listener: "127.0.0.1:8080".to_owned(),
                },
            })
            .unwrap();

        flush_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(sender);
        task.join().unwrap().unwrap();
    }
}
