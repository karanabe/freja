use super::model::UnsignedAuditRecord;
use std::{error::Error, fmt, io::Write};

use freja_domain::AuditSequence;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::{
    AuditContext, AuditEnvelope, AuditEvent, AuditRecord, AuditSchemaVersion, CheckpointSchedule,
    RecordHash, Redactor,
};

/// JSON encoding, sink I/O, continuity, or sequence-space failure.
/// A partial write permanently poisons the sink.
#[derive(Debug)]
pub enum AuditError {
    /// A typed event or record could not be encoded as canonical JSON.
    Serialize(serde_json::Error),
    /// The underlying writer failed; a partial write may have occurred.
    Write(std::io::Error),
    /// A write was attempted after a possible partial record broke chain continuity.
    SinkPoisoned,
    /// The segment already used the largest representable sequence number.
    SequenceExhausted,
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialize(_) => formatter.write_str("failed to serialize audit record"),
            Self::Write(_) => formatter.write_str("failed to write audit record"),
            Self::SinkPoisoned => {
                formatter.write_str("audit sink is poisoned after an earlier partial write")
            }
            Self::SequenceExhausted => formatter.write_str("audit sequence space is exhausted"),
        }
    }
}

impl Error for AuditError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialize(source) => Some(source),
            Self::Write(source) => Some(source),
            Self::SinkPoisoned | Self::SequenceExhausted => None,
        }
    }
}

/// Stateful JSONL writer that owns sequence and hash-chain continuity.
pub struct JsonlAuditSink<W> {
    writer: W,
    redactor: Redactor,
    next_sequence: Option<AuditSequence>,
    previous_hash: Option<RecordHash>,
    poisoned: bool,
}

impl<W: Write> JsonlAuditSink<W> {
    /// Creates a fresh audit segment beginning at sequence one.
    pub const fn new(writer: W, redactor: Redactor) -> Self {
        Self {
            writer,
            redactor,
            next_sequence: Some(AuditSequence::FIRST),
            previous_hash: None,
            poisoned: false,
        }
    }

    /// Redacts, hashes, and appends exactly one JSON object and newline.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] when JSON encoding or output fails, an earlier
    /// partial output failure poisoned this sink, or the sequence is exhausted.
    pub fn write_event(
        &mut self,
        context: AuditContext,
        mut event: AuditEvent,
    ) -> Result<AuditRecord, AuditError> {
        if self.poisoned {
            return Err(AuditError::SinkPoisoned);
        }
        self.redactor.redact_event(&mut event);
        let sequence = self.next_sequence.ok_or(AuditError::SequenceExhausted)?;
        let unsigned = UnsignedAuditRecord {
            schema_version: AuditSchemaVersion::CURRENT,
            sequence,
            occurred_at: context.occurred_at(),
            session_id: context.session_id(),
            transaction_id: context.transaction_id(),
            policy_generation: context.policy_generation(),
            event: &event,
            previous_hash: self.previous_hash,
        };
        let canonical = serde_json::to_vec(&unsigned).map_err(AuditError::Serialize)?;
        let record_hash = RecordHash(Sha256::digest(canonical).into());
        let record = AuditRecord::from_parts(
            AuditSchemaVersion::CURRENT,
            sequence,
            context.occurred_at(),
            context.session_id(),
            context.transaction_id(),
            context.policy_generation(),
            event,
            self.previous_hash,
            record_hash,
        );
        let mut line = serde_json::to_vec(&record).map_err(AuditError::Serialize)?;
        line.push(b'\n');
        if let Err(source) = self.writer.write_all(&line) {
            self.poisoned = true;
            return Err(AuditError::Write(source));
        }
        self.previous_hash = Some(record_hash);
        self.next_sequence = sequence.checked_next();
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
            && ordinary_events.is_multiple_of(schedule.interval.get())
        {
            let checkpoint = schedule
                .signer
                .sign_checkpoint(record.sequence(), record.record_hash());
            sink.write_event(
                envelope.context,
                AuditEvent::SignedCheckpoint { checkpoint },
            )?;
            sink.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use freja_domain::{AuditSequence, PolicyGeneration, SessionId};

    use super::{AuditError, JsonlAuditSink};
    use crate::{AuditContext, AuditEvent, Redactor, UnixMillis};

    fn context() -> AuditContext {
        AuditContext::new(
            UnixMillis::from_millis(1),
            SessionId::new(),
            None,
            PolicyGeneration::INITIAL,
        )
    }

    fn event() -> AuditEvent {
        AuditEvent::ConnectionAccepted {
            client: "127.0.0.1:40000".to_owned(),
            listener: "127.0.0.1:8080".to_owned(),
        }
    }

    #[test]
    fn sequence_exhaustion_does_not_emit_a_duplicate_position() {
        let mut sink = JsonlAuditSink::new(Vec::new(), Redactor::new(std::iter::empty()));
        sink.next_sequence = Some(AuditSequence::new(u64::MAX).unwrap());

        let final_record = sink.write_event(context(), event()).unwrap();
        assert_eq!(final_record.sequence().get(), u64::MAX);
        assert!(matches!(
            sink.write_event(context(), event()),
            Err(AuditError::SequenceExhausted)
        ));
        let output = String::from_utf8(sink.into_inner()).unwrap();
        assert_eq!(output.lines().count(), 1);
    }
}
