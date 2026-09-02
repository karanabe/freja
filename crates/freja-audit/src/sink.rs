use super::model::UnsignedAuditRecord;
use std::{error::Error, fmt, io::Write};

use freja_domain::AuditSequence;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::{
    AuditContext, AuditEnvelope, AuditEvent, AuditRecord, CheckpointSchedule, RecordHash, Redactor,
};

/// JSON encoding or sink I/O failure. A partial write permanently poisons the sink.
#[derive(Debug)]
pub enum AuditError {
    /// A typed event or record could not be encoded as canonical JSON.
    Serialize(serde_json::Error),
    /// The underlying writer failed; a partial write may have occurred.
    Write(std::io::Error),
    /// A write was attempted after a possible partial record broke chain continuity.
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
            schema_version: 2,
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
            schema_version: 2,
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
