#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Typed, redacted, hash-chained JSONL security audit records.
//!
//! Audit delivery uses a channel independent from best-effort UI events.
//! Producers are cloneable and safe to share between flow tasks; a single
//! consumer owns sequence assignment, redaction, hashing, and output. Secret
//! values are removed before a record hash is calculated.
//!
//! # Example
//!
//! ```
//! use freja_audit::{
//!     AuditContext, AuditEnvelope, AuditEvent, AuditFailurePolicy, AuditPublisher,
//!     UnixMillis,
//! };
//! use freja_domain::{PolicyGeneration, SessionId};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let (publisher, mut receiver) =
//!     AuditPublisher::channel(8, AuditFailurePolicy::FailClosed)?;
//! publisher.publish(AuditEnvelope {
//!     context: AuditContext {
//!         occurred_at: UnixMillis::from_millis(1),
//!         session_id: SessionId::new(),
//!         transaction_id: None,
//!         policy_generation: PolicyGeneration::default(),
//!     },
//!     event: AuditEvent::ConnectionAccepted {
//!         client: "127.0.0.1:50000".to_owned(),
//!         listener: "127.0.0.1:8080".to_owned(),
//!     },
//! }).await?;
//!
//! assert!(receiver.recv().await.is_some());
//! # Ok(())
//! # }
//! ```

mod checkpoint;
mod model;
mod publisher;
mod redaction;
mod sink;

pub use checkpoint::{CheckpointKeyError, CheckpointSchedule, CheckpointSigner, SignedCheckpoint};
pub use model::{
    AuditContext, AuditEvent, AuditFailurePolicy, AuditRecord, RecordHash, UnixMillis,
};
pub use publisher::{AuditChannelError, AuditEnvelope, AuditPublisher, PublishError};
pub use redaction::Redactor;
pub use sink::{AuditError, JsonlAuditSink, drain_jsonl, drain_jsonl_with_checkpoints};

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
