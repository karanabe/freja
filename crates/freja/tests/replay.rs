//! Integration tests for deterministic audit replay behavior.

use std::{
    fs,
    net::IpAddr,
    path::Path,
    process::{Command, Output},
};

use freja_audit::{
    AuditContext, AuditEvent, CheckpointSigner, JsonlAuditSink, Redactor, UnixMillis,
};
use freja_domain::{
    Direction, PolicyGeneration, Port, Protocol, ReplayFacts, RequestedTargetFacts, SessionId,
    TargetHost,
};

#[test]
fn replay_verifies_and_evaluates_recorded_facts() {
    let session_id = SessionId::new();
    let directory = std::env::temp_dir().join(format!("freja-replay-test-{session_id}"));
    fs::create_dir(&directory).unwrap();
    let audit_path = directory.join("audit.jsonl");
    let config_path = directory.join("candidate.toml");

    let mut sink = JsonlAuditSink::new(Vec::new(), Redactor::new(Vec::new()));
    let first = sink
        .write_event(
            AuditContext {
                occurred_at: UnixMillis::from_millis(1),
                session_id,
                transaction_id: None,
                policy_generation: PolicyGeneration::new(1).unwrap(),
            },
            AuditEvent::ReplayFactsObserved {
                facts: ReplayFacts::Requested(RequestedTargetFacts::new(
                    IpAddr::from([127, 0, 0, 1]),
                    TargetHost::parse("example.test").unwrap(),
                    Port::new(80).unwrap(),
                    Protocol::Http,
                )),
            },
        )
        .unwrap();
    let signer = CheckpointSigner::from_seed([23_u8; 32]);
    let public_key = signer.verifying_key_hex();
    sink.write_event(
        AuditContext {
            occurred_at: UnixMillis::from_millis(2),
            session_id,
            transaction_id: None,
            policy_generation: PolicyGeneration::new(1).unwrap(),
        },
        AuditEvent::SignedCheckpoint {
            checkpoint: signer.sign_checkpoint(first.sequence, first.record_hash),
        },
    )
    .unwrap();
    sink.write_event(
        AuditContext {
            occurred_at: UnixMillis::from_millis(3),
            session_id,
            transaction_id: None,
            policy_generation: PolicyGeneration::new(1).unwrap(),
        },
        AuditEvent::PayloadPrefixCaptured {
            direction: Direction::ClientToUpstream,
            protocol: Protocol::Tcp,
            bytes_hex: hex::encode("prefix-MALWARE-suffix"),
        },
    )
    .unwrap();
    fs::write(&audit_path, sink.into_inner()).unwrap();
    fs::write(
        &config_path,
        r#"
            [policy]
            generation = 99
            default_action = "allow"

            [inspection]
            mode = "streaming"

            [[inspection.patterns]]
            detector_id = "replay-signature"
            rule_id = "deny-replay-signature"
            pattern_hex = "4d414c57415245"
            directions = ["client-to-upstream"]
            action = "deny"

            [[listeners]]
            kind = "http-forward"
            bind = "127.0.0.1:8080"
        "#,
    )
    .unwrap();

    let output = run_replay(&audit_path, &config_path, &public_key);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("\"source\":\"recorded-facts\""));
    assert!(stdout.contains("\"source\":\"captured-prefix\""));
    assert!(stdout.contains("deny-replay-signature"));
    assert!(stdout.contains("\"policy_generation\":99"));

    let rejected = run_replay(&audit_path, &config_path, &"00".repeat(32));
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("checkpoint verification failed"));

    let unsupported_path = directory.join("unsupported-schema.jsonl");
    let audit = fs::read_to_string(&audit_path).unwrap();
    let unsupported = audit.replacen("\"schema_version\":1", "\"schema_version\":2", 1);
    assert_ne!(unsupported, audit);
    fs::write(&unsupported_path, unsupported).unwrap();
    let rejected = run_replay(&unsupported_path, &config_path, &public_key);
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("unsupported audit schema version 2 at line 1")
    );

    fs::remove_dir_all(directory).unwrap();
}

fn run_replay(audit_path: &Path, config_path: &Path, public_key: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_freja"))
        .args([
            "replay",
            "--audit",
            audit_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
            "--checkpoint-public-key",
            public_key,
        ])
        .output()
        .unwrap()
}
