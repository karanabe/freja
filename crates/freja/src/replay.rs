use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Read},
    path::PathBuf,
};

use freja::{AppError, AppResult, ResultExt};
use freja_audit::{AuditEvent, AuditRecord, RecordHash};
use freja_config::CompiledConfig;
use freja_domain::{Decision, Direction, Protocol, ReplayFacts, SessionId, TransactionId};
use freja_policy::{PolicyFacts, StreamScanner};
use tracing::info;

use super::MAXIMUM_REPLAY_LINE_BYTES;

pub(super) fn replay_audit(
    audit_path: &PathBuf,
    config_path: &PathBuf,
    checkpoint_public_key: Option<&str>,
) -> AppResult<()> {
    let compiled = CompiledConfig::load(config_path).with_context(|| {
        format!(
            "could not compile replay configuration {}",
            config_path.display()
        )
    })?;
    let file = File::open(audit_path)
        .with_context(|| format!("could not open audit segment {}", audit_path.display()))?;
    let mut expected_sequence = 1_u64;
    let mut previous_hash: Option<RecordHash> = None;
    let mut decisions = 0_u64;
    let expected_checkpoint_key = checkpoint_public_key
        .map(parse_checkpoint_public_key)
        .transpose()?;
    let mut verified_checkpoints = 0_u64;
    let mut scanners = HashMap::<ReplayStreamKey, StreamScanner>::new();
    let mut reader = BufReader::new(file);
    let mut line_number = 0_usize;
    while let Some(line) = read_bounded_replay_line(&mut reader, MAXIMUM_REPLAY_LINE_BYTES)? {
        line_number = line_number.saturating_add(1);
        let record = serde_json::from_str::<AuditRecord>(&line)
            .with_context(|| format!("invalid audit JSON at line {line_number}"))?;
        validate_replay_schema(record.schema_version, line_number)?;
        validate_replay_event_schema(record.schema_version, &record.event, line_number)?;
        if record.sequence.get() != expected_sequence
            || record.previous_hash != previous_hash
            || !record.verifies_hash()
        {
            return Err(AppError::msg(format!(
                "audit integrity verification failed at line {line_number}"
            )));
        }
        if let AuditEvent::SignedCheckpoint { checkpoint } = &record.event {
            let key_matches = expected_checkpoint_key.is_none_or(|expected| {
                hex::decode(&checkpoint.public_key_hex)
                    .is_ok_and(|actual| actual.as_slice() == expected.as_slice())
            });
            let covers_chain = previous_hash.is_some_and(|hash| {
                checkpoint.covers_sequence.get() == expected_sequence.saturating_sub(1)
                    && checkpoint.record_hash == hash
            });
            if !checkpoint.verifies() || !key_matches || !covers_chain {
                return Err(AppError::msg(format!(
                    "audit checkpoint verification failed at line {line_number}"
                )));
            }
            verified_checkpoints = verified_checkpoints.saturating_add(1);
        }
        decisions = decisions.saturating_add(replay_record(&compiled, &record, &mut scanners)?);
        previous_hash = Some(record.record_hash);
        expected_sequence = expected_sequence.saturating_add(1);
    }
    if expected_checkpoint_key.is_some() && verified_checkpoints == 0 {
        return Err(AppError::msg(
            "audit segment contains no checkpoint from the required public key",
        ));
    }
    info!(
        records = expected_sequence.saturating_sub(1),
        decisions, "offline replay completed"
    );
    Ok(())
}

pub(super) fn validate_replay_schema(schema_version: u16, line_number: usize) -> AppResult<()> {
    if !matches!(schema_version, 1 | 2) {
        return Err(AppError::msg(format!(
            "unsupported audit schema version {schema_version} at line {line_number}"
        )));
    }
    Ok(())
}

pub(super) fn validate_replay_event_schema(
    schema_version: u16,
    event: &AuditEvent,
    line_number: usize,
) -> AppResult<()> {
    if schema_version == 1 && matches!(event, AuditEvent::HttpRepeatStarted { .. }) {
        return Err(AppError::msg(format!(
            "audit schema version 1 cannot contain an HTTP repeat event at line {line_number}"
        )));
    }
    Ok(())
}

pub(super) fn read_bounded_replay_line(
    reader: &mut impl BufRead,
    maximum_bytes: usize,
) -> AppResult<Option<String>> {
    let maximum_with_line_ending = maximum_bytes.saturating_add(2);
    let mut bytes = Vec::new();
    let mut limited = reader.take(u64::try_from(maximum_with_line_ending).unwrap_or(u64::MAX));
    let count = limited
        .read_until(b'\n', &mut bytes)
        .context("could not read audit input")?;
    if count == 0 {
        return Ok(None);
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.len() > maximum_bytes {
        return Err(AppError::msg(format!(
            "audit line exceeds the {maximum_bytes}-byte replay limit"
        )));
    }
    String::from_utf8(bytes)
        .context("audit input is not UTF-8")
        .map(Some)
}

fn parse_checkpoint_public_key(value: &str) -> AppResult<[u8; 32]> {
    let decoded = hex::decode(value).context("checkpoint public key is not hexadecimal")?;
    decoded
        .try_into()
        .map_err(|_| AppError::msg("checkpoint public key must contain exactly 32 bytes"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ReplayStreamKey {
    session_id: SessionId,
    transaction_id: Option<TransactionId>,
    direction: Direction,
    protocol: Protocol,
}

fn replay_record(
    compiled: &CompiledConfig,
    record: &AuditRecord,
    scanners: &mut HashMap<ReplayStreamKey, StreamScanner>,
) -> AppResult<u64> {
    match &record.event {
        AuditEvent::ReplayFactsObserved { facts } => replay_facts(compiled, record, facts),
        AuditEvent::PayloadPrefixCaptured {
            direction,
            protocol,
            bytes_hex,
        } => {
            let bytes = hex::decode(bytes_hex).with_context(|| {
                format!(
                    "invalid captured bytes at sequence {}",
                    record.sequence.get()
                )
            })?;
            if bytes.len() > compiled.limits().body_prefix_bytes {
                return Err(AppError::msg(format!(
                    "captured bytes at sequence {} exceed the configured replay body-prefix limit",
                    record.sequence.get()
                )));
            }
            let key = ReplayStreamKey {
                session_id: record.session_id,
                transaction_id: record.transaction_id,
                direction: *direction,
                protocol: *protocol,
            };
            let scanner = scanners
                .entry(key)
                .or_insert_with(|| compiled.inspection().scanner(*direction));
            let mut count = 0_u64;
            for finding in scanner.inspect(&bytes) {
                let decision = compiled.inspection().evaluate(&finding, *protocol);
                emit_replay_decision(record, "captured-prefix", &decision)?;
                count = count.saturating_add(1);
            }
            Ok(count)
        }
        AuditEvent::ConnectionAccepted { .. }
        | AuditEvent::TargetResolved { .. }
        | AuditEvent::AclEvaluated { .. }
        | AuditEvent::HttpRequestObserved { .. }
        | AuditEvent::HttpResponseObserved { .. }
        | AuditEvent::ProxyAuthentication { .. }
        | AuditEvent::FindingDetected { .. }
        | AuditEvent::InspectionEvaluated { .. }
        | AuditEvent::HookExecuted { .. }
        | AuditEvent::ManualModification { .. }
        | AuditEvent::HttpRepeatStarted { .. }
        | AuditEvent::TlsCertificateGenerated { .. }
        | AuditEvent::TlsInterceptionEstablished { .. }
        | AuditEvent::ActionExecuted { .. }
        | AuditEvent::TunnelClosed { .. }
        | AuditEvent::FlowClosed { .. }
        | AuditEvent::SignedCheckpoint { .. } => Ok(0),
    }
}

fn replay_facts(
    compiled: &CompiledConfig,
    record: &AuditRecord,
    facts: &ReplayFacts,
) -> AppResult<u64> {
    let decisions = match facts {
        ReplayFacts::Requested(facts) => {
            vec![compiled.policy().evaluate(PolicyFacts::Requested(facts))]
        }
        ReplayFacts::Resolved(facts) => {
            let mut decisions = Vec::with_capacity(2);
            if let Some(decision) = compiled
                .destination_guard()
                .evaluate(compiled.policy().generation(), facts)
            {
                decisions.push(decision);
            }
            decisions.push(compiled.policy().evaluate(PolicyFacts::Resolved(facts)));
            decisions
        }
        ReplayFacts::HttpRequest(facts) => {
            vec![compiled.policy().evaluate(PolicyFacts::HttpRequest(facts))]
        }
        ReplayFacts::HttpResponse(facts) => {
            vec![compiled.policy().evaluate(PolicyFacts::HttpResponse(facts))]
        }
        ReplayFacts::Finding { finding, protocol } => {
            vec![compiled.inspection().evaluate(finding, *protocol)]
        }
    };
    for decision in &decisions {
        emit_replay_decision(record, "recorded-facts", decision)?;
    }
    Ok(u64::try_from(decisions.len()).unwrap_or(u64::MAX))
}

fn emit_replay_decision(
    record: &AuditRecord,
    source: &'static str,
    decision: &Decision,
) -> AppResult<()> {
    let output = serde_json::json!({
        "source_sequence": record.sequence,
        "session_id": record.session_id,
        "transaction_id": record.transaction_id,
        "source": source,
        "decision": decision,
    });
    let output = serde_json::to_string(&output).context("could not serialize replay decision")?;
    println!("{output}");
    Ok(())
}
