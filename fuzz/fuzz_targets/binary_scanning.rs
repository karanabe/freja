#![no_main]
#![forbid(unsafe_code)]

use freja_domain::{Confidence, DetectorId, Direction, PolicyGeneration, RuleId, Severity};
use freja_policy::{InspectionPattern, InspectionProgram, RuleAction};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let pattern_length = usize::from(data[0]).min(data.len().saturating_sub(1));
    if pattern_length == 0 {
        return;
    }
    let Ok(detector_id) = DetectorId::new("fuzz-detector") else {
        return;
    };
    let Ok(rule_id) = RuleId::new("fuzz-rule") else {
        return;
    };
    let Ok(generation) = PolicyGeneration::new(1) else {
        return;
    };
    let Ok(pattern) = InspectionPattern::new(
        detector_id,
        rule_id,
        data[1..=pattern_length].to_vec(),
        Severity::High,
        Confidence::Confirmed,
        vec![Direction::ClientToUpstream],
        RuleAction::Deny,
        Vec::new(),
    ) else {
        return;
    };
    let Ok(program) = InspectionProgram::new(generation, vec![pattern]) else {
        return;
    };
    let mut scanner = program.scanner(Direction::ClientToUpstream);
    let payload = &data[pattern_length.saturating_add(1)..];
    let split = payload.len() / 2;
    let _first = scanner.inspect(&payload[..split]);
    let _second = scanner.inspect(&payload[split..]);
});
