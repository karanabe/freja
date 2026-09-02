//! Integration tests for raw, validated, and compiled configuration lifecycle behavior.

use std::{
    fs,
    sync::atomic::{AtomicUsize, Ordering},
};

use freja_config::{CompiledConfig, ConfigError, RawConfig, TlsConfig, ValidationError};
use freja_domain::{EnforcementMode, HookMode, ListenerSpec, UiMode};

static TEMP_FILE_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

#[test]
fn compiled_config_loads_a_file_through_the_full_pipeline() {
    let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "freja-config-{}-{sequence}.toml",
        std::process::id()
    ));
    fs::write(
        &path,
        r#"
            [[listeners]]
            kind = "http-forward"
            bind = "127.0.0.1:8080"
        "#,
    )
    .unwrap();

    let compiled = CompiledConfig::load(&path).unwrap();
    fs::remove_file(path).unwrap();

    assert!(matches!(
        compiled.listeners(),
        [ListenerSpec::HttpForward(_)]
    ));
}

#[test]
fn omitted_runtime_uses_the_interactive_tui_profile() {
    let raw = RawConfig::parse(
        r#"
            [[listeners]]
            kind = "tcp-static"
            bind = "127.0.0.1:9000"
            upstream = "example.test:9001"
        "#,
    )
    .unwrap();

    let compiled = raw.validate().unwrap().compile().unwrap();
    assert_eq!(compiled.listeners().len(), 1);
    assert_eq!(compiled.runtime().ui, UiMode::Tui);
    assert_eq!(compiled.runtime().enforcement, EnforcementMode::Enforce);
    assert_eq!(compiled.runtime().hooks, HookMode::Interactive);
    assert!(matches!(compiled.tls(), TlsConfig::Tunnel));
    assert_eq!(compiled.audit().path, std::path::PathBuf::from("."));
    assert_eq!(compiled.limits().ui_content_bytes, 64 * 1_024);
    assert_eq!(compiled.limits().ui_retained_rows, 128);
}

#[test]
fn non_loopback_listener_requires_explicit_opt_in() {
    let error = RawConfig::parse(
        r#"
            [[listeners]]
            kind = "http-forward"
            bind = "0.0.0.0:8080"
        "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();

    assert!(matches!(
        error,
        ConfigError::Validation(ValidationError::NonLoopbackBindRequiresOptIn { .. })
    ));
}

#[test]
fn non_loopback_socks_listener_requires_authentication() {
    let error = RawConfig::parse(
        r#"
            [safety]
            allow_non_loopback = true

            [[listeners]]
            kind = "socks5"
            bind = "0.0.0.0:1080"
        "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();

    assert!(matches!(
        error,
        ConfigError::Validation(ValidationError::RemoteSocksListenerRequiresAuthentication { .. })
    ));
}

#[test]
fn explicitly_exposed_http_listener_requires_authentication() {
    let error = RawConfig::parse(
        r#"
            [safety]
            allow_non_loopback = true

            [[listeners]]
            kind = "http-forward"
            bind = "0.0.0.0:8080"
        "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();

    assert!(matches!(
        error,
        ConfigError::Validation(ValidationError::RemoteHttpListenerRequiresAuthentication { .. })
    ));
}

#[test]
fn authenticated_non_loopback_http_listener_compiles() {
    let compiled = RawConfig::parse(
        r#"
            [safety]
            allow_non_loopback = true

            [[listeners]]
            kind = "http-forward"
            bind = "0.0.0.0:8080"

            [listeners.authentication]
            realm = "Freja"
            credential_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "#,
    )
    .unwrap()
    .validate()
    .unwrap()
    .compile()
    .unwrap();

    assert!(matches!(
        compiled.listeners(),
        [ListenerSpec::HttpForward(_)]
    ));
}

#[test]
fn authenticated_non_loopback_socks_listener_compiles() {
    let compiled = RawConfig::parse(
        r#"
            [safety]
            allow_non_loopback = true

            [[listeners]]
            kind = "socks5"
            bind = "0.0.0.0:1080"

            [listeners.authentication]
            credential_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "#,
    )
    .unwrap()
    .validate()
    .unwrap()
    .compile()
    .unwrap();

    assert!(matches!(compiled.listeners(), [ListenerSpec::Socks5(_)]));
}

#[test]
fn requested_stage_tcp_detour_rule_compiles() {
    let compiled = RawConfig::parse(
        r#"
            [policy]
            generation = 8
            default_action = "allow"

            [[policy.rules]]
            id = "detour-legacy-tcp"
            matcher = { kind = "all", value = [
              { kind = "protocol", value = "tcp" },
              { kind = "destination-port", value = { start = 9001, end = 9001 } },
            ] }
            action = { detour = { host = "127.0.0.1", port = 9002 } }

            [[listeners]]
            kind = "tcp-static"
            bind = "127.0.0.1:9000"
            upstream = "127.0.0.1:9001"
        "#,
    )
    .unwrap()
    .validate()
    .unwrap()
    .compile()
    .unwrap();

    assert_eq!(compiled.policy().generation().get(), 8);
}

#[test]
fn interactive_hooks_require_tui() {
    let error = RawConfig::parse(
        r#"
            [runtime]
            ui = "headless"
            hooks = "interactive"

            [[listeners]]
            kind = "http-forward"
            bind = "127.0.0.1:8080"
        "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();

    assert!(matches!(
        error,
        ConfigError::Validation(ValidationError::InteractiveHooksRequireTui)
    ));
}

#[test]
fn tui_rows_must_cover_every_paused_flow() {
    let error = RawConfig::parse(
        r#"
            [limits]
            paused_flows = 4
            ui_retained_rows = 3

            [[listeners]]
            kind = "http-forward"
            bind = "127.0.0.1:8080"
        "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();

    assert!(matches!(
        error,
        ConfigError::Validation(ValidationError::UiRowsBelowPausedFlows { .. })
    ));
}

#[test]
fn interactive_tui_must_retain_the_full_bounded_request() {
    let error = RawConfig::parse(
        r#"
            [runtime]
            ui = "tui"
            hooks = "interactive"

            [limits]
            body_prefix_bytes = 1024
            ui_content_bytes = 512

            [[listeners]]
            kind = "http-forward"
            bind = "127.0.0.1:8080"
        "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();

    assert!(matches!(
        error,
        ConfigError::Validation(ValidationError::UiContentBelowBodyLimit { .. })
    ));
}

#[test]
fn combined_wire_capture_limit_must_not_overflow() {
    let mut raw = RawConfig::parse(
        r#"
            [[listeners]]
            kind = "http-forward"
            bind = "127.0.0.1:8080"
        "#,
    )
    .unwrap();
    raw.limits.header_bytes = usize::MAX;
    raw.limits.ui_content_bytes = 1;

    let error = raw.validate().unwrap_err();

    assert!(matches!(
        error,
        ConfigError::Validation(ValidationError::WireCaptureLimitOverflow)
    ));
}

#[test]
fn resource_limits_must_be_nonzero() {
    let error = RawConfig::parse(
        r#"
            [limits]
            connections = 0

            [[listeners]]
            kind = "http-forward"
            bind = "127.0.0.1:8080"
        "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();

    assert!(matches!(
        error,
        ConfigError::Validation(ValidationError::ZeroLimit {
            name: "connections"
        })
    ));
}

#[test]
fn audit_checkpoint_interval_must_be_nonzero_when_signing() {
    let error = RawConfig::parse(
        r#"
            [audit]
            checkpoint_signing_key = "audit-seed.hex"
            checkpoint_interval = 0

            [[listeners]]
            kind = "http-forward"
            bind = "127.0.0.1:8080"
        "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();

    assert!(matches!(
        error,
        ConfigError::Validation(ValidationError::ZeroLimit {
            name: "audit.checkpoint_interval"
        })
    ));
}

#[test]
fn inspection_pattern_must_fit_the_body_prefix_budget() {
    let error = RawConfig::parse(
        r#"
            [limits]
            body_prefix_bytes = 3

            [inspection]

            [[inspection.patterns]]
            detector_id = "oversized"
            rule_id = "deny-oversized"
            pattern_hex = "00010203"

            [[listeners]]
            kind = "http-forward"
            bind = "127.0.0.1:8080"
        "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();

    assert!(matches!(
        error,
        ConfigError::Validation(ValidationError::InspectionPatternExceedsBodyLimit {
            pattern_bytes: 4,
            body_prefix_bytes: 3,
            ..
        })
    ));
}

#[test]
fn tls_interception_requires_explicit_ca_inputs() {
    let error = RawConfig::parse(
        r#"
            [tls]
            handling = "intercept"

            [[listeners]]
            kind = "http-forward"
            bind = "127.0.0.1:8080"
        "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();

    assert!(matches!(
        error,
        ConfigError::Validation(ValidationError::TlsInterceptionRequiresCaCertificate)
    ));
}

#[test]
fn tls_interception_requires_a_nonempty_host_allowlist() {
    let error = RawConfig::parse(
        r#"
            [tls]
            handling = "intercept"
            ca_certificate = "ca.pem"
            ca_private_key = "ca-key.pem"

            [[listeners]]
            kind = "http-forward"
            bind = "127.0.0.1:8080"
        "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();

    assert!(matches!(
        error,
        ConfigError::Validation(ValidationError::TlsInterceptionRequiresAllowlist)
    ));
}
