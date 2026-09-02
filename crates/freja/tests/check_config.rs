//! Integration tests for the CLI configuration-check command.

use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use freja_config::CompiledConfig;
use freja_domain::{EnforcementMode, HookMode, UiMode};

struct TestConfig {
    path: PathBuf,
}

impl TestConfig {
    fn new(contents: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "freja-check-config-{}-{nanos}.toml",
            std::process::id()
        ));
        fs::write(&path, contents).unwrap();
        Self { path }
    }
}

impl Drop for TestConfig {
    fn drop(&mut self) {
        let _result = fs::remove_file(&self.path);
    }
}

#[test]
fn check_config_reports_compiled_listener_and_generation() {
    let config = TestConfig::new(
        r#"
            [policy]
            generation = 23

            [[listeners]]
            kind = "tcp-static"
            bind = "127.0.0.1:9000"
            upstream = "example.test:9001"
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_freja"))
        .args(["check-config", "--config"])
        .arg(&config.path)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("configuration valid: 1 listener(s), policy generation 23")
    );
}

#[test]
fn check_config_uses_the_built_in_configuration_when_path_is_omitted() {
    let output = Command::new(env!("CARGO_BIN_EXE_freja"))
        .arg("check-config")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("configuration valid: 1 listener(s), policy generation 1")
    );
}

#[test]
fn check_config_rejects_implicit_remote_exposure() {
    let config = TestConfig::new(
        r#"
            [[listeners]]
            kind = "http-forward"
            bind = "0.0.0.0:8080"
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_freja"))
        .args(["check-config", "--config"])
        .arg(&config.path)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("allow_non_loopback"));
}

#[test]
fn example_config_templates_pass_check_config() {
    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let templates = [
        "examples/config/headless/freja.toml",
        "examples/config/headless/freja.enforce.toml",
        "examples/config/tui/freja.toml",
        "examples/config/tui/freja.interactive.toml",
    ];

    for template in templates {
        let path = repository_root.join(template);
        let output = Command::new(env!("CARGO_BIN_EXE_freja"))
            .args(["check-config", "--config"])
            .arg(&path)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{template} failed validation: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn standard_examples_select_the_intended_runtime_profiles() {
    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let tui = CompiledConfig::load(repository_root.join("examples/config/tui/freja.toml")).unwrap();
    assert_eq!(tui.runtime().ui, UiMode::Tui);
    assert_eq!(tui.runtime().enforcement, EnforcementMode::Enforce);
    assert_eq!(tui.runtime().hooks, HookMode::Interactive);

    let headless =
        CompiledConfig::load(repository_root.join("examples/config/headless/freja.toml")).unwrap();
    assert_eq!(headless.runtime().ui, UiMode::Headless);
    assert_eq!(headless.runtime().enforcement, EnforcementMode::Enforce);
    assert_eq!(headless.runtime().hooks, HookMode::Disabled);
}
