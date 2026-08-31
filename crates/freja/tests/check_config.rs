use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

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
