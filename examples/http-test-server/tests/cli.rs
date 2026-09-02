//! Command-line safety checks for the Axum test origin.

use std::process::Command;

#[test]
fn non_loopback_bind_requires_explicit_opt_in() {
    let output = Command::new(env!("CARGO_BIN_EXE_freja-http-test-server"))
        .args(["--bind", "0.0.0.0:0"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("pass --allow-non-loopback to opt in")
    );
}
