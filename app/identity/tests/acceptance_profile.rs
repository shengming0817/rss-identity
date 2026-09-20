#[test]
fn profile_is_available_offline_from_the_actual_binary() {
    let dir = std::env::temp_dir().join(format!("identity-profile-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_identity-server"))
        .arg("--acceptance-profile")
        .env_clear()
        .current_dir(&dir)
        .output()
        .unwrap();
    std::fs::remove_dir(dir).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "formatVersion": 1, "schemaVersion": 11,
            "session": {"idleSeconds": 900, "absoluteSeconds": 14400},
            "attempts": {"sourceLimit": 30, "sourceSeconds": 300, "scopeLimit": 5, "scopeSeconds": 900},
            "kdfConcurrency": 4, "mfaMaxAgeSeconds": 300
        })
    );
}
