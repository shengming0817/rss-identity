#[test]
fn configuration_and_ca_reads_are_bounded() {
    use rss_identity_app::read_public_file;
    let path = std::env::temp_dir().join(format!("identity-input-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, [0_u8; 128]).unwrap();
    assert!(read_public_file(&path, 127).is_err());
    assert_eq!(read_public_file(&path, 128).unwrap().len(), 128);
    std::fs::remove_file(&path).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert!(read_public_file(&path, 16384).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn password_files_are_private_regular_and_bounded() {
    use rss_identity_app::read_secret;
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = std::env::temp_dir().join(format!("identity-files-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("password");
    std::fs::write(&file, "a private password with spaces\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_secret(&file).unwrap().ends_with('\n'));
    let link = dir.join("link");
    symlink(&file, &link).unwrap();
    assert!(read_secret(&link).is_err());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(read_secret(&file).is_err());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&file, vec![b'x'; 4097]).unwrap();
    assert!(read_secret(&file).is_err());
    assert!(read_secret(&dir).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn binary_help_uses_identity_name() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_identity-admin"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.starts_with("Usage: identity-admin "));
}

#[test]
fn runtime_config_is_strict_and_contains_no_maintenance_secret_slot() {
    use rss_identity_app::config::RuntimeConfig;
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../../deployment/example.json")).unwrap();
    let mut runtime = v["runtime"].clone();
    let parsed: RuntimeConfig = serde_json::from_value(runtime.clone()).unwrap();
    parsed.validate().unwrap();
    runtime["maintenance_password_file"] = serde_json::json!("/unavailable");
    assert!(serde_json::from_value::<RuntimeConfig>(runtime).is_err());
    for (key, bad) in [
        ("format_version", serde_json::json!(0)),
        ("public_gateway", v["runtime"]["private_gateway"].clone()),
    ] {
        let mut runtime = v["runtime"].clone();
        runtime[key] = bad;
        assert!(
            serde_json::from_value::<RuntimeConfig>(runtime)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}

#[test]
fn group_facts_policy_is_required_and_deployment_scoped() {
    use rss_identity_app::config::RuntimeConfig;
    let example: serde_json::Value =
        serde_json::from_str(include_str!("../../../deployment/example.json")).unwrap();
    for value in [1, 300, 0, 301, -1] {
        let mut runtime = example["runtime"].clone();
        runtime["oidc"]["group_facts_max_age_seconds"] = value.into();
        let config: RuntimeConfig = serde_json::from_value(runtime).unwrap();
        assert_eq!(config.validate().is_ok(), (1..=300).contains(&value));
    }
    let mut runtime = example["runtime"].clone();
    runtime["oidc"]
        .as_object_mut()
        .unwrap()
        .remove("group_facts_max_age_seconds");
    assert!(serde_json::from_value::<RuntimeConfig>(runtime).is_err());
}
