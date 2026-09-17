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
fn runtime_config_is_explicit_local_and_rejects_central_configuration() {
    use rss_identity_app::config::RuntimeConfig;
    let example: serde_json::Value =
        serde_json::from_str(include_str!("../../../deployment/example.json")).unwrap();
    let parsed: RuntimeConfig = serde_json::from_value(example.clone()).unwrap();
    parsed.validate().unwrap();
    assert!(parsed.oidc.is_none());
    let mut missing_manager = example.clone();
    missing_manager["storage"]["tenants"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("33333333-3333-4333-8333-333333333333"));
    assert!(
        serde_json::from_value::<RuntimeConfig>(missing_manager)
            .unwrap()
            .validate()
            .is_err()
    );
    let mut complete = example.clone();
    complete["storage"]["tenants"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("33333333-3333-4333-8333-333333333333"));
    complete["bootstrapAccounts"].as_array_mut().unwrap().push(serde_json::json!({"tenantId":"33333333-3333-4333-8333-333333333333", "principalId":"44444444-4444-4444-8444-444444444444"}));
    assert!(
        serde_json::from_value::<RuntimeConfig>(complete.clone())
            .unwrap()
            .validate()
            .is_ok()
    );
    complete["bootstrapAccounts"][1] = complete["bootstrapAccounts"][0].clone();
    assert!(
        serde_json::from_value::<RuntimeConfig>(complete)
            .unwrap()
            .validate()
            .is_err()
    );
    for key in [
        "format_version",
        "bootstrap",
        "public_origin",
        "maintenance_password_file",
        "private_gateway",
        "hydra",
        "system_tenant",
        "runtime_source",
    ] {
        let mut value = example.clone();
        value[key] = serde_json::json!("retired");
        assert!(serde_json::from_value::<RuntimeConfig>(value).is_err());
    }
    for (key, value) in [
        ("formatVersion", serde_json::json!(2)),
        (
            "instanceId",
            serde_json::json!("00000000-0000-0000-0000-000000000000"),
        ),
        ("publicGateway", serde_json::json!("0.0.0.0")),
    ] {
        let mut bad = example.clone();
        bad[key] = value;
        assert!(
            serde_json::from_value::<RuntimeConfig>(bad)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    let mut wrong_tenant = example.clone();
    wrong_tenant["bootstrapAccounts"][0]["tenantId"] =
        serde_json::json!("22222222-2222-4222-8222-222222222222");
    assert!(
        serde_json::from_value::<RuntimeConfig>(wrong_tenant)
            .unwrap()
            .validate()
            .is_err()
    );
}

#[test]
fn group_facts_policy_is_required_only_when_oidc_is_configured() {
    use rss_identity_app::config::RuntimeConfig;
    use rss_identity_core::groups::GroupFactsMaxAge;
    let mut example: serde_json::Value =
        serde_json::from_str(include_str!("../../../deployment/example.json")).unwrap();
    example["oidc"] = serde_json::json!({"groupFactsMaxAgeSeconds":300,"assuranceProfiles":[],"stateKeyFile":"/host/state.key","credentialKeyring":{"activeKeyId":"host","keys":[{"keyId":"host","path":"/host/credential.key"}]},"returnTargets":{"home":"https://identity.example.test/"}});
    for value in [
        GroupFactsMaxAge::MIN_SECONDS - 1,
        GroupFactsMaxAge::MIN_SECONDS,
        GroupFactsMaxAge::MAX_SECONDS,
        GroupFactsMaxAge::MAX_SECONDS + 1,
    ] {
        let mut runtime = example.clone();
        runtime["oidc"]["groupFactsMaxAgeSeconds"] = value.into();
        assert_eq!(
            serde_json::from_value::<RuntimeConfig>(runtime)
                .unwrap()
                .validate()
                .is_ok(),
            GroupFactsMaxAge::new(value).is_ok()
        );
    }
    example["oidc"]
        .as_object_mut()
        .unwrap()
        .remove("groupFactsMaxAgeSeconds");
    assert!(serde_json::from_value::<RuntimeConfig>(example).is_err());
}
