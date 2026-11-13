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
fn runtime_config_validates_host_policy_and_coordinates() {
    use rss_identity_app::config::RuntimeConfig;
    let example: serde_json::Value =
        serde_json::from_str(include_str!("../../../deployment/example.json")).unwrap();
    let parsed: RuntimeConfig = serde_json::from_value(example.clone()).unwrap();
    parsed.validate().unwrap();
    assert!(parsed.oidc.is_none());
    let mut complete = example.clone();
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
}

#[test]
fn group_facts_policy_is_required_only_when_oidc_is_configured() {
    use rss_identity_app::config::RuntimeConfig;
    use rss_identity_core::groups::GroupFactsMaxAge;
    let mut example: serde_json::Value =
        serde_json::from_str(include_str!("../../../deployment/example.json")).unwrap();
    example["oidc"] = serde_json::json!({"requestSeconds":5,"connectSeconds":3,"maxResponseBytes":1048576,"maxJwksKeys":128,"groupFactsMaxAgeSeconds":300,"privateProviders":[],"assuranceProfiles":[],"stateKeyFile":"/host/state.key","credentialKeyring":{"activeKeyId":"host","keys":[{"keyId":"host","path":"/host/credential.key"}]},"returnTargets":{"home":"https://identity.example.test/"}});
    for value in [0, 1, 3600, i64::MAX] {
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

#[test]
fn migration_descriptor_includes_all_installed_schema_owners() {
    use sha2::{Digest, Sha256};
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_identity-migrate"))
        .arg("--describe")
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["audit_sql_sha256"],
        hex::encode(Sha256::digest(rss_audit_postgres::MIGRATION_SQL))
    );
}

#[test]
fn configured_directories_load_at_the_supported_capacity() {
    use rss_identity_app::config::{CONFIG_MAX_BYTES, RuntimeConfig};
    use serde_json::json;
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../../../deployment/example.json")).unwrap();
    let tenants: Vec<_> = (0..1024)
        .map(|_| uuid::Uuid::new_v4().to_string())
        .collect();
    let issuer = format!("https://idp.example.test/{}", "a".repeat(2000));
    value["bootstrapAccounts"] = json!(
        tenants
            .iter()
            .map(|tenant| json!({"tenantId":tenant,"principalId":uuid::Uuid::new_v4()}))
            .collect::<Vec<_>>()
    );
    value["oidc"] = json!({"requestSeconds":5,"connectSeconds":3,"maxResponseBytes":1048576,"maxJwksKeys":128,
        "groupFactsMaxAgeSeconds":300,"stateKeyFile":"/host/state","credentialKeyring":{"activeKeyId":"key","keys":[{"keyId":"key","path":"/host/key"}]},"returnTargets":{"resume":"https://identity.example.test/auth/resume"},
        "assuranceProfiles":tenants.iter().map(|tenant|json!({"tenantId":tenant,"issuer":issuer,"clientId":"c".repeat(256),"keycloakTotp":false})).collect::<Vec<_>>(),
        "privateProviders":tenants.iter().map(|tenant|json!({"tenantId":tenant,"issuer":issuer,"clientId":"c".repeat(256),"cidrs":["10.42.0.0/16"]})).collect::<Vec<_>>()});
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(bytes.len() < CONFIG_MAX_BYTES);
    let path = std::env::temp_dir().join(format!("identity-directories-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, bytes).unwrap();
    let config = RuntimeConfig::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    let oidc = config.oidc.as_ref().unwrap();
    let profiles = oidc
        .assurance_profiles
        .iter()
        .map(|p| rss_identity_oidc::TrustedAssuranceProfile {
            tenant: rss_request_context::TenantId::parse(&p.tenant_id).unwrap(),
            issuer: p.issuer.clone(),
            client_id: p.client_id.clone(),
            keycloak_totp: p.keycloak_totp,
        })
        .collect();
    assert!(
        rss_identity_oidc::HttpOidc::new(
            profiles,
            oidc.private_access().unwrap(),
            oidc.transport().unwrap()
        )
        .is_ok()
    );
}
