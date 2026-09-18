//! Actual binary preflight must reject nested drift without opening the configured database.
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

fn check(binary: &str, path: &Path, value: &Value, valid: bool) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    let output = Command::new(binary)
        .arg("--check-config")
        .arg(path)
        .output()
        .unwrap();
    assert_eq!(
        output.status.success(),
        valid,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn candidate_binaries_preflight_closed_nested_contracts_offline() {
    let root = std::env::temp_dir().join(format!("identity-preflight-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    let cert = root.join("ca.pem");
    assert!(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=preflight"
            ])
            .arg("-keyout")
            .arg(root.join("ca.key"))
            .arg("-out")
            .arg(&cert)
            .output()
            .unwrap()
            .status
            .success()
    );
    for (name, value) in [
        ("password", "private-fixture-password".to_owned()),
        ("state", "11".repeat(32)),
        ("key", "22".repeat(32)),
    ] {
        let path = root.join(name);
        fs::write(&path, value).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut runtime: Value =
        serde_json::from_str(include_str!("../../../deployment/example.json")).unwrap();
    runtime["database"]["passwordFile"] = json!(root.join("password"));
    runtime["database"]["caFile"] = json!(cert);
    runtime["database"]["port"] = json!(1);
    runtime["oidc"] = json!({"groupFactsMaxAgeSeconds":300,"assuranceProfiles":[{"tenantId":runtime["storage"]["tenants"][0],"issuer":"https://idp.example.test","clientId":"fixture","keycloakTotp":false}],"stateKeyFile":root.join("state"),"credentialKeyring":{"activeKeyId":"active","keys":[{"keyId":"active","path":root.join("key")}]},"returnTargets":{"resume":"https://identity.example.test/auth/resume"}});
    let path = root.join("config.json");
    let server = env!("CARGO_BIN_EXE_identity-server");
    check(server, &path, &runtime, true);
    for pointer in [
        "/database",
        "/storage",
        "/budgets",
        "/bootstrapAccounts/0",
        "/oidc",
        "/oidc/assuranceProfiles/0",
        "/oidc/credentialKeyring",
        "/oidc/credentialKeyring/keys/0",
    ] {
        let mut bad = runtime.clone();
        bad.pointer_mut(pointer).unwrap()["typo"] = json!(true);
        check(server, &path, &bad, false);
    }
    let mut bad = runtime.clone();
    bad["oidc"]["credentialKeyring"]["activeKeyId"] = json!("absent");
    check(server, &path, &bad, false);
    let common = json!({"formatVersion":runtime["formatVersion"],"instanceId":runtime["instanceId"],"storage":runtime["storage"],"database":runtime["database"]});
    let mut maintenance = common.clone();
    maintenance["bootstrapAccounts"] = runtime["bootstrapAccounts"].clone();
    check(
        env!("CARGO_BIN_EXE_identity-admin"),
        &path,
        &maintenance,
        true,
    );
    maintenance["database"]["typo"] = json!(true);
    check(
        env!("CARGO_BIN_EXE_identity-admin"),
        &path,
        &maintenance,
        false,
    );
    let mut migration = common;
    migration["runtimeRole"] = json!("runtime");
    migration["maintenanceRole"] = json!("maintenance");
    check(
        env!("CARGO_BIN_EXE_identity-migrate"),
        &path,
        &migration,
        true,
    );
    migration["runtimeRole"] = json!("x".repeat(64));
    check(
        env!("CARGO_BIN_EXE_identity-migrate"),
        &path,
        &migration,
        false,
    );
}
