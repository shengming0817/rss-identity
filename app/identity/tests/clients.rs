//! Persistent Hydra registration/authentication seam; no Identity server or browser.
use rss_identity_app::{clients::LocalHydra, config::RuntimeConfig};
use serde_json::{Value, json};

#[tokio::test]
#[ignore = "requires make test-clients"]
async fn clients_are_created_verified_and_drift_is_refused() -> anyhow::Result<()> {
    let admin: u16 = std::env::var("IDENTITY_TEST_CLIENT_ADMIN_PORT")?.parse()?;
    let public: u16 = std::env::var("IDENTITY_TEST_CLIENT_PUBLIC_PORT")?.parse()?;
    let secret_file = std::env::var("IDENTITY_TEST_CLIENT_SECRET")?;
    let mut value: Value = serde_json::from_str(include_str!("../../../deployment/example.json"))?;
    value = value["runtime"].clone();
    value["hydra"]["clients"][0]["client_id"] = json!("registration-fixture");
    value["hydra"]["clients"][0]["oidc_secret_file"] = json!(secret_file);
    let config = || serde_json::from_value::<RuntimeConfig>(value.clone()).unwrap();
    let operator = LocalHydra::new(admin, public)?;
    assert_eq!(operator.install(&config()).await?, 1);
    assert_eq!(operator.install(&config()).await?, 1);
    let http = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{admin}/admin/clients/registration-fixture");
    let original: Value = http
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    for (field, drift) in [
        ("redirect_uris", json!(["https://evil.test/callback"])),
        (
            "grant_types",
            json!(["authorization_code", "client_credentials"]),
        ),
        (
            "authorization_code_grant_access_token_lifespan",
            json!("42s"),
        ),
        ("access_token_strategy", json!("jwt")),
        (
            "client_secret",
            json!("different-fixture-credential-32bytes"),
        ),
    ] {
        let mut changed = original.clone();
        changed[field] = drift.clone();
        http.put(&url)
            .json(&changed)
            .send()
            .await?
            .error_for_status()?;
        assert!(
            operator.install(&config()).await.is_err(),
            "must reject {field}"
        );
        if field != "client_secret" {
            let observed: Value = http
                .get(&url)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            assert_eq!(observed[field], drift, "must not overwrite drift");
        }
        let mut restore = original.clone();
        restore["client_secret"] = json!(std::fs::read_to_string(&secret_file)?);
        http.put(&url)
            .json(&restore)
            .send()
            .await?
            .error_for_status()?;
        assert_eq!(operator.install(&config()).await?, 1);
    }
    // A fresh operator (and a real persistent provider) must prove the stored credential again.
    assert_eq!(LocalHydra::new(admin, public)?.install(&config()).await?, 1);
    Ok(())
}
