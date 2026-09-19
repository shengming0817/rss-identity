//! Production transport + real HTTPS private Keycloak. No test-support or reference host.
use reqwest::{Client, Url};
use rss_identity_core::{assurance::AuthenticationMode, federation::*};
use rss_identity_oidc::{HttpOidc, PrivateProviderAccess};
use rss_request_context::TenantId;
use std::time::Duration;

#[tokio::test]
#[ignore = "requires hack/providers.py private-oidc"]
async fn real_private_provider_transport() -> anyhow::Result<()> {
    let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111")?;
    let issuer = std::env::var("IDENTITY_TEST_FEDERATED_ISSUER")?;
    let host = Url::parse(&issuer)?.host_str().unwrap().to_owned();
    let ca = std::fs::read_to_string(std::env::var("IDENTITY_TEST_FEDERATED_CA")?)?;
    let config: ProviderSettings = ProviderSettingsInput {
        issuer: issuer.clone(),
        client_id: "identity-test".into(),
        redirect_uri: "https://identity.example.test/api/v2/oidc/callback".into(),
        scopes: vec!["openid".into()],
        claims: ClaimMapping {
            email: None,
            groups: None,
        },
        jit: false,
    }
    .try_into()?;
    let credentials = ProviderCredentials::new("fixture-secret".into(), Some(ca.clone()))?;
    let adapter = HttpOidc::new(
        vec![],
        vec![PrivateProviderAccess {
            tenant,
            issuer: issuer.clone(),
            client_id: "identity-test".into(),
            cidrs: vec![format!("{host}/32").parse()?],
        }],
    )?;
    assert!(
        adapter
            .test(tenant, &config, &credentials)
            .await?
            .tls_verified
    );
    assert!(
        HttpOidc::new(vec![], vec![])?
            .test(tenant, &config, &credentials)
            .await
            .is_err()
    );
    let other = TenantId::parse("22222222-2222-4222-8222-222222222222")?;
    assert!(adapter.test(other, &config, &credentials).await.is_err());
    let untrusted = ProviderCredentials::new("fixture-secret".into(), None)?;
    assert!(matches!(adapter.test(tenant, &config, &untrusted).await,
        Err(FederationError::Provider(ref failure)) if failure.reason == ProviderReason::TlsRejected));
    let material = ProtocolMaterial::new(random_secret()?.to_string())?;
    let authorize = adapter
        .prepare(
            tenant,
            &config,
            &credentials,
            &material,
            AuthenticationMode::Login,
        )
        .await?;
    let client = Client::builder()
        .no_proxy()
        .cookie_store(true)
        .add_root_certificate(reqwest::Certificate::from_pem(ca.as_bytes())?)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;
    let html = client
        .get(authorize)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let action = {
        let dom = scraper::Html::parse_document(&html);
        dom.select(&scraper::Selector::parse("form#kc-form-login").unwrap())
            .next()
            .and_then(|f| f.value().attr("action"))
            .ok_or_else(|| anyhow::anyhow!("missing login form"))?
            .to_owned()
    };
    let response = client
        .post(action)
        .form(&[
            ("username", "alice"),
            ("password", "fixture-password"),
            ("credentialId", ""),
        ])
        .send()
        .await?;
    anyhow::ensure!(response.status().is_redirection(), "provider login failed");
    let callback = Url::parse(
        response
            .headers()
            .get("location")
            .ok_or_else(|| anyhow::anyhow!("missing callback"))?
            .to_str()?,
    )?;
    let query: std::collections::BTreeMap<String, String> =
        callback.query_pairs().into_owned().collect();
    assert_eq!(query["state"], material.state.as_str());
    let claims = adapter
        .exchange(
            tenant,
            &config,
            &credentials,
            material,
            query["code"].clone().into(),
        )
        .await?;
    assert_eq!(claims.issuer, issuer);
    assert!(!claims.subject.is_empty());
    Ok(())
}
