//! Production transport + real HTTPS private Keycloak. No test-support or reference host.
use crate::{HttpOidc, PrivateProviderAccess};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Client, Url};
use rss_identity_core::{assurance::AuthenticationMode, federation::*};
use rss_request_context::TenantId;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

struct ControlledDns {
    addresses: Vec<SocketAddr>,
    calls: Arc<AtomicUsize>,
}
impl Resolve for ControlledDns {
    fn resolve(&self, name: Name) -> Resolving {
        assert_eq!(name.as_str(), "private-idp.invalid");
        self.calls.fetch_add(1, Ordering::SeqCst);
        let addresses = self.addresses.clone();
        Box::pin(async move { Ok(Box::new(addresses.into_iter()) as Addrs) })
    }
}
fn controlled(adapter: &mut HttpOidc, addresses: Vec<SocketAddr>, calls: Arc<AtomicUsize>) {
    adapter.lookup = Some(Arc::new(ControlledDns { addresses, calls }));
}

#[tokio::test]
#[ignore = "requires hack/providers.py private-oidc"]
async fn real_private_provider_transport() -> anyhow::Result<()> {
    let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111")?;
    let issuer = std::env::var("IDENTITY_TEST_FEDERATED_ISSUER")?;
    let host = Url::parse(&issuer)?.host_str().unwrap().to_owned();
    assert_eq!(host, "private-idp.invalid");
    let address: std::net::IpAddr = std::env::var("IDENTITY_TEST_PRIVATE_ADDRESS")?.parse()?;
    let endpoint = SocketAddr::new(address, 0);
    let calls = Arc::new(AtomicUsize::new(0));
    let ca = std::fs::read_to_string(std::env::var("IDENTITY_TEST_FEDERATED_CA")?)?;
    let config: ProviderSettings = ProviderSettingsInput {
        issuer: issuer.clone(),
        client_id: "identity-test".into(),
        redirect_uri: "https://identity.example.test/api/v2/oidc/callback".into(),
        scopes: vec!["openid".into()],
        claims: ClaimMapping {
            email: None,
            groups: None,
            department_snapshot: None,
        },
        jit: false,
    }
    .try_into()?;
    let credentials = ProviderCredentials::new("fixture-secret".into(), Some(ca.clone()))?;
    let mut adapter = HttpOidc::new(
        vec![],
        vec![PrivateProviderAccess {
            tenant,
            issuer: issuer.clone(),
            client_id: "identity-test".into(),
            cidrs: vec![format!("{address}/32").parse()?],
        }],
    )?;
    controlled(&mut adapter, vec![endpoint], calls.clone());
    assert!(
        adapter
            .test(tenant, &config, &credentials)
            .await?
            .tls_verified
    );
    let discovery_calls = calls.load(Ordering::SeqCst);
    assert!(
        discovery_calls > 0,
        "real discovery must traverse the production resolver"
    );
    let mut denied = HttpOidc::new(vec![], vec![])?;
    controlled(&mut denied, vec![endpoint], calls.clone());
    assert!(denied.test(tenant, &config, &credentials).await.is_err());
    controlled(
        &mut adapter,
        vec![endpoint, "169.254.169.254:0".parse()?],
        calls.clone(),
    );
    assert!(adapter.test(tenant, &config, &credentials).await.is_err());
    controlled(&mut adapter, vec![endpoint], calls.clone());
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
        .resolve(&host, endpoint)
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
    let before_exchange = calls.load(Ordering::SeqCst);
    let claims = adapter
        .exchange(
            tenant,
            &config,
            &credentials,
            material,
            query["code"].clone().into(),
        )
        .await?;
    assert!(
        calls.load(Ordering::SeqCst) > before_exchange,
        "code exchange must traverse the production resolver"
    );
    assert_eq!(claims.issuer, issuer);
    assert!(!claims.subject.is_empty());
    Ok(())
}
