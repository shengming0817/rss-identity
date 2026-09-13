#![cfg(feature = "test-support")]
use reqwest::{Client, Response, Url};
use rss_identity_core::federation::*;
use rss_identity_oidc::{HttpOidc, TrustedAssuranceProfile};
use std::time::Duration;
use zeroize::Zeroizing;
const REDIRECT: &str = "http://127.0.0.1:19999/auth/callback";
fn location(response: &Response) -> anyhow::Result<Url> {
    Ok(Url::parse(
        response
            .headers()
            .get("location")
            .ok_or_else(|| anyhow::anyhow!("missing location, status {}", response.status()))?
            .to_str()?,
    )?)
}
fn query(url: &Url, name: &str) -> anyhow::Result<String> {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| anyhow::anyhow!("missing callback parameter {name}"))
}
fn browser() -> anyhow::Result<Client> {
    Ok(Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?)
}
fn provider(issuer: &str) -> anyhow::Result<(HttpOidc, ProviderSettings)> {
    let p = HttpOidc::for_loopback_test(vec![TrustedAssuranceProfile {
        keycloak_totp: false,
        tenant: tenant(),
        issuer: issuer.into(),
        client_id: "identity-test".into(),
    }])?;
    let c = (rss_identity_core::federation::ProviderSettingsInput {
        issuer: issuer.into(),
        client_id: "identity-test".into(),

        redirect_uri: REDIRECT.into(),
        scopes: vec!["openid".into(), "profile".into()],
        claims: ClaimMapping {
            email: None,
            groups: None,
        },
        jit: false,
    })
    .try_into()
    .unwrap();
    Ok((p, c))
}

async fn keycloak_login(url: Url) -> anyhow::Result<Url> {
    let browser = browser()?;
    let response = browser.get(url).send().await?.error_for_status()?;
    let html = response.text().await?;
    let action = {
        let dom = scraper::Html::parse_document(&html);
        let selector = scraper::Selector::parse("form#kc-form-login").unwrap();
        dom.select(&selector)
            .next()
            .and_then(|f| f.value().attr("action"))
            .ok_or_else(|| anyhow::anyhow!("missing Keycloak login form"))?
            .to_owned()
    };
    let response = browser
        .post(action)
        .form(&[
            ("username", "alice"),
            ("password", "fixture-password"),
            ("credentialId", ""),
        ])
        .send()
        .await?;
    location(&response)
}
async fn prepare(p: &HttpOidc, c: &ProviderSettings) -> anyhow::Result<(Url, ProtocolMaterial)> {
    let material = ProtocolMaterial::new(random_secret()?.to_string())?;
    let url = p
        .prepare(
            tenant(),
            c,
            &rss_identity_core::federation::ProviderCredentials::new("fixture-secret".into(), None)
                .unwrap(),
            &material,
            rss_identity_core::assurance::AuthenticationMode::Login,
        )
        .await?;
    Ok((Url::parse(&url)?, material))
}
async fn flow(issuer: &str) -> anyhow::Result<()> {
    let (p, c) = provider(issuer)?;
    let (url, material) = prepare(&p, &c).await?;
    assert_eq!(query(&url, "code_challenge_method")?, "S256");
    let cb = keycloak_login(url).await?;
    assert_eq!(query(&cb, "state")?, material.state.as_str());
    let code = query(&cb, "code")?;
    let claims = p
        .exchange(
            tenant(),
            &c,
            &rss_identity_core::federation::ProviderCredentials::new("fixture-secret".into(), None)
                .unwrap(),
            material,
            Zeroizing::new(code.clone()),
        )
        .await?;
    assert_eq!(claims.issuer, issuer);
    assert!(!claims.subject.is_empty());
    let (_, material) = prepare(&p, &c).await?;
    assert!(
        p.exchange(
            tenant(),
            &c,
            &rss_identity_core::federation::ProviderCredentials::new("fixture-secret".into(), None)
                .unwrap(),
            material,
            Zeroizing::new(code)
        )
        .await
        .is_err()
    );
    for (field, value, error) in [
        ("nonce", "wrong-nonce", FederationError::Claims),
        (
            "code_challenge",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            FederationError::provider(ProviderStage::Exchange, ProviderReason::CodeRejected),
        ),
    ] {
        let (mut url, material) = prepare(&p, &c).await?;
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .filter(|(k, _)| k != field)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        url.query_pairs_mut()
            .clear()
            .extend_pairs(pairs)
            .append_pair(field, value);
        let cb = keycloak_login(url).await?;
        assert!(
            matches!(p.exchange(tenant(), &c, &rss_identity_core::federation::ProviderCredentials::new("fixture-secret".into(), None).unwrap(), material, Zeroizing::new(query(&cb,"code")?)).await,Err(e) if e==error)
        );
    }
    let (mut url, _) = prepare(&p, &c).await?;
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != "redirect_uri")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(pairs)
        .append_pair("redirect_uri", "http://127.0.0.1:19999/wrong");
    let response = browser()?.get(url).send().await?;
    if let Ok(loc) = location(&response) {
        assert!(loc.query_pairs().all(|(k, _)| k != "code"));
        assert_ne!(loc.path(), "/wrong");
    } else {
        assert!(response.status().is_client_error());
    }
    Ok(())
}
#[tokio::test]
#[ignore = "requires isolated Keycloak; make test-oidc"]
async fn real_provider_flows() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(120), async {
        flow(&std::env::var("IDENTITY_TEST_KEYCLOAK_ISSUER")?).await?;
        let (p, c) = provider("http://127.0.0.1:1")?;
        assert!(
            p.test(
                tenant(),
                &c,
                &rss_identity_core::federation::ProviderCredentials::new(
                    "fixture-secret".into(),
                    None
                )
                .unwrap()
            )
            .await
            .is_err()
        );
        Ok::<(), anyhow::Error>(())
    })
    .await?
}

fn tenant() -> rss_request_context::TenantId {
    rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap()
}
