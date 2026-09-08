#![cfg(feature = "test-support")]
use reqwest::{Client, Response, Url};
use rss_identity_oidc::{OidcError, Provider, ProviderConfig};
use serde_json::{Value, json};
use std::time::Duration;
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
async fn provider(issuer: &str) -> anyhow::Result<Provider> {
    Ok(Provider::discover(ProviderConfig::for_loopback_test(
        issuer,
        "identity-test",
        "fixture-secret",
        REDIRECT,
    )?)
    .await?)
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
async fn hydra_login(url: Url, admin: &str) -> anyhow::Result<Url> {
    // Test-only login/consent fixture. No production authority is implemented by this test.
    let browser = browser()?;
    let login_url = location(&browser.get(url).send().await?)?;
    let challenge = query(&login_url, "login_challenge")?;
    let accepted: Value = browser
        .put(format!("{admin}/admin/oauth2/auth/requests/login/accept"))
        .query(&[("login_challenge", challenge)])
        .json(&json!({"subject":"fixture-principal", "remember":false}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let consent_url = location(
        &browser
            .get(accepted["redirect_to"].as_str().unwrap())
            .send()
            .await?,
    )?;
    let challenge = query(&consent_url, "consent_challenge")?;
    let accepted: Value = browser.put(format!("{admin}/admin/oauth2/auth/requests/consent/accept")).query(&[("consent_challenge",challenge)]).json(&json!({"grant_scope":["openid","profile"],"remember":false,"session":{"id_token":{"tenant_id":"fixture-tenant"}}})).send().await?.error_for_status()?.json().await?;
    location(
        &browser
            .get(accepted["redirect_to"].as_str().unwrap())
            .send()
            .await?,
    )
}
async fn callback(url: Url, admin: Option<&str>) -> anyhow::Result<Url> {
    if let Some(admin) = admin {
        hydra_login(url, admin).await
    } else {
        keycloak_login(url).await
    }
}
async fn flow(issuer: &str, admin: Option<&str>) -> anyhow::Result<()> {
    let p = provider(issuer).await?;
    let (url, attempt) = p.begin();
    assert_eq!(query(&url, "code_challenge_method")?, "S256");
    let cb = callback(url, admin).await?;
    let code = query(&cb, "code")?;
    let state = query(&cb, "state")?;
    let subject = p.finish(attempt, &state, code.clone()).await?;
    assert_eq!(subject.issuer(), issuer);
    assert!(!subject.subject().is_empty());
    // Code replay cannot succeed, even from the same registered client.
    let (url, attempt) = p.begin();
    assert!(matches!(
        p.finish(attempt, &query(&url, "state")?, code).await,
        Err(OidcError::Exchange)
    ));
    let (url, attempt) = p.begin();
    assert!(matches!(
        p.finish(attempt, "wrong-state", "unused".into()).await,
        Err(OidcError::State)
    ));
    // Provider issues a valid signed ID token with a different nonce: adapter must reject it.
    let (_, attempt) = p.begin();
    assert!(matches!(
        p.finish(attempt, &query(&url, "state")?, "unused".into())
            .await,
        Err(OidcError::State)
    ));
    let (mut url, attempt) = p.begin();
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .filter(|(k, _)| k != "nonce")
        .collect();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(pairs)
        .append_pair("nonce", "wrong-nonce");
    let cb = callback(url, admin).await?;
    assert!(matches!(
        p.finish(attempt, &query(&cb, "state")?, query(&cb, "code")?)
            .await,
        Err(OidcError::Claims)
    ));
    // Wrong verifier: keep the returned state but send an authorization challenge the attempt cannot satisfy.
    let (mut url, attempt) = p.begin();
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .filter(|(k, _)| k != "code_challenge")
        .collect();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(pairs)
        .append_pair(
            "code_challenge",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
    let cb = callback(url, admin).await?;
    assert!(matches!(
        p.finish(attempt, &query(&cb, "state")?, query(&cb, "code")?)
            .await,
        Err(OidcError::Exchange)
    ));
    // A wrong redirect URI must never yield an authorization code to that destination.
    let (mut url, _) = p.begin();
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .filter(|(k, _)| k != "redirect_uri")
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
#[ignore = "requires isolated Keycloak and Hydra; make test-oidc starts both"]
async fn real_provider_flows() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(120), async {
        flow(&std::env::var("IDENTITY_TEST_KEYCLOAK_ISSUER")?, None).await?;
        flow(
            &std::env::var("IDENTITY_TEST_HYDRA_ISSUER")?,
            Some(&std::env::var("IDENTITY_TEST_HYDRA_ADMIN")?),
        )
        .await?;
        assert!(
            Provider::discover(ProviderConfig::for_loopback_test(
                "http://127.0.0.1:1",
                "client",
                "secret",
                REDIRECT
            )?)
            .await
            .is_err()
        );
        Ok::<(), anyhow::Error>(())
    })
    .await?
}
