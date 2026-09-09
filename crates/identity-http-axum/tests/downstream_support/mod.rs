#![allow(dead_code)]
use reqwest::{Client, Url};
use serde_json::{Value, json};
pub const VALIDATION: &str = "fixture-validation-mdm-secret-32bytes";
pub const SERVICE: &str = "fixture-service-identity-admin-32bytes";
pub fn query(u: &Url, k: &str) -> anyhow::Result<String> {
    u.query_pairs()
        .find(|(key, _)| key == k)
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| anyhow::anyhow!("missing expected redirect field"))
}
pub fn location(r: reqwest::Response) -> anyhow::Result<Url> {
    if !r.status().is_redirection() {
        anyhow::bail!("expected redirect, status={}", r.status());
    }
    Ok(Url::parse(
        r.headers()
            .get("location")
            .ok_or_else(|| anyhow::anyhow!("missing redirect"))?
            .to_str()?,
    )?)
}
pub async fn post(
    c: &Client,
    origin: &str,
    path: &str,
    v: Value,
    csrf: Option<&str>,
) -> anyhow::Result<Value> {
    let mut r = c
        .post(format!("{origin}{path}"))
        .header("Origin", origin)
        .header("X-Identity-Request", "1")
        .json(&v);
    if let Some(csrf) = csrf {
        r = r.header("X-CSRF-Token", csrf);
    }
    let r = r.send().await?;
    if !r.status().is_success() {
        let status = r.status();
        let body: Value = r.json().await?;
        anyhow::bail!("bridge rejected {path}: {} {}", status, body["code"]);
    }
    Ok(r.json().await?)
}
pub async fn flow(
    c: &Client,
    origin: &str,
    issuer: &str,
    csrf: &str,
    exchange_verifier: &str,
    replay: bool,
) -> anyhow::Result<(String, Value, String)> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut authorize = Url::parse(&format!("{issuer}oauth2/auth"))?;
    authorize.query_pairs_mut().extend_pairs([
        ("client_id", "mdm"),
        ("redirect_uri", "https://mdm.example.test/auth/callback"),
        ("response_type", "code"),
        ("scope", "openid"),
        ("audience", "mdm-api"),
        ("state", "consumer-state-value"),
        ("nonce", "consumer-nonce-value"),
        ("code_challenge_method", "S256"),
        ("code_challenge", &challenge),
    ]);
    let login = location(c.get(authorize).send().await?)?;
    let login_challenge = query(&login, "login_challenge")?;
    let handle = post(
        c,
        origin,
        "/api/v1/downstream/login",
        json!({"challenge":login_challenge}),
        None,
    )
    .await?;
    let accepted = post(
        c,
        origin,
        "/api/v1/downstream/login/accept",
        json!({"flow":handle,"challenge":login_challenge}),
        Some(csrf),
    )
    .await?;
    let consent = location(
        c.get(accepted["redirect_to"].as_str().unwrap())
            .send()
            .await?,
    )?;
    let consent_challenge = query(&consent, "consent_challenge")?;
    let continuation = post(
        c,
        origin,
        "/api/v1/downstream/consent",
        json!({"challenge":consent_challenge}),
        None,
    )
    .await?;
    assert_eq!(continuation, handle);
    let accepted = post(
        c,
        origin,
        "/api/v1/downstream/consent/accept",
        json!({"flow":handle,"challenge":consent_challenge}),
        Some(csrf),
    )
    .await?;
    let callback = location(
        c.get(accepted["redirect_to"].as_str().unwrap())
            .send()
            .await?,
    )?;
    assert_eq!(query(&callback, "state")?, "consumer-state-value");
    let code = query(&callback, "code")?;
    let response = c
        .post(format!("{issuer}oauth2/token"))
        .basic_auth("mdm", Some("fixture-oidc-mdm-secret"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://mdm.example.test/auth/callback"),
            ("code_verifier", exchange_verifier),
        ])
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "token exchange failed {}",
        response.status()
    );
    let token: Value = response.json().await?;
    if replay {
        let replay = c
            .post(format!("{issuer}oauth2/token"))
            .basic_auth("mdm", Some("fixture-oidc-mdm-secret"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://mdm.example.test/auth/callback"),
                ("code_verifier", exchange_verifier),
            ])
            .send()
            .await?;
        assert!(replay.status().is_client_error());
    }
    Ok((
        token["access_token"].as_str().unwrap().into(),
        handle,
        token["id_token"].as_str().unwrap().into(),
    ))
}

use super::support::A;
use rss_identity_core::downstream::*;
use rss_identity_http_axum::*;
use rss_identity_postgres::*;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use zeroize::Zeroizing;
pub fn downstream(
    store: Authority,
    hydra: Arc<rss_identity_hydra::Hydra>,
    issuer: &str,
) -> anyhow::Result<Downstream> {
    Ok(Downstream::new(
        store,
        hydra,
        vec![Registration::new(RegistrationInput {
            tenant: rss_request_context::TenantId::parse(A)?,
            client: "mdm".into(),
            audience: "mdm-api".into(),
            issuer: issuer.into(),
            redirect: "https://mdm.example.test/auth/callback".into(),
            version: 1,
        })?],
        Lifetimes::new(LifetimeLimits {
            request: 300,
            code: 60,
            access_token: 300,
            clock_skew: 30,
        })?,
        Arc::new(PrepareAdmission::new(8, 120, Duration::from_secs(60))?),
    )?)
}
pub async fn serve(
    store: Authority,
    d: Downstream,
    origin: &str,
) -> anyhow::Result<tokio::task::JoinHandle<std::io::Result<()>>> {
    let config = HttpConfig::new(origin, Duration::from_secs(30))?;
    let app = router(store, config.clone())?.merge(downstream_router(
        d,
        config,
        BTreeMap::from([("mdm".into(), Zeroizing::new(VALIDATION.into()))]),
    )?);
    let listener = tokio::net::TcpListener::bind(format!(
        "127.0.0.1:{}",
        std::env::var("IDENTITY_TEST_BRIDGE_PORT")?
    ))
    .await?;
    Ok(tokio::spawn(async move {
        axum::serve(
            listener,
            app.layer(axum::middleware::map_request(
                |mut r: axum::extract::Request| async move {
                    r.extensions_mut()
                        .insert(ClientAddress("127.0.0.1".parse().unwrap()));
                    r
                },
            ))
            .into_make_service(),
        )
        .await
    }))
}
