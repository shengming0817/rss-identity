//! Real PG + production HTTPS Keycloak adapter + in-process Axum. No product binary/T3 claim.
#[path = "../../identity-postgres/tests/federation_support/mod.rs"]
mod federation_support;
#[allow(dead_code)]
#[path = "../../identity-postgres/tests/support/mod.rs"]
mod support;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
    response::Response,
};
use rss_identity_core::{federation::*, session::SessionSecret};
use rss_identity_http_axum::{HttpConfig, federated_router};
use rss_identity_oidc::{ApprovedProvider, HttpOidc};
use rss_identity_postgres::*;
use rss_transactional_messaging_postgres::PgTransactionFault;
use serde_json::{Value, json};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};
use support::*;
use tower::ServiceExt;
use zeroize::Zeroizing;
const ORIGIN: &str = "https://identity.example.test";
const CALLBACK: &str = "https://identity.example.test/api/v1/oidc/callback";
const BROWSER: &str = "__Host-identity-oidc-browser=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
fn production(ca: bool, allow: bool) -> anyhow::Result<HttpOidc> {
    let issuer = std::env::var("IDENTITY_TEST_FEDERATED_ISSUER")?;
    let pem = std::fs::read(std::env::var("IDENTITY_TEST_FEDERATED_CA")?)?;
    Ok(HttpOidc::new(
        vec![ApprovedProvider {
            tenant: tenant(),
            issuer,
            client_id: "identity-test".into(),
            secret_ref: "fixture@1".into(),
            redirect_uri: CALLBACK.into(),
            addresses: vec![if allow { "127.0.0.0/8" } else { "192.0.2.0/24" }.parse()?],
        }],
        BTreeMap::from([("fixture@1".into(), Zeroizing::new("fixture-secret".into()))]),
        ca.then_some(pem.as_slice()),
    )?)
}
fn config() -> anyhow::Result<ProviderSettings> {
    Ok((rss_identity_core::federation::ProviderSettingsInput {
        issuer: std::env::var("IDENTITY_TEST_FEDERATED_ISSUER")?,
        client_id: "identity-test".into(),
        secret_ref: "fixture@1".into(),
        redirect_uri: CALLBACK.into(),
        scopes: vec!["openid".into(), "profile".into(), "email".into()],
        claims: ClaimMapping {
            email: Some("email".into()),
            groups: Some("groups".into()),
        },
        jit: true,
    })
    .try_into()
    .unwrap())
}
fn service(f: &Fixture, upstream: Arc<dyn UpstreamOidc>) -> Federation {
    Federation::new(
        f.store.clone(),
        upstream,
        StateSigner::new([7; 32], ORIGIN).unwrap(),
        BTreeMap::from([(("identity".into(), "home".into()), format!("{ORIGIN}/done"))]),
    )
    .unwrap()
}
fn app(s: &Federation) -> Router {
    federated_router(
        s.clone(),
        HttpConfig::new(ORIGIN, Duration::from_secs(30)).unwrap(),
    )
    .unwrap()
}
async fn provider(f: &Fixture, s: &Federation) -> anyhow::Result<ProviderView> {
    let p = s
        .authority()
        .create_provider(federation_support::actor(f).await?, config()?, deadline())
        .await?;
    Ok(s.authority()
        .enable_provider(
            federation_support::actor(f).await?,
            p.id,
            p.version,
            true,
            deadline(),
        )
        .await?)
}
fn request(
    method: &str,
    path: &str,
    cookie: &str,
    csrf: Option<&str>,
    body: Value,
) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("origin", ORIGIN)
        .header("content-type", "application/json")
        .header("x-identity-request", "1")
        .header("cookie", cookie);
    if let Some(csrf) = csrf {
        request = request.header("x-csrf-token", csrf)
    }
    let mut request = request.body(Body::from(body.to_string())).unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
    ));
    request
}
async fn body(response: Response) -> anyhow::Result<Value> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 65536).await?,
    )?)
}
async fn begin(
    app: &Router,
    p: &ProviderView,
    cookie: &str,
    csrf: Option<&str>,
    password: Option<&str>,
    link: bool,
) -> anyhow::Result<String> {
    let payload = if link {
        json!({"client_id":"identity","return_target":"home","password":password})
    } else {
        json!({"client_id":"identity","return_target":"home"})
    };
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            &format!(
                "/api/v1/tenants/{A}/oidc/{}/{}",
                p.id,
                if link { "link" } else { "login" }
            ),
            cookie,
            csrf,
            payload,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(body(response).await?["authorization_url"]
        .as_str()
        .unwrap()
        .into())
}
async fn authorize(url: &str, user: &str) -> anyhow::Result<String> {
    let pem = std::fs::read(std::env::var("IDENTITY_TEST_FEDERATED_CA")?)?;
    let browser = reqwest::Client::builder()
        .no_proxy()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_pem(&pem)?)
        .timeout(Duration::from_secs(10))
        .build()?;
    let response = browser.get(url).send().await?.error_for_status()?;
    let html = response.text().await?;
    let action = {
        let dom = scraper::Html::parse_document(&html);
        dom.select(&scraper::Selector::parse("form#kc-form-login").unwrap())
            .next()
            .and_then(|f| f.value().attr("action"))
            .ok_or_else(|| anyhow::anyhow!("Keycloak login form absent"))?
            .to_owned()
    };
    let response = browser
        .post(action)
        .form(&[
            ("username", user),
            ("password", "fixture-password"),
            ("credentialId", ""),
        ])
        .send()
        .await?;
    let location = response
        .headers()
        .get("location")
        .ok_or_else(|| anyhow::anyhow!("Keycloak callback absent: {}", response.status()))?
        .to_str()?;
    let u = reqwest::Url::parse(location)?;
    Ok(format!("{}?{}", u.path(), u.query().unwrap_or_default()))
}
async fn callback(app: &Router, path: &str, cookie: &str) -> anyhow::Result<Response> {
    Ok(app
        .clone()
        .oneshot(request("GET", path, cookie, None, Value::Null))
        .await?)
}
fn cookie(response: &Response) -> String {
    response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .into()
}
fn secret(cookie: &str) -> SessionSecret {
    SessionSecret::parse(cookie.split_once('=').unwrap().1.into()).unwrap()
}
async fn successful(app: &Router, p: &ProviderView, user: &str) -> anyhow::Result<String> {
    let url = begin(app, p, BROWSER, None, None, false).await?;
    let cb = authorize(&url, user).await?;
    let response = callback(app, &cb, BROWSER).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"], format!("{ORIGIN}/done"));
    Ok(cookie(&response))
}
#[tokio::test]
#[ignore = "requires make test-federated"]
async fn real_federated_login_and_linking() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let s = service(&f, Arc::new(production(true, true)?));
    let p = provider(&f, &s).await?;
    let app = app(&s);
    f.store
        .create_account(
            federation_support::actor(&f).await?,
            login("same@example.test"),
            password(),
            false,
            false,
            deadline(),
        )
        .await?;
    let alice = successful(&app, &p, "alice").await?;
    let bob = successful(&app, &p, "bob").await?;
    let a = f
        .store
        .inspect_session(f.key.tenant, secret(&alice), deadline())
        .await?;
    let b = f
        .store
        .inspect_session(f.key.tenant, secret(&bob), deadline())
        .await?;
    assert_ne!(a.account(), b.account());
    let principal = a.account();
    let facts:Value=sqlx::query_scalar("SELECT auth_facts FROM identity_authority.sessions WHERE tenant_id=$1::uuid AND session_id=$2::uuid").bind(A).bind(a.view().id.to_string()).fetch_one(&f.owner).await?;
    assert_eq!(facts["email"], "same@example.test");
    assert_eq!(facts["email_verified"], true);
    assert_eq!(facts["groups"], json!(["staff"]));
    assert_eq!(facts["mapping_version"], p.version);
    let local = federation_support::session(&f).await?;
    let local_cookie = format!(
        "{BROWSER}; __Host-identity-session={}",
        local.secret().expose()
    );
    let target = provider(&f, &s).await?;
    let url = begin(
        &app,
        &target,
        &local_cookie,
        Some(&local.secret().csrf()),
        Some(PASSWORD),
        true,
    )
    .await?;
    let cb = authorize(&url, "bob").await?;
    let response = callback(&app, &cb, &local_cookie).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()["location"],
        format!("{ORIGIN}/done?identity_result=linked")
    );
    let linked = cookie(&response);
    assert_eq!(
        f.store
            .inspect_session(f.key.tenant, secret(&linked), deadline())
            .await?
            .account(),
        f.key
    );
    let linked_cookie = format!("{BROWSER}; {linked}");
    let url = begin(
        &app,
        &target,
        &linked_cookie,
        Some(&secret(&linked).csrf()),
        Some(PASSWORD),
        true,
    )
    .await?;
    let cb = authorize(&url, "bob").await?;
    let response = callback(&app, &cb, &linked_cookie).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()["location"],
        format!("{ORIGIN}/done?identity_result=already_linked")
    );
    let alice_cookie = format!("{BROWSER}; {alice}");
    let url = begin(
        &app,
        &target,
        &alice_cookie,
        Some(&secret(&alice).csrf()),
        None,
        true,
    )
    .await?;
    assert!(url.contains("prompt=login"));
    assert!(url.contains("max_age=0"));
    let cb = authorize(&url, "alice").await?;
    let response = callback(&app, &cb, &alice_cookie).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(!response.headers().contains_key("set-cookie"));
    let next = response.headers()["location"].to_str()?.to_owned();
    let cb = authorize(&next, "alice").await?;
    let response = callback(&app, &cb, &alice_cookie).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        f.store
            .inspect_session(f.key.tenant, secret(&cookie(&response)), deadline())
            .await?
            .account(),
        principal
    );
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires make test-federated"]
async fn federated_http_rejects_mismatch_and_uncertain_commit() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let s = service(&f, Arc::new(production(true, true)?));
    let p = provider(&f, &s).await?;
    let app = app(&s);
    let url = begin(&app, &p, BROWSER, None, None, false).await?;
    let cb = authorize(&url, "alice").await?;
    let mut parsed = reqwest::Url::parse(&format!("{ORIGIN}{cb}"))?;
    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(k, _)| k != "iss")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    parsed.query_pairs_mut().clear().extend_pairs(pairs);
    let missing = callback(
        &app,
        &format!("{}?{}", parsed.path(), parsed.query().unwrap()),
        BROWSER,
    )
    .await?;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    parsed
        .query_pairs_mut()
        .append_pair("iss", "https://wrong.example.test");
    let wrong_issuer = callback(
        &app,
        &format!("{}?{}", parsed.path(), parsed.query().unwrap()),
        BROWSER,
    )
    .await?;
    assert_eq!(wrong_issuer.status(), StatusCode::UNAUTHORIZED);
    let wrong = callback(
        &app,
        &cb,
        "__Host-identity-oidc-browser=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    )
    .await?;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert!(!wrong.headers().contains_key("set-cookie"));
    let response = app
        .clone()
        .oneshot(request("HEAD", &cb, BROWSER, None, Value::Null))
        .await?;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let response = callback(&app, &cb, BROWSER).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let response = callback(&app, &cb, BROWSER).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!response.headers().contains_key("set-cookie"));
    let url = begin(&app, &p, BROWSER, None, None, false).await?;
    let cb = authorize(&url, "alice").await?;
    let p = s
        .authority()
        .update_provider(
            federation_support::actor(&f).await?,
            p.id,
            p.version,
            p.settings.clone(),
            deadline(),
        )
        .await?;
    let response = callback(&app, &cb, BROWSER).await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(!response.headers().contains_key("set-cookie"));
    let url = begin(&app, &p, BROWSER, None, None, false).await?;
    let cb = authorize(&url, "alice").await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let response = callback(&app, &cb, BROWSER).await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("set-cookie"));
    let scripted = federation_support::ScriptedOidc::new();
    let mocked = service(&f, scripted.clone());
    let mock_app = federated_router(
        mocked.clone(),
        HttpConfig::new(ORIGIN, Duration::from_secs(30))?,
    )?;
    let url = begin(&mock_app, &p, BROWSER, None, None, false).await?;
    let state = reqwest::Url::parse(&url)?
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let runtime = f.runtime.clone();
    *scripted.hook.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
            runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
            Ok(())
        })
    }));
    let response = callback(
        &mock_app,
        &format!(
            "/api/v1/oidc/callback?state={state}&code=bob&iss={}",
            p.settings.issuer().as_str()
        ),
        BROWSER,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("set-cookie"));
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires make test-federated"]
async fn federated_tls_and_egress_policy() -> anyhow::Result<()> {
    production(true, true)?.test(tenant(), &config()?).await?;
    assert_eq!(
        production(false, true)?
            .test(tenant(), &config()?)
            .await
            .unwrap_err(),
        FederationError::provider(ProviderStage::Discovery, ProviderReason::TlsRejected)
    );
    assert_eq!(
        production(true, false)?
            .test(tenant(), &config()?)
            .await
            .unwrap_err(),
        FederationError::provider(ProviderStage::Binding, ProviderReason::EgressDenied)
    );
    let mut wrong = config()?.input();
    wrong.issuer = "https://169.254.169.254".into();
    assert!(
        production(true, true)?
            .test(tenant(), &wrong.try_into()?)
            .await
            .is_err()
    );
    Ok(())
}

fn tenant() -> rss_request_context::TenantId {
    rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap()
}
