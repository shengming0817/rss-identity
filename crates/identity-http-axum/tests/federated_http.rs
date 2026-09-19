//! Real PG + HTTPS Keycloak adapter with explicit loopback fixture transport + in-process Axum. No product binary/T3 claim.
#[path = "../../identity-postgres/tests/federation_support/mod.rs"]
mod federation_support;
#[path = "group_lifecycle/mod.rs"]
mod group_lifecycle;
mod keycloak_support;
#[path = "../../identity-postgres/tests/support/mod.rs"]
mod support;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::Response,
};
use rss_identity_core::{federation::*, session::SessionSecret};
use rss_identity_http_axum::{HttpConfig, federated_router, router};
use rss_identity_oidc::{HttpOidc, TrustedAssuranceProfile};
use rss_identity_postgres::*;
use rss_transactional_messaging_postgres::PgTransactionFault;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use support::*;
use tower::ServiceExt;
use zeroize::Zeroizing;
const ORIGIN: &str = "https://identity.example.test";
const CALLBACK: &str = "https://identity.example.test/api/v2/oidc/callback";
const BROWSER: &str = "__Host-identity-oidc-browser=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
fn fixture_transport(keycloak_totp: bool) -> anyhow::Result<HttpOidc> {
    Ok(HttpOidc::for_loopback_test(vec![
        TrustedAssuranceProfile {
            keycloak_totp,
            tenant: tenant(),
            issuer: std::env::var("IDENTITY_TEST_FEDERATED_ISSUER")?,
            client_id: "identity-test".into(),
        },
    ])?)
}
fn credentials(ca: bool) -> anyhow::Result<ProviderCredentials> {
    ProviderCredentials::new(
        "fixture-secret".into(),
        if ca {
            Some(std::fs::read_to_string(std::env::var(
                "IDENTITY_TEST_FEDERATED_CA",
            )?)?)
        } else {
            None
        },
    )
    .map_err(Into::into)
}

fn config() -> anyhow::Result<ProviderSettings> {
    Ok((rss_identity_core::federation::ProviderSettingsInput {
        issuer: std::env::var("IDENTITY_TEST_FEDERATED_ISSUER")?,
        client_id: "identity-test".into(),

        redirect_uri: CALLBACK.into(),
        scopes: vec!["openid".into(), "profile".into(), "email".into()],
        claims: ClaimMapping {
            department: Some(rss_identity_core::department::DepartmentClaim::new(
                "department_id".into(),
                60,
            )?),
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
        rss_identity_core::groups::GroupFactsMaxAge::new(300).unwrap(),
        f.store.clone(),
        upstream,
        StateSigner::new([7; 32], ORIGIN).unwrap(),
        FederationConfig {
            callback: CALLBACK.into(),
            credential_keys: credential_keys(),
            targets: BTreeMap::from([("home".into(), format!("{ORIGIN}/done"))]),
        },
    )
    .unwrap()
}
fn app(s: &Federation) -> Router {
    federated_router(
        s.clone(),
        HttpConfig::new(ORIGIN, Duration::from_secs(30)).unwrap(),
    )
    .unwrap()
    .merge(
        router(
            s.authority(),
            HttpConfig::new(ORIGIN, Duration::from_secs(30)).unwrap(),
        )
        .unwrap(),
    )
}
async fn provider(f: &Fixture, s: &Federation) -> anyhow::Result<ProviderView> {
    let p = s
        .create_provider(
            federation_support::actor(f).await?,
            config()?,
            rss_identity_core::federation::ProviderCredentials::new(
                "fixture-secret".into(),
                Some(std::fs::read_to_string(std::env::var(
                    "IDENTITY_TEST_FEDERATED_CA",
                )?)?),
            )?,
            deadline(),
        )
        .await?;
    Ok(s.enable_provider(
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
    request
        .extensions_mut()
        .insert(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse().unwrap(),
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
        json!({"returnTarget":"home","password":password})
    } else {
        json!({"returnTarget":"home"})
    };
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            &format!(
                "/api/v2/tenants/{A}/oidc/{}/{}",
                p.id,
                if link { "link" } else { "login" }
            ),
            cookie,
            csrf,
            payload,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(body(response).await?["authorizationUrl"]
        .as_str()
        .unwrap()
        .into())
}
async fn authorize(url: &str, user: &str) -> anyhow::Result<String> {
    authorize_factor(url, user, false).await
}
async fn authorize_factor(url: &str, user: &str, totp: bool) -> anyhow::Result<String> {
    let u = keycloak_support::authorize(url, user, totp).await?;
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
async fn real_step_up_rotates_only_the_bound_session() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let s = service(&f, Arc::new(fixture_transport(true)?));
    let p = provider(&f, &s).await?;
    let app = app(&s);
    let original = successful(&app, &p, "alice").await?;
    let path = format!("/api/v2/tenants/{A}/oidc/{}/step-up", p.id);
    let browser = format!("{BROWSER}; {original}");
    let csrf = secret(&original).csrf();
    let input = json!({"returnTarget":"home"});
    for (cookies, token) in [(BROWSER, None), (browser.as_str(), None)] {
        let r = app
            .clone()
            .oneshot(request("POST", &path, cookies, token, input.clone()))
            .await?;
        assert!(r.status().is_client_error());
    }
    // Removing the requested ACR from the browser URL cannot weaken the stored requirement.
    let r = app
        .clone()
        .oneshot(request("POST", &path, &browser, Some(&csrf), input.clone()))
        .await?;
    assert_eq!(r.status(), StatusCode::OK);
    let url = body(r).await?["authorizationUrl"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut lowered = reqwest::Url::parse(&url)?;
    assert!(
        lowered
            .query_pairs()
            .any(|(k, v)| k == "acr_values" && v == "2")
    );
    assert!(
        lowered
            .query_pairs()
            .any(|(k, v)| k == "max_age" && v == "0")
    );
    let pairs: Vec<(String, String)> = lowered
        .query_pairs()
        .filter(|(k, _)| k != "acr_values")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    lowered.query_pairs_mut().clear().extend_pairs(pairs);
    let cb = authorize(lowered.as_str(), "alice").await?;
    let r = callback(&app, &cb, &browser).await?;
    assert_eq!(r.headers()["location"], "/auth/error?reason=failed");
    assert!(!r.headers().contains_key("set-cookie"));
    f.store
        .inspect_session(f.key.tenant, secret(&original), deadline())
        .await?;
    // A different real Keycloak user cannot replace the current principal.
    let r = app
        .clone()
        .oneshot(request("POST", &path, &browser, Some(&csrf), input.clone()))
        .await?;
    let url = body(r).await?["authorizationUrl"]
        .as_str()
        .unwrap()
        .to_owned();
    let cb = authorize_factor(&url, "bob", true).await?;
    let r = callback(&app, &cb, &browser).await?;
    assert_eq!(r.headers()["location"], "/auth/error?reason=failed");
    assert!(!r.headers().contains_key("set-cookie"));
    let r = app
        .clone()
        .oneshot(request("POST", &path, &browser, Some(&csrf), input))
        .await?;
    let url = body(r).await?["authorizationUrl"]
        .as_str()
        .unwrap()
        .to_owned();
    let cb = authorize_factor(&url, "alice", true).await?;
    let r = callback(&app, &cb, &browser).await?;
    assert_eq!(r.headers()["location"], format!("{ORIGIN}/done"));
    let upgraded = cookie(&r);
    let current = f
        .store
        .inspect_session(f.key.tenant, secret(&upgraded), deadline())
        .await?;
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&original), deadline())
            .await
            .is_err()
    );
    let facts: Value = sqlx::query_scalar("SELECT auth_facts FROM identity_authority.sessions WHERE tenant_id=$1::uuid AND session_id=$2::uuid")
        .bind(A).bind(current.view().id.to_string()).fetch_one(&f.owner).await?;
    assert_eq!(facts["assurance"]["acr"], "mfa");
    assert!(facts["assurance"]["auth_time"].as_i64().unwrap() > 0);
    let replay = callback(&app, &cb, &format!("{BROWSER}; {upgraded}")).await?;
    assert!(!replay.headers().contains_key("set-cookie"));
    let envelopes: Vec<Value> = sqlx::query_scalar("SELECT envelope FROM rss_transactional_messaging.outbox WHERE envelope->>'route'='federation.changed'").fetch_all(&f.owner).await?;
    let audit: Vec<Value> = envelopes
        .into_iter()
        .map(|v| {
            let bytes: Vec<u8> = serde_json::from_value(v["payload"].clone()).unwrap();
            serde_json::from_slice(&bytes).unwrap()
        })
        .collect();
    assert_eq!(
        audit.iter().filter(|v| v["action"] == "stepped_up").count(),
        1
    );
    // A real adapter profile withdrawal is applied before startup opens HTTP admission.
    let withdrawn = service(&f, Arc::new(fixture_transport(false)?));
    withdrawn
        .reconcile_assurance_profiles(f.key.tenant, deadline())
        .await?;
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&upgraded), deadline())
            .await
            .is_err()
    );
    assert!(
        federation_support::begin(&f, &s, &p).await.is_err(),
        "stale approved process must not start flows"
    );
    s.reconcile_assurance_profiles(f.key.tenant, deadline())
        .await?;
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&upgraded), deadline())
            .await
            .is_err(),
        "restoring the assurance profile must not revive MFA"
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-federated"]
async fn real_upstream_client_secret_rotation() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let old = service(&f, Arc::new(fixture_transport(true)?));
    let p = provider(&f, &old).await?;
    let old_app = app(&old);
    let url = begin(&old_app, &p, BROWSER, None, None, false).await?;
    let cb = authorize(&url, "alice").await?;
    let issuer = std::env::var("IDENTITY_TEST_FEDERATED_ISSUER")?;
    let base = issuer.strip_suffix("/realms/identity").unwrap();
    let ca = std::fs::read(std::env::var("IDENTITY_TEST_FEDERATED_CA")?)?;
    let operator = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
        .timeout(Duration::from_secs(10))
        .build()?;
    let token: Value = operator
        .post(format!(
            "{base}/realms/master/protocol/openid-connect/token"
        ))
        .form(&[
            ("grant_type", "password"),
            ("client_id", "admin-cli"),
            ("username", "fixture-operator"),
            ("password", "fixture-operator-password"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let admin_token = Zeroizing::new(token["access_token"].as_str().unwrap().to_owned());
    let clients: Value = operator
        .get(format!(
            "{base}/admin/realms/identity/clients?clientId=identity-test"
        ))
        .bearer_auth(admin_token.as_str())
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let id = clients[0]["id"].as_str().unwrap();
    let secret_value: Value = operator
        .post(format!(
            "{base}/admin/realms/identity/clients/{id}/client-secret"
        ))
        .bearer_auth(admin_token.as_str())
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let new_secret = Zeroizing::new(secret_value["value"].as_str().unwrap().to_owned());
    let rejected = callback(&old_app, &cb, BROWSER).await?;
    assert_eq!(rejected.headers()["location"], "/auth/error?reason=failed");
    assert!(!rejected.headers().contains_key("set-cookie"));
    let next = HttpOidc::for_loopback_test(vec![TrustedAssuranceProfile {
        tenant: f.key.tenant,
        issuer,
        client_id: "identity-test".into(),
        keycloak_totp: true,
    }])?;
    let next = service(&f, Arc::new(next));
    let settings = p.settings.input();
    let updated = next
        .update_provider(
            federation_support::actor(&f).await?,
            p.id,
            p.version,
            settings.try_into()?,
            rss_identity_core::federation::ProviderCredentials::new(
                new_secret.to_string(),
                Some(std::fs::read_to_string(std::env::var(
                    "IDENTITY_TEST_FEDERATED_CA",
                )?)?),
            )?,
            deadline(),
        )
        .await?;
    successful(&app(&next), &updated, "alice").await?;
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires make test-federated"]
async fn real_federated_login_and_linking() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let s = service(&f, Arc::new(fixture_transport(true)?));
    let p = provider(&f, &s).await?;
    let app = app(&s);
    f.store
        .create_local_account(
            federation_support::actor(&f).await?,
            login("same@example.test"),
            password(),
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
    let VerifiedDepartment::Available(department) = a.department()? else {
        anyhow::bail!("signed department missing");
    };
    assert_eq!(department.value()?.unwrap().as_str(), "dept-01");
    assert_eq!(department.account(), a.account());
    assert_eq!(department.provider_id().to_string(), p.id.to_string());
    assert!(matches!(
        b.department()?,
        VerifiedDepartment::Unavailable(
            rss_identity_core::facts::FactUnavailableReason::ClaimMissing
        )
    ));

    let principal = a.account();
    let facts:Value=sqlx::query_scalar("SELECT auth_facts FROM identity_authority.sessions WHERE tenant_id=$1::uuid AND session_id=$2::uuid").bind(A).bind(a.view().id.to_string()).fetch_one(&f.owner).await?;
    assert_eq!(facts["email"], "same@example.test");
    assert_eq!(facts["email_verified"], true);
    assert_eq!(facts["groups"]["values"], json!(["/staff"]));
    assert_eq!(facts["provider_config_version"], p.version);
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
    let s = service(&f, Arc::new(fixture_transport(true)?));
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
    assert_eq!(missing.status(), StatusCode::SEE_OTHER);
    assert_eq!(missing.headers()["location"], "/auth/error?reason=failed");
    parsed
        .query_pairs_mut()
        .append_pair("iss", "https://wrong.example.test");
    let wrong_issuer = callback(
        &app,
        &format!("{}?{}", parsed.path(), parsed.query().unwrap()),
        BROWSER,
    )
    .await?;
    assert_eq!(wrong_issuer.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        wrong_issuer.headers()["location"],
        "/auth/error?reason=failed"
    );
    let wrong = callback(
        &app,
        &cb,
        "__Host-identity-oidc-browser=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    )
    .await?;
    assert_eq!(wrong.status(), StatusCode::SEE_OTHER);
    assert_eq!(wrong.headers()["location"], "/auth/error?reason=failed");
    assert!(!wrong.headers().contains_key("set-cookie"));
    let response = app
        .clone()
        .oneshot(request("HEAD", &cb, BROWSER, None, Value::Null))
        .await?;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let response = callback(&app, &cb, BROWSER).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let response = callback(&app, &cb, BROWSER).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"], "/auth/error?reason=failed");
    assert!(!response.headers().contains_key("set-cookie"));
    let url = begin(&app, &p, BROWSER, None, None, false).await?;
    let cb = authorize(&url, "alice").await?;
    let p = s
        .update_provider(
            federation_support::actor(&f).await?,
            p.id,
            p.version,
            p.settings.clone(),
            rss_identity_core::federation::ProviderCredentials::new(
                "fixture-secret".into(),
                Some(std::fs::read_to_string(std::env::var(
                    "IDENTITY_TEST_FEDERATED_CA",
                )?)?),
            )?,
            deadline(),
        )
        .await?;
    let response = callback(&app, &cb, BROWSER).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"], "/auth/error?reason=failed");
    assert!(!response.headers().contains_key("set-cookie"));
    let url = begin(&app, &p, BROWSER, None, None, false).await?;
    let cb = authorize(&url, "alice").await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let response = callback(&app, &cb, BROWSER).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()["location"],
        "/auth/error?reason=unavailable"
    );
    assert!(!response.headers().contains_key("set-cookie"));
    let scripted = federation_support::ScriptedOidc::new();
    let mocked = service(&f, scripted.clone());
    mocked
        .reconcile_assurance_profiles(f.key.tenant, deadline())
        .await?;
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
            "/api/v2/oidc/callback?state={state}&code=bob&iss={}",
            p.settings.issuer().as_str()
        ),
        BROWSER,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()["location"],
        "/auth/error?reason=unavailable"
    );
    assert!(!response.headers().contains_key("set-cookie"));
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires make test-federated"]
async fn federated_tls_and_self_service_policy() -> anyhow::Result<()> {
    fixture_transport(true)?
        .test(tenant(), &config()?, &credentials(true)?)
        .await?;
    assert_eq!(
        fixture_transport(true)?
            .test(tenant(), &config()?, &credentials(false)?)
            .await
            .unwrap_err(),
        FederationError::provider(ProviderStage::Discovery, ProviderReason::TlsRejected)
    );
    let mut private = config()?.input();
    private.issuer = "https://127.0.0.1".into();
    assert!(
        HttpOidc::new(vec![], vec![])?
            .validate(tenant(), &private.try_into()?, &credentials(false)?)
            .is_err()
    );
    Ok(())
}

fn tenant() -> rss_request_context::TenantId {
    rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap()
}

#[tokio::test]
#[ignore = "requires make test-federated"]
async fn real_department_claim_rejection_preserves_host_diagnostic() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let federation = service(&f, Arc::new(fixture_transport(true)?));
    let mut input = config()?.input();
    // Keycloak signs groups as an array. Selecting it as the single department
    // claim exercises a real verified-token shape rejection, not a browser error.
    input.claims.groups = None;
    input.claims.department = Some(rss_identity_core::department::DepartmentClaim::new(
        "groups".into(),
        60,
    )?);
    let provider = federation
        .create_provider(
            f.actor().await?,
            input.try_into()?,
            credentials(true)?,
            deadline(),
        )
        .await?;
    let provider = federation
        .enable_provider(
            f.actor().await?,
            provider.id,
            provider.version,
            true,
            deadline(),
        )
        .await?;
    let app = app(&federation);
    let url = begin(&app, &provider, BROWSER, None, None, false).await?;
    let callback_url = authorize(&url, "alice").await?;
    let response = callback(&app, &callback_url, BROWSER).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"], "/auth/error?reason=failed");
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert_eq!(
        response
            .extensions()
            .get::<rss_identity_http_axum::HttpFailure>(),
        Some(&rss_identity_http_axum::HttpFailure::Authority(
            AuthorityError::Federation(FederationError::Claims),
        )),
    );
    let body = to_bytes(response.into_body(), 1024).await?;
    assert!(
        body.is_empty(),
        "internal failure must not reach the browser body"
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-federated"]
async fn real_provider_management_and_encrypted_credentials() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let s = service(&f, Arc::new(fixture_transport(true)?));
    let p = s
        .create_provider(f.actor().await?, config()?, credentials(true)?, deadline())
        .await?;
    assert!(!p.enabled);
    assert!(!format!("{p:?}").contains("fixture-secret"));
    let sealed:Value=sqlx::query_scalar("SELECT sealed FROM identity_authority.provider_credentials WHERE tenant_id=$1::uuid AND provider_id=$2::uuid").bind(A).bind(p.id.to_string()).fetch_one(&f.owner).await?;
    assert!(!sealed.to_string().contains("fixture-secret"));
    sqlx::query("UPDATE identity_authority.provider_credentials SET sealed=jsonb_set(sealed,'{key_id}','\"missing\"') WHERE tenant_id=$1::uuid AND provider_id=$2::uuid").bind(A).bind(p.id.to_string()).execute(&f.owner).await?;
    assert!(
        s.test_provider(f.actor().await?, p.id, deadline())
            .await
            .is_err()
    );
    assert_eq!(
        s.list_providers(f.actor().await?, deadline()).await?.len(),
        1
    );
    sqlx::query("UPDATE identity_authority.provider_credentials SET sealed=$3 WHERE tenant_id=$1::uuid AND provider_id=$2::uuid").bind(A).bind(p.id.to_string()).bind(sealed).execute(&f.owner).await?;
    assert!(
        s.test_provider(f.actor().await?, p.id, deadline())
            .await?
            .tls_verified
    );
    f.close().await;
    Ok(())
}
