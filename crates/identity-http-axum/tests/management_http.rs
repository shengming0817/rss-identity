//! Real PG management/router seam, independent of production assembly.
#[path = "../../identity-postgres/tests/federation_support/mod.rs"]
mod federation_support;
#[allow(dead_code)]
#[path = "../../identity-postgres/tests/support/mod.rs"]
mod support;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, Response, StatusCode},
};
use rss_identity_http_axum::{HttpConfig, federated_router, management_router};
use rss_identity_postgres::*;
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::atomic::Ordering, time::Duration};
use support::*;
use tower::ServiceExt;
const ORIGIN: &str = "https://identity.example.test";
fn app(
    f: &Fixture,
) -> (
    Router,
    Federation,
    std::sync::Arc<federation_support::ScriptedOidc>,
) {
    let upstream = federation_support::ScriptedOidc::new();
    let service = federation_support::service(f, upstream.clone());
    let config = HttpConfig::new(ORIGIN, Duration::from_secs(30)).unwrap();
    (
        federated_router(service.clone(), config.clone())
            .unwrap()
            .merge(management_router(service.clone(), config).unwrap()),
        service,
        upstream,
    )
}
fn req(method: &str, path: &str, cookie: &str, csrf: &str, value: Value) -> Request<Body> {
    let mut r = Request::builder()
        .method(method)
        .uri(path)
        .header("origin", ORIGIN)
        .header("x-identity-request", "1")
        .header("content-type", "application/json");
    if !cookie.is_empty() {
        r = r.header("cookie", cookie);
    }
    if !csrf.is_empty() {
        r = r.header("x-csrf-token", csrf);
    }
    let mut r = r.body(Body::from(value.to_string())).unwrap();
    r.extensions_mut()
        .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
    r
}
async fn json_body(r: Response<Body>) -> anyhow::Result<Value> {
    Ok(serde_json::from_slice(
        &to_bytes(r.into_body(), 65536).await?,
    )?)
}
async fn login_as(app: &Router, name: &str, pw: &str) -> anyhow::Result<(String, String)> {
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/tenants/{A}/login"),
            "",
            "",
            json!({"login":name,"password":pw}),
        ))
        .await?;
    anyhow::ensure!(r.status() == StatusCode::OK, "login failed: {}", r.status());
    let cookie = r.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let v = json_body(r).await?;
    assert!(v["identity"]["principal_id"].is_string());
    Ok((cookie, v["csrf_token"].as_str().unwrap().into()))
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn management_accounts_sessions_and_boundaries() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let (app, _, _) = app(&f);
    let (cookie, csrf) = login_as(&app, "admin", PASSWORD).await?;
    let base = format!("/api/v1/tenants/{A}");
    let self_path = format!("{base}/accounts/{}/enabled", f.key.principal.as_uuid());
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &self_path,
            &cookie,
            &csrf,
            json!({"enabled":false}),
        ))
        .await?;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(r).await?["code"], "last_administrator");
    for (cookie_value, csrf_value, status) in [
        ("", "", StatusCode::UNAUTHORIZED),
        (&*cookie, "bad", StatusCode::FORBIDDEN),
    ] {
        let r = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("{base}/accounts"),
                cookie_value,
                csrf_value,
                json!({"login":"member","password":PASSWORD,"role":"member"}),
            ))
            .await?;
        assert_eq!(r.status(), status);
    }
    let mut r = req("POST", &self_path, &cookie, &csrf, json!({"enabled":false}));
    r.headers_mut().remove("origin");
    assert_eq!(
        app.clone().oneshot(r).await?.status(),
        StatusCode::FORBIDDEN
    );
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("{base}/accounts"),
            &cookie,
            &csrf,
            json!({"login":"member","password":PASSWORD,"role":"member"}),
        ))
        .await?;
    assert_eq!(r.status(), StatusCode::CREATED);
    let member = json_body(r).await?;
    let id = member["principal_id"].as_str().unwrap();
    let (member_cookie, member_csrf) = login_as(&app, "member", PASSWORD).await?;
    let r = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("{base}/accounts"),
            &member_cookie,
            "",
            json!(null),
        ))
        .await?;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(r).await?["code"], "insufficient_privilege");
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("{base}/accounts/{id}/administrator"),
            &member_cookie,
            &member_csrf,
            json!({"enabled":true}),
        ))
        .await?;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r=app.clone().oneshot(req("POST",&format!("{base}/account/password"),&member_cookie,&member_csrf,json!({"current_password":"wrong but sufficiently long","password":"new private member password"}))).await?;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(r).await?["code"], "reauthentication_failed");
    let r = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("{base}/session"),
            &member_cookie,
            "",
            json!(null),
        ))
        .await?;
    assert_eq!(r.status(), StatusCode::OK);
    let foreign = format!("/api/v1/tenants/{B}/accounts");
    assert_eq!(
        app.clone()
            .oneshot(req("GET", &foreign, &cookie, "", json!(null)))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for (action, enabled) in [("membership", false), ("enabled", false)] {
        let r = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("{base}/accounts/{id}/{action}"),
                &cookie,
                &csrf,
                json!({"enabled":enabled}),
            ))
            .await?;
        assert_eq!(r.status(), StatusCode::OK);
    }
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("{base}/accounts/{id}/password"),
            &cookie,
            &csrf,
            json!({"password":"new private member password"}),
        ))
        .await?;
    assert_eq!(r.status(), StatusCode::OK);
    let v = json_body(r).await?;
    assert_eq!(v["enabled"], false);
    assert_eq!(v["member_active"], false);
    assert_eq!(v["administrator"], false);
    assert_eq!(
        app.clone()
            .oneshot(req(
                "GET",
                &format!("{base}/session"),
                &member_cookie,
                "",
                json!(null)
            ))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for action in ["enabled", "membership"] {
        assert_eq!(
            app.clone()
                .oneshot(req(
                    "POST",
                    &format!("{base}/accounts/{id}/{action}"),
                    &cookie,
                    &csrf,
                    json!({"enabled":true})
                ))
                .await?
                .status(),
            StatusCode::OK
        );
    }
    let (mc, mt) = login_as(&app, "member", "new private member password").await?;
    let r=app.clone().oneshot(req("POST",&format!("{base}/account/password"),&mc,&mt,json!({"current_password":"new private member password","password":"another private member password"}))).await?;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        app.clone()
            .oneshot(req("GET", &format!("{base}/session"), &mc, "", json!(null)))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let r = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("{base}/accounts?limit=1"),
            &cookie,
            "",
            json!(null),
        ))
        .await?;
    let v = json_body(r).await?;
    assert_eq!(v["accounts"].as_array().unwrap().len(), 1);
    assert!(v["next_cursor"].is_string());
    assert!(!v.to_string().contains("password_hash"));
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn management_provider_operations_safe_and_scoped() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let (app, _, upstream) = app(&f);
    let (cookie, csrf) = login_as(&app, "admin", PASSWORD).await?;
    let base = format!("/api/v1/tenants/{A}");
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("{base}/providers"),
            &cookie,
            &csrf,
            serde_json::to_value(federation_support::settings().input())?,
        ))
        .await?;
    assert_eq!(r.status(), StatusCode::CREATED);
    let p = json_body(r).await?;
    assert_eq!(p["enabled"], false);
    let id = p["id"].as_str().unwrap();
    let url = format!("{base}/providers/{id}");
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("{url}/enabled"),
            &cookie,
            &csrf,
            json!({"enabled":true,"expected_version":1}),
        ))
        .await?;
    assert_eq!(r.status(), StatusCode::OK);
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("{url}/enabled"),
            &cookie,
            &csrf,
            json!({"enabled":false,"expected_version":1}),
        ))
        .await?;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let r = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("{base}/login-options"),
            "",
            "",
            json!(null),
        ))
        .await?;
    let options = json_body(r).await?;
    assert_eq!(options["providers"].as_array().unwrap().len(), 1);
    assert!(!options.to_string().contains("secret_ref"));
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("{url}/test"),
            &cookie,
            &csrf,
            json!({}),
        ))
        .await?;
    assert_eq!(json_body(r).await?["passed"], true);
    upstream.fail.store(true, Ordering::SeqCst);
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("{url}/test"),
            &cookie,
            &csrf,
            json!({}),
        ))
        .await?;
    let v = json_body(r).await?;
    assert_eq!(v["passed"], false);
    assert_eq!(v["diagnostic"]["stage"], "jwks");
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("{url}/enabled"),
            &cookie,
            &csrf,
            json!({"enabled":false,"expected_version":2}),
        ))
        .await?;
    assert_eq!(r.status(), StatusCode::OK);
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn callback_cancellation_consumes_only_bound_attempts() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let (app, s, upstream) = app(&f);
    let oversized = format!("/api/v1/oidc/callback?state={}", "a".repeat(8192));
    let r = app
        .clone()
        .oneshot(req("GET", &oversized, "", "", json!(null)))
        .await?;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()["location"], "/auth/error?reason=failed");
    let p = federation_support::enabled(&f, &s).await?;
    let state = federation_support::begin(&f, &s, &p).await?;
    let mut url = url::Url::parse(&format!("{ORIGIN}/api/v1/oidc/callback"))?;
    url.query_pairs_mut()
        .append_pair("state", &state)
        .append_pair("error", "access_denied")
        .append_pair("error_description", "private upstream marker")
        .append_pair("iss", "https://idp.example.test");
    let path = format!("{}?{}", url.path(), url.query().unwrap());
    let wrong = app
        .clone()
        .oneshot(req(
            "GET",
            &path,
            "__Host-identity-oidc-browser=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "",
            json!(null),
        ))
        .await?;
    assert_eq!(wrong.status(), StatusCode::SEE_OTHER);
    let cookie = format!(
        "__Host-identity-oidc-browser={}",
        federation_support::BROWSER
    );
    let r = app
        .clone()
        .oneshot(req("GET", &path, &cookie, "", json!(null)))
        .await?;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()["location"], "/auth/error?reason=cancelled");
    assert!(r.headers().get("set-cookie").is_none());
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    let r = app
        .clone()
        .oneshot(req("GET", &path, &cookie, "", json!(null)))
        .await?;
    assert_eq!(r.headers()["location"], "/auth/error?reason=failed");
    assert!(
        federation_support::finish(&s, state, "alice")
            .await
            .is_err()
    );
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn management_rechecks_inflight_provider_authority() -> anyhow::Result<()> {
    for revoke in [false, true] {
        let f = Fixture::new().await?;
        f.bootstrap().await?;
        let (app, s, upstream) = app(&f);
        let p = federation_support::enabled(&f, &s).await?;
        let second = f
            .store
            .create_local_account(
                f.actor().await?,
                support::login("second"),
                password(),
                LocalAccountRole::Administrator,
                deadline(),
            )
            .await?;
        let proof = f
            .store
            .verify_password(
                f.key.tenant,
                support::login("second"),
                password(),
                source(),
                deadline(),
            )
            .await?;
        let other = session_actor(&f.store, proof).await?;
        assert_ne!(other.account(), f.key);
        let (cookie, csrf) = login_as(&app, "admin", PASSWORD).await?;
        let authority = f.store.clone();
        let next = s.clone();
        let target = f.key;
        let id = p.id;
        let version = p.version;
        let settings = p.settings.clone();
        *upstream.hook.lock().unwrap() = Some(Box::new(move || {
            Box::pin(async move {
                if revoke {
                    authority
                        .set_account_administrator(other, target, false, deadline())
                        .await
                        .map_err(|_| rss_identity_core::federation::FederationError::Unavailable)?;
                } else {
                    next.update_provider(other, id, version, settings, deadline())
                        .await
                        .map_err(|_| rss_identity_core::federation::FederationError::Unavailable)?;
                }
                Ok(())
            })
        }));
        let r = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/tenants/{A}/providers/{}/test", p.id),
                &cookie,
                &csrf,
                json!({}),
            ))
            .await?;
        assert_eq!(
            r.status(),
            if revoke {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::CONFLICT
            }
        );
        let value = json_body(r).await?;
        assert_eq!(
            value["code"],
            if revoke {
                "invalid_credential"
            } else {
                "configuration_changed"
            }
        );
        assert_ne!(second.key(), f.key);
        f.close().await;
    }
    Ok(())
}
