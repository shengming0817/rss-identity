//! Real PG management/router seam, independent of production assembly.
#[path = "../../identity-postgres/tests/federation_support/mod.rs"]
mod federation_support;
#[allow(dead_code)]
#[path = "../../identity-postgres/tests/support/mod.rs"]
mod support;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, Response, StatusCode},
};
use rss_identity_http_axum::{HttpConfig, federated_router, management_router};
use rss_identity_postgres::*;
use serde_json::{Value, json};
use std::{sync::atomic::Ordering, time::Duration};
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
        .insert(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse().unwrap(),
        ));
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
    let duplicate = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("{base}/accounts"),
            &cookie,
            &csrf,
            json!({"login":"admin","password":"different strong password","role":"member"}),
        ))
        .await?;
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(duplicate).await?["code"],
        "account_already_exists"
    );
    let current = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("{base}/session"),
            &cookie,
            "",
            json!(null),
        ))
        .await?;
    assert_eq!(current.status(), StatusCode::OK);
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
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(
        v["accounts"][0]["principal_id"]
            .as_str()
            .unwrap()
            .to_owned(),
    );
    let mut cursor = v["next_cursor"].clone();
    while let Some(next) = cursor.as_str() {
        let response = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("{base}/accounts?limit=1&cursor={next}"),
                &cookie,
                "",
                json!(null),
            ))
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let page = json_body(response).await?;
        for account in page["accounts"].as_array().unwrap() {
            assert!(seen.insert(account["principal_id"].as_str().unwrap().to_owned()));
        }
        cursor = page["next_cursor"].clone();
    }
    let all = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("{base}/accounts"),
            &cookie,
            "",
            json!(null),
        ))
        .await?;
    assert_eq!(
        seen.len(),
        json_body(all).await?["accounts"].as_array().unwrap().len()
    );
    for query in ["cursor=invalid", "limit=0", "limit=101"] {
        let r = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("{base}/accounts?{query}"),
                &cookie,
                "",
                json!(null),
            ))
            .await?;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

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
    let mut original = federation_support::settings().input();
    original.issuer = "https://idp.example.test/realms/other".into();
    let created = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("{base}/providers"),
            &cookie,
            &csrf,
            serde_json::to_value(&original)?,
        ))
        .await?;
    let second = json_body(created).await?;
    let second_path = format!("{base}/providers/{}", second["id"].as_str().unwrap());
    let mut changed = original;
    changed.client_id = "updated-client".into();
    let update = json!({"expected_version":1,"settings":changed});
    let updated = app
        .clone()
        .oneshot(req("PUT", &second_path, &cookie, &csrf, update.clone()))
        .await?;
    assert_eq!(updated.status(), StatusCode::OK);
    let updated = json_body(updated).await?;
    assert_eq!(updated["version"], 2);
    assert_eq!(updated["settings"]["client_id"], "updated-client");
    assert_eq!(updated["enabled"], false);
    let stale = app
        .clone()
        .oneshot(req("PUT", &second_path, &cookie, &csrf, update))
        .await?;
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(stale).await?["code"], "configuration_changed");
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
    let enabled = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("{second_path}/enabled"),
            &cookie,
            &csrf,
            json!({"enabled":true,"expected_version":2}),
        ))
        .await?;
    assert_eq!(enabled.status(), StatusCode::OK);
    let choices = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("{base}/login-options"),
            "",
            "",
            json!(null),
        ))
        .await?;
    let choices = json_body(choices).await?;
    let choices = choices["providers"].as_array().unwrap();
    assert_eq!(choices.len(), 2);
    assert_ne!(choices[0]["label"], choices[1]["label"]);
    assert!(
        choices
            .iter()
            .any(|p| p["label"].as_str().unwrap().contains("/realms/other"))
    );

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
        .append_pair("error_uri", "https://upstream.test/private-error")
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

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn provider_capacity_is_atomic_and_keeps_management_available() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let (app, _, _) = app(&f);
    let (cookie, csrf) = login_as(&app, "admin", PASSWORD).await?;
    let settings = serde_json::to_value(federation_support::settings().input())?;
    sqlx::query("INSERT INTO identity_authority.providers(tenant_id,provider_id,config_version,revocation_epoch,enabled,settings) SELECT $1::uuid,gen_random_uuid(),1,1,false,$2 FROM generate_series(1,99)")
        .bind(A).bind(&settings).execute(&f.owner).await?;
    let path = format!("/api/v1/tenants/{A}/providers");
    let (first, second) = tokio::join!(
        app.clone()
            .oneshot(req("POST", &path, &cookie, &csrf, settings.clone())),
        app.clone()
            .oneshot(req("POST", &path, &cookie, &csrf, settings))
    );
    let first = first?;
    let second = second?;
    let rejected = if first.status() == StatusCode::CREATED {
        second
    } else {
        assert_eq!(second.status(), StatusCode::CREATED);
        first
    };
    assert_eq!(rejected.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(rejected).await?["code"], "provider_limit_reached");
    let list = app
        .oneshot(req("GET", &path, &cookie, "", json!(null)))
        .await?;
    assert_eq!(list.status(), StatusCode::OK);
    assert_eq!(
        json_body(list).await?["providers"]
            .as_array()
            .unwrap()
            .len(),
        100
    );
    f.close().await;
    Ok(())
}
