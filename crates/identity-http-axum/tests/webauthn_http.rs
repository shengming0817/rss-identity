//! Same-origin HTTP boundary with real PG and software WebAuthn signatures.
#[path = "../../identity-postgres/tests/support/mod.rs"]
mod support;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use rss_identity_http_axum::{HttpConfig, webauthn_router};
use rss_identity_postgres::*;
use serde_json::{Value, json};
use std::time::Duration;
use support::*;
use tower::ServiceExt;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
const ORIGIN: &str = "https://identity.example.test";
fn request(path: &str, cookie: &str, csrf: Option<&str>, body: Value) -> Request<Body> {
    let mut r = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/identity/tenants/{A}/webauthn/{path}"))
        .header("origin", ORIGIN)
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .header("x-identity-request", "1");
    if let Some(csrf) = csrf {
        r = r.header("x-csrf-token", csrf)
    }
    r.body(Body::from(body.to_string())).unwrap()
}
async fn json_body(r: axum::response::Response) -> anyhow::Result<Value> {
    Ok(serde_json::from_slice(
        &to_bytes(r.into_body(), 131072).await?,
    )?)
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn webauthn_http_csrf_lifecycle_and_one_use_proof() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let session = f.login().await?;
    let cookie = format!("__Host-identity-session={}", session.secret().expose());
    let csrf = session.secret().csrf();
    let w = WebauthnAuthority::connect(
        f.store.clone(),
        "identity.example.test".into(),
        url::Url::parse(ORIGIN)?,
        deadline(),
    )
    .await?;
    let app = webauthn_router(w, HttpConfig::new(ORIGIN, Duration::from_secs(30))?)?;
    let body = json!({"label":"browser key","recover":false});
    assert!(
        app.clone()
            .oneshot(request("register/begin", &cookie, None, body.clone()))
            .await?
            .status()
            .is_client_error()
    );
    let r = app
        .clone()
        .oneshot(request("register/begin", &cookie, Some(&csrf), body))
        .await?;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["cache-control"], "no-store");
    let start = json_body(r).await?;
    assert!(start.get("state").is_none());
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let response = authenticator.do_registration(
        url::Url::parse(ORIGIN)?,
        serde_json::from_value(start["options"].clone())?,
    )?;
    let body = json!({"id":start["id"],"response":response});
    let r = app
        .clone()
        .oneshot(request(
            "register/finish",
            &cookie,
            Some(&csrf),
            body.clone(),
        ))
        .await?;
    assert_eq!(r.status(), 200);
    let credential = json_body(r).await?;
    assert!(
        app.clone()
            .oneshot(request("register/finish", &cookie, Some(&csrf), body))
            .await?
            .status()
            .is_client_error()
    );
    let r = app
        .clone()
        .oneshot(request(
            "authenticate/begin",
            &cookie,
            Some(&csrf),
            json!({"operation":{"kind":"remove","credential":credential["id"]}}),
        ))
        .await?;
    assert_eq!(r.status(), 200);
    let start = json_body(r).await?;
    let response = authenticator.do_authentication(
        url::Url::parse(ORIGIN)?,
        serde_json::from_value(start["options"].clone())?,
    )?;
    let r = app
        .clone()
        .oneshot(request(
            "authenticate/finish",
            &cookie,
            Some(&csrf),
            json!({"id":start["id"],"response":response}),
        ))
        .await?;
    assert_eq!(r.status(), 200);
    let proof_cookie = r.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap();
    let proof = format!("{cookie}; {proof_cookie}");
    assert!(r.headers()["set-cookie"].to_str()?.contains("HttpOnly"));
    let cancelled = app
        .clone()
        .oneshot(request("operation/cancel", &proof, Some(&csrf), json!({})))
        .await?;
    assert_eq!(cancelled.status(), 200);
    assert!(
        cancelled.headers()["set-cookie"]
            .to_str()?
            .contains("Max-Age=0")
    );
    let removal_path = format!("credentials/{}/remove", credential["id"].as_str().unwrap());
    assert!(
        app.clone()
            .oneshot(request(&removal_path, &proof, Some(&csrf), json!({})))
            .await?
            .status()
            .is_client_error()
    );
    let r = app
        .clone()
        .oneshot(request(
            "authenticate/begin",
            &cookie,
            Some(&csrf),
            json!({"operation":{"kind":"remove","credential":credential["id"]}}),
        ))
        .await?;
    let start = json_body(r).await?;
    let response = authenticator.do_authentication(
        url::Url::parse(ORIGIN)?,
        serde_json::from_value(start["options"].clone())?,
    )?;
    let r = app
        .clone()
        .oneshot(request(
            "authenticate/finish",
            &cookie,
            Some(&csrf),
            json!({"id":start["id"],"response":response}),
        ))
        .await?;
    assert_eq!(r.status(), 200);
    let proof = format!(
        "{cookie}; {}",
        r.headers()["set-cookie"]
            .to_str()?
            .split(';')
            .next()
            .unwrap()
    );
    let path = format!("credentials/{}/remove", credential["id"].as_str().unwrap());
    assert!(
        app.clone()
            .oneshot(request(&path, &cookie, Some(&csrf), json!({})))
            .await?
            .status()
            .is_client_error()
    );
    assert_eq!(
        app.clone()
            .oneshot(request(&path, &proof, Some(&csrf), json!({})))
            .await?
            .status(),
        200
    );
    assert!(
        app.oneshot(request(&path, &proof, Some(&csrf), json!({})))
            .await?
            .status()
            .is_client_error()
    );
    f.close().await;
    Ok(())
}
