//! Real PG + in-process Router seam (T2), without claiming product binary/TLS T3.
#[path = "../../identity-postgres/tests/support/mod.rs"]
mod support;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::Response,
};
use rss_identity_service_http::{ServiceEndpoints, routes};
use rss_identity_web_credentials::{
    CredentialError, HttpConfig, SessionActivity, authenticate_request,
};
use rss_transactional_messaging_postgres::PgTransactionFault;
use serde_json::{Value, json};
use std::time::Duration;
use support::*;
use tower::ServiceExt;

const ORIGIN: &str = "https://identity.example.test";

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn public_host_requests_enforce_activity_and_revocation() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let app = app(&f);
    let config = HttpConfig::new(ORIGIN, Duration::from_secs(10))?;
    let (cookie, csrf, initial) = successful_login(&app).await?;
    let mut headers = request("GET", "session", Some(&cookie), None, json!(null))
        .headers()
        .clone();
    headers.remove("origin");
    headers.remove("x-identity-request");
    let (proof, credential) = authenticate_request(
        &f.store,
        &config,
        crate::support::binding(f.key.tenant),
        &headers,
        SessionActivity::Passive,
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(proof.view().id.to_string(), initial["session"]["id"]);
    assert_eq!(credential.expose(), cookie.split_once('=').unwrap().1);
    assert_eq!(
        proof.view().idle_expires_at,
        initial["session"]["idleExpiresAt"]
    );
    let active = request("POST", "resource", Some(&cookie), Some(&csrf), json!(null))
        .headers()
        .clone();
    for mode in [SessionActivity::Passive, SessionActivity::Active] {
        for value in [
            format!("{cookie}; broken"),
            format!("{cookie}; {cookie}"),
            format!("{cookie}; extra={}", "x".repeat(8192)),
        ] {
            let mut malformed = active.clone();
            malformed.insert("cookie", value.parse()?);
            let error = authenticate_request(
                &f.store,
                &config,
                crate::support::binding(f.key.tenant),
                &malformed,
                mode,
                deadline(),
            )
            .await
            .err()
            .unwrap();
            assert_eq!(error, CredentialError::Malformed);
        }
        let mut duplicate = active.clone();
        duplicate.append("cookie", cookie.parse()?);
        assert_eq!(
            authenticate_request(
                &f.store,
                &config,
                crate::support::binding(f.key.tenant),
                &duplicate,
                mode,
                deadline()
            )
            .await
            .err()
            .unwrap(),
            CredentialError::Malformed
        );
    }
    for name in ["origin", "x-identity-request", "x-csrf-token"] {
        for duplicate in [false, true] {
            let mut rejected = active.clone();
            if duplicate {
                rejected.append(name, rejected[name].clone());
            } else {
                rejected.remove(name);
            }
            let error = authenticate_request(
                &f.store,
                &config,
                crate::support::binding(f.key.tenant),
                &rejected,
                SessionActivity::Active,
                deadline(),
            )
            .await
            .err()
            .unwrap();
            assert_eq!(
                error,
                if duplicate && name != "origin" {
                    CredentialError::Malformed
                } else {
                    CredentialError::Forbidden
                }
            );
        }
    }
    for (name, value) in [
        ("origin", "https://evil.example.test"),
        ("x-csrf-token", "wrong"),
        ("x-identity-request", "0"),
    ] {
        let mut rejected = active.clone();
        rejected.insert(name, value.parse()?);
        assert_eq!(
            authenticate_request(
                &f.store,
                &config,
                crate::support::binding(f.key.tenant),
                &rejected,
                SessionActivity::Active,
                deadline()
            )
            .await
            .err()
            .unwrap(),
            CredentialError::Forbidden
        );
    }
    for mode in [SessionActivity::Passive, SessionActivity::Active] {
        let error = authenticate_request(
            &f.store,
            &config,
            crate::support::binding(rss_request_context::TenantId::parse(B)?),
            &active,
            mode,
            deadline(),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            error,
            CredentialError::Invalid
                | CredentialError::Authority(rss_identity_postgres::AuthorityError::Rejected)
        ));
        let error = authenticate_request(
            &f.maintenance,
            &config,
            crate::support::binding(f.key.tenant),
            &active,
            mode,
            deadline(),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            error,
            CredentialError::Invalid
                | CredentialError::Authority(rss_identity_postgres::AuthorityError::Rejected)
        ));
        // Either the caller or HTTP configuration may provide the tighter budget.
        for (timeout, remaining) in [
            (Duration::from_secs(10), Duration::ZERO),
            (Duration::from_nanos(1), Duration::from_secs(10)),
        ] {
            let bounded = HttpConfig::new(ORIGIN, timeout)?;
            let error = authenticate_request(
                &f.store,
                &bounded,
                crate::support::binding(f.key.tenant),
                &active,
                mode,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(remaining),
            )
            .await
            .err()
            .unwrap();

            assert_eq!(
                error,
                if remaining.is_zero() {
                    CredentialError::Deadline
                } else {
                    CredentialError::Authority(
                        rss_identity_postgres::AuthorityError::DeadlineElapsed,
                    )
                }
            );
        }
    }
    // Every rejected request above leaves idle expiry unchanged.
    let (proof, _) = authenticate_request(
        &f.store,
        &config,
        crate::support::binding(f.key.tenant),
        &headers,
        SessionActivity::Passive,
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(
        proof.view().idle_expires_at,
        initial["session"]["idleExpiresAt"]
    );
    sqlx::query("UPDATE identity_authority.sessions SET idle_expires_at=idle_expires_at-5 WHERE session_id=$1::uuid")
        .bind(initial["session"]["id"].as_str().unwrap()).execute(&f.owner).await?;
    let (passive, _) = authenticate_request(
        &f.store,
        &config,
        crate::support::binding(f.key.tenant),
        &headers,
        SessionActivity::Passive,
        deadline(),
    )
    .await
    .unwrap();
    let (proof, _) = authenticate_request(
        &f.store,
        &config,
        crate::support::binding(f.key.tenant),
        &active,
        SessionActivity::Active,
        deadline(),
    )
    .await
    .unwrap();
    assert!(proof.view().idle_expires_at > passive.view().idle_expires_at);
    assert_eq!(
        proof.view().absolute_expires_at,
        passive.view().absolute_expires_at
    );
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let error = authenticate_request(
        &f.store,
        &config,
        crate::support::binding(f.key.tenant),
        &active,
        SessionActivity::Active,
        deadline(),
    )
    .await
    .err()
    .unwrap();

    assert!(matches!(
        error,
        CredentialError::Authority(rss_identity_postgres::AuthorityError::CommitUnknown(_))
    ));

    app.oneshot(crate::request_support::scoped(request(
        "POST",
        "session/logout",
        Some(&cookie),
        Some(&csrf),
        json!(null),
    )))
    .await?;
    for mode in [SessionActivity::Passive, SessionActivity::Active] {
        let error = authenticate_request(
            &f.store,
            &config,
            crate::support::binding(f.key.tenant),
            &active,
            mode,
            deadline(),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            error,
            CredentialError::Invalid
                | CredentialError::Authority(rss_identity_postgres::AuthorityError::Rejected)
        ));
    }
    f.runtime.close().await;
    let error = authenticate_request(
        &f.store,
        &config,
        crate::support::binding(f.key.tenant),
        &headers,
        SessionActivity::Passive,
        deadline(),
    )
    .await
    .err()
    .unwrap();

    assert!(matches!(error, CredentialError::Authority(_)));
    f.close().await;
    Ok(())
}

fn app(f: &Fixture) -> Router {
    routes(
        f.store.clone(),
        HttpConfig::new(ORIGIN, Duration::from_secs(10)).unwrap(),
        ServiceEndpoints::default(),
    )
    .unwrap()
}
fn request(
    method: &str,
    path: &str,
    cookie: Option<&str>,
    csrf: Option<&str>,
    body: Value,
) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(format!("/api/v1/identity/tenants/{A}/{path}"))
        .header("origin", ORIGIN)
        .header("content-type", "application/json")
        .header("x-identity-request", "1");
    if let Some(v) = cookie {
        req = req.header("cookie", v);
    }
    if let Some(v) = csrf {
        req = req.header("x-csrf-token", v);
    }
    let mut req = req.body(Body::from(body.to_string())).unwrap();
    req.extensions_mut()
        .insert(rss_identity_service_http::ClientAddress(
            "127.0.0.1".parse().unwrap(),
        ));
    req
}
fn login_request(cookie: Option<&str>, csrf: Option<&str>) -> Request<Body> {
    request(
        "POST",
        "login",
        cookie,
        csrf,
        json!({"login":"admin","password":PASSWORD}),
    )
}
async fn body(response: Response) -> anyhow::Result<Value> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 131_072).await?,
    )?)
}
async fn successful_login(app: &Router) -> anyhow::Result<(String, String, Value)> {
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(login_request(None, None)))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let header = response.headers()["set-cookie"].to_str()?.to_owned();
    assert!(header.contains("Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age="));
    assert!(!header.contains("Domain"));
    let value = body(response).await?;
    Ok((
        header.split(';').next().unwrap().into(),
        value["csrfToken"].as_str().unwrap().into(),
        value,
    ))
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_http_login_cookie_csrf_and_replacement() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let app = app(&f);
    for header in ["origin", "x-identity-request"] {
        let mut req = login_request(None, None);
        req.headers_mut().remove(header);
        let response = app
            .clone()
            .oneshot(crate::request_support::scoped(req))
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(!response.headers().contains_key("set-cookie"));
    }
    let (cookie, csrf, first) = successful_login(&app).await?;
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(login_request(
            Some(&cookie),
            Some("wrong"),
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(login_request(
            Some(&cookie),
            Some(&csrf),
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let new_cookie = response.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let replacement = body(response).await?;
    assert_ne!(replacement["session"]["id"], first["session"]["id"]);
    assert_ne!(new_cookie, cookie);
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "GET",
                "session",
                Some(&cookie),
                None,
                json!(null)
            )))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let csrf = replacement["csrfToken"].as_str().unwrap();
    let a = app.clone().oneshot(crate::request_support::scoped(request(
        "POST",
        "session/refresh",
        Some(&new_cookie),
        Some(csrf),
        json!(null),
    )));
    let b = app.clone().oneshot(crate::request_support::scoped(request(
        "POST",
        "session/refresh",
        Some(&new_cookie),
        Some(csrf),
        json!(null),
    )));
    let (a, b) = tokio::join!(a, b);
    let (a, b) = (a?, b?);
    let (success, failure) = if a.status() == StatusCode::OK {
        (a, b)
    } else {
        (b, a)
    };
    assert_eq!(success.status(), StatusCode::OK);
    assert_eq!(failure.status(), StatusCode::UNAUTHORIZED);
    assert!(!failure.headers().contains_key("set-cookie"));
    let cookie = success.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let rotated = body(success).await?;
    assert_eq!(rotated["session"]["id"], replacement["session"]["id"]);
    assert_eq!(
        rotated["session"]["absoluteExpiresAt"],
        replacement["session"]["absoluteExpiresAt"]
    );
    let csrf = rotated["csrfToken"].as_str().unwrap();
    let list = body(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "GET",
                "sessions",
                Some(&cookie),
                None,
                json!(null),
            )))
            .await?,
    )
    .await?;
    assert_eq!(list["sessions"].as_array().unwrap().len(), 1);
    assert!(!list.to_string().contains(cookie.split_once('=').unwrap().1));
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "POST",
            "sessions/logout-all",
            Some(&cookie),
            Some(csrf),
            json!(null),
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        response.headers()["set-cookie"]
            .to_str()?
            .contains("Max-Age=0")
    );
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "GET",
                "session",
                Some(&cookie),
                None,
                json!(null)
            )))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_http_settlement_never_sets_uncertain_cookie() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let app = app(&f);
    let (cookie, csrf, _) = successful_login(&app).await?;
    let before = f.events().await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "POST",
            "session/refresh",
            Some(&cookie),
            Some(&csrf),
            json!(null),
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(f.events().await?, before + 1);
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "GET",
                "session",
                Some(&cookie),
                None,
                json!(null)
            )))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let (cookie, csrf, _) = successful_login(&app).await?;
    let before = f.events().await?;
    sqlx::raw_sql("CREATE FUNCTION public.reject_http_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private-http-marker'; END $$; CREATE TRIGGER reject_http_event BEFORE INSERT ON rss_audit.records FOR EACH ROW EXECUTE FUNCTION public.reject_http_event();").execute(&f.owner).await?;
    for req in [
        login_request(None, None),
        request(
            "POST",
            "session/refresh",
            Some(&cookie),
            Some(&csrf),
            json!(null),
        ),
        request(
            "POST",
            "session/logout",
            Some(&cookie),
            Some(&csrf),
            json!(null),
        ),
        request(
            "POST",
            "sessions/logout-all",
            Some(&cookie),
            Some(&csrf),
            json!(null),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(crate::request_support::scoped(req))
            .await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.headers().contains_key("set-cookie"));
        assert!(
            !body(response)
                .await?
                .to_string()
                .contains("private-http-marker")
        );
    }
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::RollbackFailedAfterAck);
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "POST",
            "session/refresh",
            Some(&cookie),
            Some(&csrf),
            json!(null),
        )))
        .await?;
    assert!(matches!(
        response
            .extensions()
            .get::<rss_identity_service_http::HttpFailure>(),
        Some(rss_identity_service_http::HttpFailure::Authority(
            rss_identity_postgres::AuthorityError::RollbackFailed(_)
        ))
    ));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(f.events().await?, before);
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "GET",
                "session",
                Some(&cookie),
                None,
                json!(null)
            )))
            .await?
            .status(),
        StatusCode::OK
    );
    f.runtime.close().await;
    let response = app
        .oneshot(crate::request_support::scoped(request(
            "GET",
            "session",
            Some(&cookie),
            None,
            json!(null),
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("set-cookie"));
    assert!(matches!(
        response
            .extensions()
            .get::<rss_identity_service_http::HttpFailure>(),
        Some(rss_identity_service_http::HttpFailure::Authority(_))
    ));
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_http_origin_expiry_and_transport_boundaries() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let app = app(&f);
    let mut req = login_request(None, None);
    req.extensions_mut().clear();
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(req))
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let (cookie, csrf, value) = successful_login(&app).await?;
    let id = value["session"]["id"].as_str().unwrap();
    sqlx::query("UPDATE identity_authority.sessions SET issued_at=issued_at-100,local_authenticated_at=CASE WHEN authentication_source='local_password' THEN issued_at-100 ELSE local_authenticated_at END, absolute_expires_at=absolute_expires_at-100, idle_expires_at=issued_at+20 WHERE session_id=$1::uuid").bind(id).execute(&f.owner).await?;
    let idle: i64 = sqlx::query_scalar(
        "SELECT idle_expires_at FROM identity_authority.sessions WHERE session_id=$1::uuid",
    )
    .bind(id)
    .fetch_one(&f.owner)
    .await?;
    for (origin, token) in [
        ("https://evil.example.test", csrf.as_str()),
        ("null", csrf.as_str()),
        (ORIGIN, "wrong"),
    ] {
        let mut req = request(
            "POST",
            "session/refresh",
            Some(&cookie),
            Some(token),
            json!(null),
        );
        req.headers_mut().insert("origin", origin.parse()?);
        let response = app
            .clone()
            .oneshot(crate::request_support::scoped(req))
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!response.headers().contains_key("set-cookie"));
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT idle_expires_at FROM identity_authority.sessions WHERE session_id=$1::uuid"
        )
        .bind(id)
        .fetch_one(&f.owner)
        .await?,
        idle
    );
    let mut req = request("GET", "session", Some(&cookie), None, json!(null));
    *req.uri_mut() = format!("/api/v1/identity/tenants/{B}/session").parse()?;
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(req))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "GET",
            "session",
            Some(&cookie),
            None,
            json!(null),
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key("set-cookie"));
    let after = body(response).await?;
    assert_eq!(after["session"]["idleExpiresAt"].as_i64().unwrap(), idle);
    // Lax cookies may accompany cross-site top-level navigation: safe methods cannot renew idle.
    for (method, path) in [
        ("GET", "session"),
        ("HEAD", "session"),
        ("GET", "sessions"),
        ("HEAD", "sessions"),
    ] {
        let mut req = request(method, path, Some(&cookie), None, json!(null));
        req.headers_mut()
            .insert("origin", "https://evil.example.test".parse()?);
        assert_eq!(
            app.clone()
                .oneshot(crate::request_support::scoped(req))
                .await?
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT idle_expires_at FROM identity_authority.sessions WHERE session_id=$1::uuid"
            )
            .bind(id)
            .fetch_one(&f.owner)
            .await?,
            idle
        );
    }
    let rotated = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "POST",
            "session/refresh",
            Some(&cookie),
            Some(&csrf),
            json!(null),
        )))
        .await?;
    assert_eq!(rotated.status(), StatusCode::OK);
    let cookie = rotated.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let value = body(rotated).await?;
    assert!(value["session"]["idleExpiresAt"].as_i64().unwrap() > idle);
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "GET",
            "sessions?cursor=00000000-0000-0000-0000-000000000000",
            Some(&cookie),
            None,
            json!(null),
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    sqlx::query("UPDATE identity_authority.sessions SET idle_expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE session_id=$1::uuid").bind(id).execute(&f.owner).await?;
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "GET",
                "session",
                Some(&cookie),
                None,
                json!(null)
            )))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // An expired browser cookie must not prevent a fresh same-origin password login.
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(login_request(
                Some(&cookie),
                None
            )))
            .await?
            .status(),
        StatusCode::OK
    );
    f.reset_attempts().await?;
    for i in 0..31 {
        let mut req = request(
            "POST",
            "login",
            None,
            None,
            json!({"login":format!("absent-{i}"),"password":PASSWORD}),
        );
        req.headers_mut()
            .insert("x-forwarded-for", format!("192.0.2.{i}").parse()?);
        let status = app
            .clone()
            .oneshot(crate::request_support::scoped(req))
            .await?
            .status();
        assert_eq!(
            status,
            if i < 30 {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
    }
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_http_recovery_current_logout_and_deadline() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let app = app(&f);
    assert!(
        routes(
            f.maintenance.clone(),
            HttpConfig::new(ORIGIN, Duration::from_secs(1))?,
            ServiceEndpoints::default()
        )
        .is_err()
    );
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(login_request(
            Some("__Host-identity-session=damaged"),
            None,
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(login_request(
            Some("__Host-identity-session=damaged; __Host-identity-session=other"),
            None,
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let (first, csrf, _) = successful_login(&app).await?;
    let (second, _, _) = successful_login(&app).await?;
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "POST",
            "session/logout",
            Some(&first),
            Some(&csrf),
            json!(null),
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        response.headers()["set-cookie"]
            .to_str()?
            .contains("Max-Age=0")
    );
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "GET",
                "session",
                Some(&first),
                None,
                json!(null)
            )))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "GET",
                "session",
                Some(&second),
                None,
                json!(null)
            )))
            .await?
            .status(),
        StatusCode::OK
    );
    let short = routes(
        f.store.clone(),
        HttpConfig::new(ORIGIN, Duration::from_millis(40))?,
        ServiceEndpoints::default(),
    )?;
    let mut expired =
        crate::request_support::scoped(request("GET", "session", None, None, json!(null)));
    expired
        .extensions_mut()
        .insert(rss_request_context::Deadline::at(std::time::Instant::now()));
    let rejected = short.clone().oneshot(expired).await?;
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rejected.headers()["cache-control"], "no-store");
    assert_eq!(rejected.headers()["referrer-policy"], "no-referrer");
    let mut req = login_request(None, None);
    *req.body_mut() = Body::from_stream(futures::stream::pending::<
        Result<&'static str, std::io::Error>,
    >());
    let response = tokio::time::timeout(
        Duration::from_millis(500),
        short.oneshot(crate::request_support::scoped(req)),
    )
    .await??;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(
        response
            .extensions()
            .get::<rss_identity_service_http::HttpFailure>(),
        Some(&rss_identity_service_http::HttpFailure::RequestTimeout)
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_http_lookup_never_inserts_tenant_guard() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let app = app(&f);
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_authority.tenants")
        .fetch_one(&f.owner)
        .await?;
    let fake = format!("__Host-identity-session={}", "a".repeat(64));
    for target in [
        B.to_string(),
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
    ] {
        for method in ["GET", "HEAD"] {
            let mut req = request(method, "session", Some(&fake), None, json!(null));
            *req.uri_mut() = format!("/api/v1/identity/tenants/{target}/session").parse()?;
            assert!(
                !app.clone()
                    .oneshot(crate::request_support::scoped(req))
                    .await?
                    .status()
                    .is_success()
            );
        }
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identity_authority.tenants")
            .fetch_one(&f.owner)
            .await?,
        before
    );
    let (cookie, _, _) = successful_login(&app).await?;
    // Even ON CONFLICT attempts fire BEFORE INSERT. Authentication must not attempt a write.
    sqlx::raw_sql("CREATE FUNCTION public.reject_guard_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'unexpected guard insert'; END $$; CREATE TRIGGER reject_guard_insert BEFORE INSERT ON identity_authority.tenants FOR EACH ROW EXECUTE FUNCTION public.reject_guard_insert();").execute(&f.owner).await?;
    for (method, path) in [
        ("GET", "session"),
        ("HEAD", "session"),
        ("GET", "sessions"),
        ("HEAD", "sessions"),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(crate::request_support::scoped(request(
                    method,
                    path,
                    Some(&cookie),
                    None,
                    json!(null)
                )))
                .await?
                .status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identity_authority.tenants")
            .fetch_one(&f.owner)
            .await?,
        before
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_http_pending_commit_preserves_settlement() -> anyhow::Result<()> {
    use rss_identity_postgres::AuthorityError;
    use rss_identity_service_http::HttpFailure;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let normal = app(&f);
    let short = routes(
        f.store.clone(),
        HttpConfig::new(ORIGIN, Duration::from_millis(200))?,
        ServiceEndpoints::default(),
    )?;
    for (fault, committed) in [
        (PgTransactionFault::CommitPending, false),
        (PgTransactionFault::CommitAcknowledgedPending, true),
    ] {
        let (cookie, csrf, _) = successful_login(&normal).await?;
        let before = f.events().await?;
        f.runtime.inject_next_transaction_fault(fault);
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            short
                .clone()
                .oneshot(crate::request_support::scoped(request(
                    "POST",
                    "session/refresh",
                    Some(&cookie),
                    Some(&csrf),
                    json!(null),
                ))),
        )
        .await??;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            matches!(
                response.extensions().get::<HttpFailure>(),
                Some(HttpFailure::Authority(AuthorityError::CommitUnknown(_)))
            ),
            "classification: {:?}",
            response.extensions().get::<HttpFailure>()
        );
        assert!(!response.headers().contains_key("set-cookie"));
        assert_eq!(f.events().await?, before + i64::from(committed));
        let response = normal
            .clone()
            .oneshot(crate::request_support::scoped(request(
                "GET",
                "session",
                Some(&cookie),
                None,
                json!(null),
            )))
            .await?;
        assert_eq!(
            response.status(),
            if committed {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::OK
            }
        );
    }
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_http_reauthentication_preserves_identity_and_rotates_credentials()
-> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let app = app(&f);
    let (cookie, csrf, first) = successful_login(&app).await?;
    // The public prefix counts toward the URI budget, even inside a nested Router.
    let prefix = format!("/api/v1/identity/tenants/{A}/session?padding=");
    for (length, expected) in [(8192, StatusCode::OK), (8193, StatusCode::BAD_REQUEST)] {
        let path = format!("{prefix}{}", "a".repeat(length - prefix.len()));
        let mut req = request("GET", "session", Some(&cookie), None, json!(null));
        *req.uri_mut() = path.parse()?;
        let response = app
            .clone()
            .oneshot(crate::request_support::scoped(req))
            .await?;
        assert_eq!(response.status(), expected);
        assert!(!response.headers().contains_key("set-cookie"));
    }
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "POST",
            "session/reauthenticate",
            Some(&cookie),
            None,
            json!({"password":PASSWORD}),
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    for value in [
        json!({"password":PASSWORD,"login":"another"}),
        json!({"password":PASSWORD,"administrator":true}),
    ] {
        let response = app
            .clone()
            .oneshot(crate::request_support::scoped(request(
                "POST",
                "session/reauthenticate",
                Some(&cookie),
                Some(&csrf),
                value,
            )))
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key("set-cookie"));
    }
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "POST",
            "session/reauthenticate",
            Some(&cookie),
            Some(&csrf),
            json!({"password":PASSWORD}),
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let replacement = response.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let value = body(response).await?;
    assert_ne!(replacement, cookie);
    assert_eq!(
        value["identity"]["principalId"],
        first["identity"]["principalId"]
    );
    assert_ne!(value["session"]["id"], first["session"]["id"]);
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "GET",
                "session",
                Some(&cookie),
                None,
                json!(null)
            )))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.oneshot(crate::request_support::scoped(request(
            "GET",
            "session",
            Some(&replacement),
            None,
            json!(null)
        )))
        .await?
        .status(),
        StatusCode::OK
    );
    f.close().await;
    Ok(())
}

fn bearer_app(f: &Fixture) -> Router {
    routes(
        f.store.clone(),
        HttpConfig::new(ORIGIN, Duration::from_secs(10)).unwrap(),
        ServiceEndpoints {
            programmatic_bearer: true,
            ..Default::default()
        },
    )
    .unwrap()
}
fn bearer_login() -> Request<Body> {
    let mut req = request(
        "POST",
        "bearer/login",
        None,
        None,
        json!({"login":"admin","password":PASSWORD}),
    );
    req.headers_mut().remove("origin");
    req.headers_mut().remove("x-identity-request");
    req
}
fn bearer_headers(secret: &str) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("authorization", format!("Bearer {secret}").parse().unwrap());
    headers
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn bearer_http_lifecycle_and_presentation_are_independent() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let app = bearer_app(&f);
    let config = HttpConfig::new(ORIGIN, Duration::from_secs(10))?;
    let (cookie, csrf, _) = successful_login(&app).await?;
    // Browser router alone must not expose a programmatic issuance bypass.
    assert_eq!(super_router_status(&f).await?, StatusCode::NOT_FOUND);
    for headers in [
        axum::http::HeaderMap::new(),
        bearer_headers(&"a".repeat(64)),
    ] {
        let error = rss_identity_web_credentials::authenticate_bearer_request(
            &f.store,
            &config,
            crate::support::binding(f.key.tenant),
            &headers,
            deadline(),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            error,
            CredentialError::Invalid
                | CredentialError::Authority(rss_identity_postgres::AuthorityError::Rejected)
        ));

        let mut logout = request("POST", "bearer/logout", None, None, json!(null));
        logout.headers_mut().extend(headers);
        let response = app
            .clone()
            .oneshot(crate::request_support::scoped(logout))
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["www-authenticate"], "Bearer");
    }
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(bearer_login()))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(!response.headers().contains_key("www-authenticate"));
    assert!(!response.headers().contains_key("set-cookie"));
    let issued = body(response).await?;
    let token = issued["accessToken"].as_str().unwrap();
    assert_eq!(issued["tokenType"], "Bearer");
    assert!(
        issued["absoluteExpiresAt"].as_i64().unwrap() > issued["idleExpiresAt"].as_i64().unwrap()
    );
    let headers = bearer_headers(token);
    let (proof, retained) = rss_identity_web_credentials::authenticate_bearer_request(
        &f.store,
        &config,
        crate::support::binding(f.key.tenant),
        &headers,
        deadline(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("bearer rejected"))?;
    assert_eq!(proof.view().id.to_string(), issued["sessionId"]);
    assert_eq!(retained.expose(), token);
    for (name, value) in [
        ("cookie", cookie.clone()),
        ("x-api-key", "opaque-key".into()),
        ("authorization", format!("Bearer {token}")),
    ] {
        let mut mixed = headers.clone();
        mixed.append(name, value.parse()?);
        let error = rss_identity_web_credentials::authenticate_bearer_request(
            &f.store,
            &config,
            crate::support::binding(f.key.tenant),
            &mixed,
            deadline(),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error, CredentialError::Malformed);

        assert!(!format!("{error:?}").contains(token));
    }
    let mut mixed = request("GET", "session", Some(&cookie), None, json!(null));
    mixed
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse()?);
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(mixed))
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    let fake_cookie = format!("__Host-identity-session={token}");
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "GET",
                "session",
                Some(&fake_cookie),
                None,
                json!(null)
            )))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let browser_secret = cookie.split_once('=').unwrap().1;
    let error = rss_identity_web_credentials::authenticate_bearer_request(
        &f.store,
        &config,
        crate::support::binding(f.key.tenant),
        &bearer_headers(browser_secret),
        deadline(),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(
        error,
        CredentialError::Authority(rss_identity_postgres::AuthorityError::Rejected)
    ));
    let mut logout = request("POST", "bearer/logout", None, None, json!(null));
    logout.headers_mut().remove("origin");
    logout
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse()?);
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(logout))
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(
        rss_identity_web_credentials::authenticate_bearer_request(
            &f.store,
            &config,
            crate::support::binding(f.key.tenant),
            &headers,
            deadline()
        )
        .await
        .err()
        .unwrap(),
        CredentialError::Authority(rss_identity_postgres::AuthorityError::Rejected)
    );
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "POST",
                "session/logout",
                Some(&cookie),
                Some(&csrf),
                json!(null)
            )))
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    f.close().await;
    Ok(())
}
async fn super_router_status(f: &Fixture) -> anyhow::Result<StatusCode> {
    Ok(app(f)
        .oneshot(crate::request_support::scoped(bearer_login()))
        .await?
        .status())
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn bearer_http_admission_shared_limits_and_failed_issuance() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let app = bearer_app(&f);
    for name in ["cookie", "authorization", "x-api-key"] {
        let mut req = bearer_login();
        req.headers_mut().insert(
            name,
            (if name == "cookie" {
                "__Host-identity-session=broken"
            } else {
                "invalid"
            })
            .parse()?,
        );
        assert_eq!(
            app.clone()
                .oneshot(crate::request_support::scoped(req))
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let mut missing_source = bearer_login();
    missing_source
        .extensions_mut()
        .remove::<rss_identity_service_http::ClientAddress>();
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(missing_source))
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let mut query = bearer_login();
    *query.uri_mut() =
        format!("/api/v1/identity/tenants/{A}/bearer/login?password=secret-marker").parse()?;
    let denied = app
        .clone()
        .oneshot(crate::request_support::scoped(query))
        .await?;
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
    assert!(
        !String::from_utf8(to_bytes(denied.into_body(), 4096).await?.to_vec())?
            .contains("secret-marker")
    );
    for i in 0..5 {
        let path = if i % 2 == 0 { "login" } else { "bearer/login" };
        let response = app
            .clone()
            .oneshot(crate::request_support::scoped(request(
                "POST",
                path,
                None,
                None,
                json!({"login":"admin","password":"incorrect-password"}),
            )))
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let limited = app
        .clone()
        .oneshot(crate::request_support::scoped(bearer_login()))
        .await?;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry: u32 = limited.headers()["retry-after"].to_str()?.parse()?;
    assert!((590..=600).contains(&retry));
    assert_eq!(body(limited).await?, json!({"code":"rate_limited"}));
    f.reset_attempts().await?;
    sqlx::raw_sql("CREATE FUNCTION public.reject_programmatic_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private-event-marker'; END $$; CREATE TRIGGER reject_programmatic_event BEFORE INSERT ON rss_audit.records FOR EACH ROW EXECUTE FUNCTION public.reject_programmatic_event();").execute(&f.owner).await?;
    let response = app
        .clone()
        .oneshot(crate::request_support::scoped(bearer_login()))
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("set-cookie"));
    let value = body(response).await?;
    assert!(value.get("accessToken").is_none());
    assert!(!value.to_string().contains("private-event-marker"));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_authority.sessions")
        .fetch_one(&f.owner)
        .await?;
    assert_eq!(count, 0);
    sqlx::raw_sql("DROP TRIGGER reject_programmatic_event ON rss_audit.records; DROP FUNCTION public.reject_programmatic_event()").execute(&f.owner).await?;
    for i in 0..7 {
        let path = if i % 2 == 0 { "login" } else { "bearer/login" };
        let response = app
            .clone()
            .oneshot(crate::request_support::scoped(request(
                "POST",
                path,
                None,
                None,
                json!({"login":"admin","password":PASSWORD}),
            )))
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "correct passwords share no failure quota"
        );
        assert!(!response.headers().contains_key("retry-after"));
    }
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn profile_http_requires_policy_csrf_and_exact_receipts() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let app = app(&f);
    let (cookie, csrf, _) = successful_login(&app).await?;
    let path = format!("accounts/{}/profile", f.key.principal.as_uuid());
    let operation = uuid::Uuid::now_v7();
    let mut extensions = serde_json::Map::new();
    extensions.insert("remote".into(), json!(false));
    for i in 0..1022 {
        extensions.insert(format!("field{i}"), json!(i));
    }
    extensions.insert("array".into(), json!(vec![0; 1024]));
    let input = json!({"operationId":operation,"expectedRevision":0,"value":{"displayName":"Name","username":null,"email":null,"extensions":extensions,"maxAgeSeconds":60}});
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "PUT",
                &path,
                Some(&cookie),
                None,
                input.clone()
            )))
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    let result = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "PUT",
            &path,
            Some(&cookie),
            Some(&csrf),
            input.clone(),
        )))
        .await?;
    assert_eq!(result.status(), StatusCode::OK);
    assert_eq!(result.headers()["cache-control"], "no-store");
    assert!(!result.headers().contains_key("set-cookie"));
    assert_eq!(
        body(result).await?,
        json!({"operationId":operation,"revision":1})
    );
    let stale = uuid::Uuid::new_v7(uuid::Timestamp::from_unix(uuid::NoContext, 1, 0));
    for (id, status) in [
        (uuid::Uuid::new_v4(), StatusCode::BAD_REQUEST),
        (stale, StatusCode::GONE),
    ] {
        let mut changed = input.clone();
        changed["operationId"] = json!(id);
        for (method, uri, data) in [
            ("GET", format!("{path}/operations/{id}"), json!(null)),
            ("PUT", path.clone(), changed),
        ] {
            let response = app
                .clone()
                .oneshot(crate::request_support::scoped(request(
                    method,
                    &uri,
                    Some(&cookie),
                    Some(&csrf),
                    data,
                )))
                .await?;
            assert_eq!(response.status(), status);
            if status == StatusCode::GONE {
                assert_eq!(body(response).await?["code"], "profile_operation_expired");
            }
        }
    }
    let saved = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "GET",
            &path,
            Some(&cookie),
            None,
            json!(null),
        )))
        .await?;
    assert_eq!(
        body(saved).await?,
        json!({"revision":1,"value":input["value"]})
    );
    let missing = json!({"operationId":uuid::Uuid::now_v7(),"expectedRevision":1});
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "PUT",
                &path,
                Some(&cookie),
                Some(&csrf),
                missing
            )))
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    let unchanged = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "GET",
            &path,
            Some(&cookie),
            None,
            json!(null),
        )))
        .await?;
    assert_eq!(
        body(unchanged).await?,
        json!({"revision":1,"value":input["value"]})
    );
    let mut invalid = input.clone();
    invalid["value"]["emailVerified"] = json!(true);
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "PUT",
                &path,
                Some(&cookie),
                Some(&csrf),
                invalid
            )))
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    let receipt = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "GET",
            &format!("{path}/operations/{operation}"),
            Some(&cookie),
            None,
            json!(null),
        )))
        .await?;
    assert_eq!(body(receipt).await?["revision"], 1);
    let mut conflict = input.clone();
    conflict["value"]["displayName"] = json!("Other");
    let result = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "PUT",
            &path,
            Some(&cookie),
            Some(&csrf),
            conflict,
        )))
        .await?;
    assert_eq!(result.status(), StatusCode::CONFLICT);
    assert_eq!(body(result).await?["code"], "operation_conflict");
    let mut conflict = input.clone();
    conflict["operationId"] = json!(uuid::Uuid::now_v7());
    let result = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "PUT",
            &path,
            Some(&cookie),
            Some(&csrf),
            conflict,
        )))
        .await?;
    assert_eq!(result.status(), StatusCode::CONFLICT);
    assert_eq!(body(result).await?["code"], "revision_conflict");
    let deletion = json!({"operationId":uuid::Uuid::now_v7(),"expectedRevision":1,"value":null});
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "PUT",
                &path,
                Some(&cookie),
                Some(&csrf),
                deletion
            )))
            .await?
            .status(),
        StatusCode::OK
    );
    let deleted = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "GET",
            &path,
            Some(&cookie),
            None,
            json!(null),
        )))
        .await?;
    assert_eq!(body(deleted).await?, json!({"revision":2,"value":null}));
    // Compact JSON and PostgreSQL JSONB have different encoding overheads.
    let mut arrays = vec![vec![0; 1023]; 32];
    arrays.last_mut().unwrap().truncate(1019);
    let expanded = json!({"x":arrays});
    assert!(serde_json::to_vec(&expanded)?.len() <= rss_identity_core::profile::MAX_BYTES);
    let value = json!({"displayName":"n".repeat(512),"username":"u".repeat(256),"email":"e".repeat(320),"extensions":expanded,"maxAgeSeconds":3600});
    let write = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "PUT",
            &path,
            Some(&cookie),
            Some(&csrf),
            json!({"operationId":uuid::Uuid::now_v7(),"expectedRevision":2,"value":value}),
        )))
        .await?;
    assert_eq!(write.status(), StatusCode::OK);
    let read = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "GET",
            &path,
            Some(&cookie),
            None,
            json!(null),
        )))
        .await?;
    assert_eq!(body(read).await?["value"], value);
    let (fresh_cookie, _, _) = successful_login(&app).await?;
    let observation = app
        .clone()
        .oneshot(crate::request_support::scoped(request(
            "GET",
            "profile",
            Some(&fresh_cookie),
            None,
            json!(null),
        )))
        .await?;
    assert_eq!(observation.status(), StatusCode::OK);
    assert_eq!(
        body(observation).await?["profile"]["extensions"]["value"],
        expanded
    );
    f.policy.revoke(f.key);
    assert_eq!(
        app.clone()
            .oneshot(crate::request_support::scoped(request(
                "GET",
                &path,
                Some(&cookie),
                None,
                json!(null)
            )))
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.oneshot(crate::request_support::scoped(request(
            "GET",
            "profile",
            Some(&cookie),
            None,
            json!(null)
        )))
        .await?
        .status(),
        StatusCode::OK
    );
    f.close().await;
    Ok(())
}

#[path = "request_support/mod.rs"]
mod request_support;
