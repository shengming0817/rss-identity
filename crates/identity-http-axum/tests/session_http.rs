//! Real PG + in-process Router seam (T2), without claiming product binary/TLS T3.
#[path = "../../identity-postgres/tests/support/mod.rs"]
mod support;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::Response,
};
use rss_identity_http_axum::{HttpConfig, router};
use rss_transactional_messaging_postgres::PgTransactionFault;
use serde_json::{Value, json};
use std::time::Duration;
use support::*;
use tower::ServiceExt;

const ORIGIN: &str = "https://identity.example.test";

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn public_session_reader_is_passive_and_rejects_revoked_credentials() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let app = app(&f);
    let (cookie, csrf, initial) = successful_login(&app).await?;
    let headers = request("GET", "session", Some(&cookie), None, json!(null))
        .headers()
        .clone();
    let proof =
        rss_identity_http_axum::inspect_session(&f.store, f.key.tenant, &headers, deadline())
            .await
            .unwrap();
    assert_eq!(proof.view().id.to_string(), initial["session"]["id"]);
    assert_eq!(
        proof.view().idle_expires_at,
        initial["session"]["idleExpiresAt"]
    );
    let mut ambiguous = headers.clone();
    ambiguous.append("cookie", cookie.parse()?);
    let error =
        rss_identity_http_axum::inspect_session(&f.store, f.key.tenant, &ambiguous, deadline())
            .await
            .err()
            .unwrap();
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert_eq!(error.headers()["cache-control"], "no-store");
    app.oneshot(request(
        "POST",
        "session/logout",
        Some(&cookie),
        Some(&csrf),
        json!(null),
    ))
    .await?;
    let error =
        rss_identity_http_axum::inspect_session(&f.store, f.key.tenant, &headers, deadline())
            .await
            .err()
            .unwrap();
    assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
    f.close().await;
    Ok(())
}
fn app(f: &Fixture) -> Router {
    router(
        f.store.clone(),
        HttpConfig::new(ORIGIN, Duration::from_secs(10)).unwrap(),
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
        .uri(format!("/api/v2/tenants/{A}/{path}"))
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
        .insert(rss_identity_http_axum::ClientAddress(
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
        &to_bytes(response.into_body(), 16_384).await?,
    )?)
}
async fn successful_login(app: &Router) -> anyhow::Result<(String, String, Value)> {
    let response = app.clone().oneshot(login_request(None, None)).await?;
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
        let response = app.clone().oneshot(req).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(!response.headers().contains_key("set-cookie"));
    }
    let (cookie, csrf, first) = successful_login(&app).await?;
    let response = app
        .clone()
        .oneshot(login_request(Some(&cookie), Some("wrong")))
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = app
        .clone()
        .oneshot(login_request(Some(&cookie), Some(&csrf)))
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
            .oneshot(request("GET", "session", Some(&cookie), None, json!(null)))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let csrf = replacement["csrfToken"].as_str().unwrap();
    let a = app.clone().oneshot(request(
        "POST",
        "session/refresh",
        Some(&new_cookie),
        Some(csrf),
        json!(null),
    ));
    let b = app.clone().oneshot(request(
        "POST",
        "session/refresh",
        Some(&new_cookie),
        Some(csrf),
        json!(null),
    ));
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
            .oneshot(request("GET", "sessions", Some(&cookie), None, json!(null)))
            .await?,
    )
    .await?;
    assert_eq!(list["sessions"].as_array().unwrap().len(), 1);
    assert!(!list.to_string().contains(cookie.split_once('=').unwrap().1));
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "sessions/logout-all",
            Some(&cookie),
            Some(csrf),
            json!(null),
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        response.headers()["set-cookie"]
            .to_str()?
            .contains("Max-Age=0")
    );
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "session", Some(&cookie), None, json!(null)))
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
        .oneshot(request(
            "POST",
            "session/refresh",
            Some(&cookie),
            Some(&csrf),
            json!(null),
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(f.events().await?, before + 1);
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "session", Some(&cookie), None, json!(null)))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let (cookie, csrf, _) = successful_login(&app).await?;
    let before = f.events().await?;
    sqlx::raw_sql("CREATE FUNCTION public.reject_http_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private-http-marker'; END $$; CREATE TRIGGER reject_http_event BEFORE INSERT ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.reject_http_event();").execute(&f.owner).await?;
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
        let response = app.clone().oneshot(req).await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.headers().contains_key("set-cookie"));
        assert!(
            !body(response)
                .await?
                .to_string()
                .contains("private-http-marker")
        );
    }
    assert_eq!(f.events().await?, before);
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "session", Some(&cookie), None, json!(null)))
            .await?
            .status(),
        StatusCode::OK
    );
    f.runtime.close().await;
    let response = app
        .oneshot(request("GET", "session", Some(&cookie), None, json!(null)))
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("set-cookie"));
    assert!(matches!(
        response
            .extensions()
            .get::<rss_identity_http_axum::HttpFailure>(),
        Some(rss_identity_http_axum::HttpFailure::Authority(_))
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
        app.clone().oneshot(req).await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let (cookie, csrf, value) = successful_login(&app).await?;
    let id = value["session"]["id"].as_str().unwrap();
    sqlx::query("UPDATE identity_authority.sessions SET auth_time=auth_time-100, absolute_expires_at=absolute_expires_at-100, idle_expires_at=auth_time+20 WHERE session_id=$1::uuid").bind(id).execute(&f.owner).await?;
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
        let response = app.clone().oneshot(req).await?;
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
    *req.uri_mut() = format!("/api/v2/tenants/{B}/session").parse()?;
    assert_eq!(
        app.clone().oneshot(req).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    let response = app
        .clone()
        .oneshot(request("GET", "session", Some(&cookie), None, json!(null)))
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
        assert_eq!(app.clone().oneshot(req).await?.status(), StatusCode::OK);
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
        .oneshot(request(
            "POST",
            "session/refresh",
            Some(&cookie),
            Some(&csrf),
            json!(null),
        ))
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
        .oneshot(request(
            "GET",
            "sessions?cursor=00000000-0000-0000-0000-000000000000",
            Some(&cookie),
            None,
            json!(null),
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    sqlx::query("UPDATE identity_authority.sessions SET idle_expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE session_id=$1::uuid").bind(id).execute(&f.owner).await?;
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "session", Some(&cookie), None, json!(null)))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // An expired browser cookie must not prevent a fresh same-origin password login.
    assert_eq!(
        app.clone()
            .oneshot(login_request(Some(&cookie), None))
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
        let status = app.clone().oneshot(req).await?.status();
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
        router(
            f.maintenance.clone(),
            HttpConfig::new(ORIGIN, Duration::from_secs(1))?
        )
        .is_err()
    );
    let response = app
        .clone()
        .oneshot(login_request(Some("__Host-identity-session=damaged"), None))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(login_request(
            Some("__Host-identity-session=damaged; __Host-identity-session=other"),
            None,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let (first, csrf, _) = successful_login(&app).await?;
    let (second, _, _) = successful_login(&app).await?;
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "session/logout",
            Some(&first),
            Some(&csrf),
            json!(null),
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        response.headers()["set-cookie"]
            .to_str()?
            .contains("Max-Age=0")
    );
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "session", Some(&first), None, json!(null)))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "session", Some(&second), None, json!(null)))
            .await?
            .status(),
        StatusCode::OK
    );
    let short = router(
        f.store.clone(),
        HttpConfig::new(ORIGIN, Duration::from_millis(40))?,
    )?;
    let mut req = login_request(None, None);
    *req.body_mut() = Body::from_stream(futures::stream::pending::<
        Result<&'static str, std::io::Error>,
    >());
    let response = tokio::time::timeout(Duration::from_millis(500), short.oneshot(req)).await??;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(
        response
            .extensions()
            .get::<rss_identity_http_axum::HttpFailure>(),
        Some(&rss_identity_http_axum::HttpFailure::RequestTimeout)
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
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_authority.guard")
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
            *req.uri_mut() = format!("/api/v2/tenants/{target}/session").parse()?;
            assert!(!app.clone().oneshot(req).await?.status().is_success());
        }
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identity_authority.guard")
            .fetch_one(&f.owner)
            .await?,
        before
    );
    let (cookie, _, _) = successful_login(&app).await?;
    // Even ON CONFLICT attempts fire BEFORE INSERT. Authentication must not attempt a write.
    sqlx::raw_sql("CREATE FUNCTION public.reject_guard_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'unexpected guard insert'; END $$; CREATE TRIGGER reject_guard_insert BEFORE INSERT ON identity_authority.guard FOR EACH ROW EXECUTE FUNCTION public.reject_guard_insert();").execute(&f.owner).await?;
    for (method, path) in [
        ("GET", "session"),
        ("HEAD", "session"),
        ("GET", "sessions"),
        ("HEAD", "sessions"),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(request(method, path, Some(&cookie), None, json!(null)))
                .await?
                .status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identity_authority.guard")
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
    use rss_identity_http_axum::HttpFailure;
    use rss_identity_postgres::AuthorityError;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let normal = app(&f);
    let short = router(
        f.store.clone(),
        HttpConfig::new(ORIGIN, Duration::from_millis(200))?,
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
            short.clone().oneshot(request(
                "POST",
                "session/refresh",
                Some(&cookie),
                Some(&csrf),
                json!(null),
            )),
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
            .oneshot(request("GET", "session", Some(&cookie), None, json!(null)))
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
async fn session_http_v2_reauthentication_is_bound_and_has_no_legacy_role_surface()
-> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let app = app(&f);
    let (cookie, csrf, first) = successful_login(&app).await?;
    assert_eq!(first["identity"].as_object().unwrap().len(), 2);
    assert!(first["identity"].get("administrator").is_none());
    for path in [
        format!("/api/v1/tenants/{A}/session"),
        "/auth/callback".into(),
        "/api/v2/oidc/callback".into(),
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "session/reauthenticate",
            Some(&cookie),
            None,
            json!({"password":PASSWORD}),
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    for value in [
        json!({"password":PASSWORD,"login":"another"}),
        json!({"password":PASSWORD,"administrator":true}),
    ] {
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "session/reauthenticate",
                Some(&cookie),
                Some(&csrf),
                value,
            ))
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key("set-cookie"));
    }
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "session/reauthenticate",
            Some(&cookie),
            Some(&csrf),
            json!({"password":PASSWORD}),
        ))
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
            .oneshot(request("GET", "session", Some(&cookie), None, json!(null)))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.oneshot(request(
            "GET",
            "session",
            Some(&replacement),
            None,
            json!(null)
        ))
        .await?
        .status(),
        StatusCode::OK
    );
    f.close().await;
    Ok(())
}
