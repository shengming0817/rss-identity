#[path = "../../identity-postgres/tests/federation_support/mod.rs"]
mod federation_support;
#[allow(dead_code)]
#[path = "../../identity-postgres/tests/support/mod.rs"]
mod support;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use rss_identity_core::{cli::CliLoginBinding, federation::*};
use rss_identity_postgres::*;
use serde_json::{Value, json};
use std::time::Duration;
use support::*;
use tower::ServiceExt;
const ORIGIN: &str = "https://identity.example.test";
fn request(
    method: &str,
    path: &str,
    cookie: Option<&str>,
    csrf: Option<&str>,
    body: Value,
) -> Request<Body> {
    let mut r = Request::builder()
        .method(method)
        .uri(path)
        .header("origin", ORIGIN)
        .header("x-identity-request", "1")
        .header("content-type", "application/json");
    if let Some(v) = cookie {
        r = r.header("cookie", v);
    }
    if let Some(v) = csrf {
        r = r.header("x-csrf-token", v);
    }
    let mut r = r.body(Body::from(body.to_string())).unwrap();
    r.extensions_mut()
        .insert(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse().unwrap(),
        ));
    r
}
async fn json_body(r: axum::response::Response) -> anyhow::Result<Value> {
    Ok(serde_json::from_slice(
        &to_bytes(r.into_body(), 65536).await?,
    )?)
}
async fn session(app: &Router, domain: &str, login: &str) -> anyhow::Result<(String, String)> {
    let r = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/tenants/{domain}/login"),
            None,
            None,
            json!({"login":login,"password":PASSWORD}),
        ))
        .await?;
    assert_eq!(r.status(), StatusCode::OK);
    let cookie = r.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let value = json_body(r).await?;
    Ok((cookie, value["csrf_token"].as_str().unwrap().into()))
}
#[tokio::test]
#[ignore = "requires real PostgreSQL"]
async fn platform_http_enforces_roles_and_activates_created_tenants() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let config = rss_identity_http_axum::HttpConfig::new(ORIGIN, Duration::from_secs(30))?;
    let app = rss_identity_http_axum::router(f.store.clone(), config.clone())?.merge(
        rss_identity_http_axum::platform_router(f.store.clone(), config)?,
    );
    let (cookie, csrf) = session(&app, SYSTEM, "platform").await?;
    let (ordinary, ordinary_csrf) = session(&app, A, "admin").await?;
    let tenant = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    let operation = uuid::Uuid::new_v4();
    let principal = uuid::Uuid::new_v4();
    let body = json!({"tenant_id":tenant,"name":"Created through API","administrator":{"operation_id":operation,"principal_id":principal,"login":"new-admin","password":PASSWORD}});
    let denied = app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/platform/tenants",
            Some(&ordinary),
            Some(&ordinary_csrf),
            body.clone(),
        ))
        .await?;
    assert!(
        denied.status() == StatusCode::UNAUTHORIZED || denied.status() == StatusCode::FORBIDDEN
    );
    let denied = app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/platform/tenants",
            Some(&cookie),
            None,
            body.clone(),
        ))
        .await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let created = app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/platform/tenants",
            Some(&cookie),
            Some(&csrf),
            body.clone(),
        ))
        .await?;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(json_body(created).await?["active"], true);
    let _ = session(&app, tenant, "new-admin").await?;
    let repeated = app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/platform/tenants",
            Some(&cookie),
            Some(&csrf),
            body,
        ))
        .await?;
    assert_eq!(repeated.status(), StatusCode::CONFLICT);
    let read = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/api/v1/platform/operations/{operation}"),
            Some(&cookie),
            None,
            Value::Null,
        ))
        .await?;
    assert_eq!(read.status(), StatusCode::OK);
    let read = json_body(read).await?;
    assert_eq!(read["operation"]["principal_id"], principal.to_string());
    assert!(!read.to_string().contains(PASSWORD));
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PostgreSQL"]
async fn cli_sso_code_is_single_use_pkce_bound_and_revocable() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let s = federation_support::service(&f, federation_support::ScriptedOidc::new());
    let mut settings = federation_support::settings().input();
    settings.jit = false;
    let p = s
        .create_provider(
            f.platform_actor().await?,
            settings.try_into()?,
            ProviderCredentials::new("fixture-secret".into(), None)?,
            deadline(),
        )
        .await?;
    let p = s
        .enable_provider(f.platform_actor().await?, p.id, p.version, true, deadline())
        .await?;
    // Existing association is a fixture precondition; production association uses the separately tested link flow.
    sqlx::query(
        "INSERT INTO identity_authority.external_identities VALUES($1::uuid,$2,$3,$4::uuid,$5,$6)",
    )
    .bind(SYSTEM)
    .bind(uuid::Uuid::new_v4())
    .bind(f.system_key.principal.as_uuid())
    .bind(p.id.to_string())
    .bind(p.settings.issuer().as_str())
    .bind("platform-subject")
    .execute(&f.owner)
    .await?;
    let verifier = random_secret()?;
    let state = random_secret()?;
    let binding = CliLoginBinding::new(
        "http://127.0.0.1:49152/callback".into(),
        CliLoginBinding::challenge_for(&verifier),
        state.to_string(),
    )?;
    let redirect = s
        .begin_cli_login(
            p.id,
            binding.clone(),
            federation_support::BROWSER.into(),
            source(),
            deadline(),
        )
        .await?;
    let server_state = federation_support::state(redirect);
    let outcome = s
        .complete(
            server_state,
            federation_support::BROWSER.into(),
            zeroize::Zeroizing::new("platform-subject".into()),
            p.settings.issuer().as_str().into(),
            None,
            deadline(),
        )
        .await?;
    let FederatedOutcome::Redirect(redirect) = outcome else {
        panic!("browser must not receive a central session")
    };
    let url = url::Url::parse(&redirect.url)?;
    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(
        url.query_pairs().find(|(k, _)| k == "state").unwrap().1,
        state.as_str()
    );
    assert!(
        f.store
            .exchange_cli_login(
                zeroize::Zeroizing::new(code.clone()),
                random_secret()?,
                binding.redirect_uri().into(),
                source(),
                deadline()
            )
            .await
            .is_err()
    );
    let issued = f
        .store
        .exchange_cli_login(
            zeroize::Zeroizing::new(code.clone()),
            verifier,
            binding.redirect_uri().into(),
            source(),
            deadline(),
        )
        .await?;
    assert!(issued.identity().platform_administrator);
    assert!(!issued.identity().administrator);
    assert!(
        f.store
            .exchange_cli_login(
                zeroize::Zeroizing::new(code),
                random_secret()?,
                binding.redirect_uri().into(),
                source(),
                deadline()
            )
            .await
            .is_err()
    );
    let second = f
        .store
        .create_local_account(
            f.platform_actor().await?,
            login("other-platform"),
            password(),
            LocalAccountRole::Member,
            deadline(),
        )
        .await?;
    f.store
        .set_platform_role(
            f.platform_actor().await?,
            second.key().principal,
            true,
            deadline(),
        )
        .await?;
    f.store
        .set_platform_role(
            f.platform_actor().await?,
            f.system_key.principal,
            false,
            deadline(),
        )
        .await?;
    assert!(
        f.store
            .inspect_session(
                f.system_key.tenant,
                rss_identity_core::session::SessionSecret::parse(issued.secret().expose().into())?,
                deadline()
            )
            .await
            .is_err()
    );
    f.close().await;
    Ok(())
}
