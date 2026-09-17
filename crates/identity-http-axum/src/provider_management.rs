//! Optional OIDC management adapter.
use crate::{
    AppState, HttpConfig,
    boundary::*,
    dto,
    management::{Error, body},
};
use axum::{
    Extension, Json, Router,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use rss_identity_core::federation::*;
use rss_identity_postgres::{AuthenticatedSession, AuthorityError, Federation};
use serde::Deserialize;
type Result<T> = std::result::Result<T, Error>;
#[derive(Clone)]
struct Management {
    federation: Federation,
}
pub(crate) fn router(
    federation: Federation,
    config: HttpConfig,
) -> std::result::Result<Router, AuthorityError> {
    let authority = federation.authority();
    authority.require_runtime()?;
    Ok(Router::new()
        .route("/api/v2/tenants/{tenant}/login-options", get(options))
        .route(
            "/api/v2/tenants/{tenant}/providers",
            get(providers).post(create_provider),
        )
        .route(
            "/api/v2/tenants/{tenant}/providers/{provider}",
            put(update_provider),
        )
        .route(
            "/api/v2/tenants/{tenant}/providers/{provider}/enabled",
            post(provider_enabled),
        )
        .route(
            "/api/v2/tenants/{tenant}/providers/{provider}/test",
            post(test_provider),
        )
        .layer(axum::extract::DefaultBodyLimit::max(32768))
        .route_layer(middleware::from_fn_with_state(
            AppState { authority, config },
            request_boundary,
        ))
        .with_state(Management { federation }))
}
async fn actor(
    s: &Management,
    t: &str,
    h: &HeaderMap,
    b: RequestBudget,
    write: bool,
) -> Result<AuthenticatedSession> {
    let secret = cookie(h)?.ok_or(UNAUTH)?;
    if write {
        if unique(h, "x-identity-request")? != Some("1") {
            return Err(FORBIDDEN.into());
        }
        csrf(h, &secret)?;
    }
    Ok(s.federation
        .authority()
        .inspect_session(tenant(t)?, secret, b.remaining())
        .await?)
}
async fn options(
    State(s): State<Management>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
) -> Result<Response> {
    Ok(Json(dto::LoginOptions {
        providers: s
            .federation
            .login_options(tenant(&t)?, b.remaining())
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    })
    .into_response())
}
async fn providers(
    State(s): State<Management>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    h: HeaderMap,
) -> Result<Response> {
    let actor = actor(&s, &t, &h, b, false).await?;
    Ok(Json(dto::Providers {
        providers: s
            .federation
            .list_providers(actor, b.remaining())
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    })
    .into_response())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateProvider {
    settings: dto::ProviderSettings,
    client_secret: String,
    ca_pem: Option<String>,
}
async fn create_provider(
    State(s): State<Management>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    r: Request,
) -> Result<Response> {
    let actor = actor(&s, &t, r.headers(), b, true).await?;
    let v: CreateProvider = body(r, b).await?;
    let credentials =
        ProviderCredentials::new(v.client_secret, v.ca_pem).map_err(AuthorityError::from)?;
    let settings = v.settings.into_domain().map_err(AuthorityError::from)?;
    Ok((
        StatusCode::CREATED,
        Json(dto::Provider::from(
            s.federation
                .create_provider(actor, settings, credentials, b.remaining())
                .await?,
        )),
    )
        .into_response())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateProvider {
    expected_version: i64,
    settings: dto::ProviderSettings,
    client_secret: String,
    ca_pem: Option<String>,
}
async fn update_provider(
    State(s): State<Management>,
    Path((t, p)): Path<(String, ProviderId)>,
    Extension(b): Extension<RequestBudget>,
    r: Request,
) -> Result<Response> {
    let actor = actor(&s, &t, r.headers(), b, true).await?;
    let v: UpdateProvider = body(r, b).await?;
    let credentials =
        ProviderCredentials::new(v.client_secret, v.ca_pem).map_err(AuthorityError::from)?;
    let settings = v.settings.into_domain().map_err(AuthorityError::from)?;
    Ok(Json(dto::Provider::from(
        s.federation
            .update_provider(
                actor,
                p,
                v.expected_version,
                settings,
                credentials,
                b.remaining(),
            )
            .await?,
    ))
    .into_response())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderToggle {
    expected_version: i64,
    enabled: bool,
}
async fn provider_enabled(
    State(s): State<Management>,
    Path((t, p)): Path<(String, ProviderId)>,
    Extension(b): Extension<RequestBudget>,
    r: Request,
) -> Result<Response> {
    let actor = actor(&s, &t, r.headers(), b, true).await?;
    let v: ProviderToggle = body(r, b).await?;
    Ok(Json(dto::Provider::from(
        s.federation
            .enable_provider(actor, p, v.expected_version, v.enabled, b.remaining())
            .await?,
    ))
    .into_response())
}
async fn test_provider(
    State(s): State<Management>,
    Path((t, p)): Path<(String, ProviderId)>,
    Extension(b): Extension<RequestBudget>,
    h: HeaderMap,
) -> Result<Response> {
    let actor = actor(&s, &t, &h, b, true).await?;
    match s.federation.test_provider(actor, p, b.remaining()).await {
        Ok(report) => Ok(Json(serde_json::json!({"passed":true,"report":dto::ConnectionReport::from(report)})).into_response()),
        Err(AuthorityError::Federation(
            error @ (FederationError::Provider(_) | FederationError::Unavailable),
        )) => Ok(
            Json(serde_json::json!({"passed":false,"diagnostic":dto::ProviderDiagnostic::from(error.diagnostic())}))
                .into_response(),
        ),
        Err(error) => Err(error.into()),
    }
}
