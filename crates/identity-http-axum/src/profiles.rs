//! Profile management shares the cookie/CSRF and transaction policy owners.
use crate::{AppState, boundary::*, management::Error};
use axum::{
    Extension, Json, Router,
    extract::{Path, Request, State},
    http::HeaderMap,
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use rss_identity_core::{PrincipalId, account::AccountKey};
use rss_identity_postgres::{Authority, AuthorityError};
use uuid::Uuid;
mod dto;

pub(crate) fn router(
    authority: Authority,
    config: crate::HttpConfig,
) -> Result<Router, AuthorityError> {
    authority.require_runtime()?;
    let state = AppState { authority, config };
    Ok(Router::new()
        .route("/tenants/{tenant}/profile", get(current))
        .route(
            "/tenants/{tenant}/accounts/{principal}/profile",
            get(local).put(update),
        )
        .route(
            "/tenants/{tenant}/accounts/{principal}/profile/operations/{operation}",
            get(receipt),
        )
        .layer(axum::extract::DefaultBodyLimit::max(98_304))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            request_boundary,
        ))
        .with_state(state))
}
async fn actor(
    s: &AppState,
    t: &str,
    h: &HeaderMap,
    b: RequestBudget,
    write: bool,
) -> Result<rss_identity_postgres::AuthenticatedSession, Error> {
    let secret = cookie(h)?.ok_or(UNAUTH)?;
    if write {
        if unique(h, "x-identity-request")? != Some("1") {
            return Err(FORBIDDEN.into());
        }
        csrf(h, &secret)?;
    }
    Ok(s.authority
        .inspect_session(tenant(t)?, secret, b.remaining())
        .await?)
}
fn target(t: &str, p: &str) -> Result<AccountKey, Error> {
    Ok(AccountKey {
        tenant: tenant(t)?,
        principal: PrincipalId::parse(p).map_err(|_| BAD)?,
    })
}
async fn current(
    State(s): State<AppState>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    h: HeaderMap,
) -> Result<Response, Error> {
    let actor = actor(&s, &t, &h, b, false).await?;
    let profile = s.authority.current_profile(&actor, b.remaining()).await?;
    Ok(Json(dto::Observation::from(profile.view()?)).into_response())
}
async fn local(
    State(s): State<AppState>,
    Path((t, p)): Path<(String, String)>,
    Extension(b): Extension<RequestBudget>,
    h: HeaderMap,
) -> Result<Response, Error> {
    let actor = actor(&s, &t, &h, b, false).await?;
    Ok(Json(dto::Local::from(
        s.authority
            .read_local_profile(&actor, target(&t, &p)?, b.remaining())
            .await?,
    ))
    .into_response())
}
async fn update(
    State(s): State<AppState>,
    Path((t, p)): Path<(String, String)>,
    Extension(b): Extension<RequestBudget>,
    request: Request,
) -> Result<Response, Error> {
    let actor = actor(&s, &t, request.headers(), b, true).await?;
    let bytes = tokio::time::timeout_at(
        b.cutoff(),
        axum::body::to_bytes(request.into_body(), 98_304),
    )
    .await
    .map_err(|_| HttpError::request_timeout())?
    .map_err(|_| BAD)?;
    let change: dto::Change = serde_json::from_slice(&bytes).map_err(|_| BAD)?;
    let change = change.try_into().map_err(|_| BAD)?;
    Ok(Json(dto::Receipt::from(
        s.authority
            .update_local_profile(actor, target(&t, &p)?, change, b.remaining())
            .await?,
    ))
    .into_response())
}
async fn receipt(
    State(s): State<AppState>,
    Path((t, p, o)): Path<(String, String, String)>,
    Extension(b): Extension<RequestBudget>,
    h: HeaderMap,
) -> Result<Response, Error> {
    let actor = actor(&s, &t, &h, b, false).await?;
    let operation = Uuid::parse_str(&o).map_err(|_| BAD)?;
    Ok(Json(
        s.authority
            .local_profile_receipt(&actor, target(&t, &p)?, operation, b.remaining())
            .await?
            .map(dto::Receipt::from),
    )
    .into_response())
}
