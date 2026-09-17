use crate::{AppState, boundary::*};
use axum::{
    Extension, Json,
    extract::{FromRequest, Path, Query, Request, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use rss_identity_core::SessionId;
use rss_identity_core::{
    account::{LoginKey, Password},
    session::SessionSecret,
};
use rss_identity_postgres::{AttemptSource, AuthenticatedSession, AuthorityError, IssuedSession};
use serde::Deserialize;

type Result<T> = std::result::Result<T, HttpError>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    login: String,
    password: String,
}
pub(crate) fn issued(value: IssuedSession) -> Result<Response> {
    let max_age = value.cookie_max_age();
    if max_age == 0 {
        return Err(HttpError::from(AuthorityError::Unavailable));
    }
    let header = session_cookie(value.secret(), max_age)
        .parse()
        .map_err(|_| HttpError::from(AuthorityError::Unavailable))?;
    let mut response = Json(project_session(
        value.identity(),
        value.view(),
        value.secret().csrf(),
    ))
    .into_response();
    response.headers_mut().insert(header::SET_COOKIE, header);
    Ok(response)
}
fn project_session(
    identity: &rss_identity_postgres::SessionIdentity,
    view: &rss_identity_postgres::SessionView,
    csrf_token: String,
) -> crate::dto::Issued {
    use crate::dto::{Identity, Issued, SessionInfo};
    Issued {
        identity: Identity {
            principal_id: identity.principal_id.to_string(),
            has_local_password: identity.has_local_password,
        },
        session: SessionInfo {
            id: view.id.to_string(),
            auth_time: view.auth_time,
            idle_expires_at: view.idle_expires_at,
            absolute_expires_at: view.absolute_expires_at,
        },
        csrf_token,
    }
}
pub(crate) async fn login(
    State(state): State<AppState>,
    Path(raw): Path<String>,
    Extension(budget): Extension<RequestBudget>,
    request: Request,
) -> Result<Response> {
    let tenant = tenant(&raw)?;
    if unique(request.headers(), "x-identity-request")? != Some("1") {
        return Err(FORBIDDEN);
    }
    let peer = request
        .extensions()
        .get::<crate::ClientAddress>()
        .ok_or(HttpError::from(AuthorityError::Unavailable))?
        .0;
    let source = AttemptSource::parse(&peer.to_string()).map_err(HttpError::from)?;
    let replacement = match login_cookie(request.headers())? {
        Some(secret) => {
            let token = SessionSecret::parse(secret.expose().into()).map_err(|_| UNAUTH)?;
            match state
                .authority
                .inspect_session(tenant, token, budget.remaining())
                .await
            {
                Ok(proof) => {
                    csrf(request.headers(), &secret)?;
                    Some(proof)
                }
                Err(AuthorityError::Rejected) => None,
                Err(e) => return Err(e.into()),
            }
        }
        None => None,
    };
    // Only inbound body reading is cancelled here; no write transaction has started.
    let Json(input) = tokio::time::timeout_at(
        budget.cutoff(),
        Json::<Login>::from_request(request, &state),
    )
    .await
    .map_err(|_| HttpError::request_timeout())?
    .map_err(|_| BAD)?;
    let password = Password::new(input.password).map_err(|_| UNAUTH)?;
    let login = LoginKey::parse(&input.login).map_err(|_| UNAUTH)?;
    issued(
        state
            .authority
            .login_local(
                tenant,
                login,
                password,
                source,
                replacement,
                budget.remaining(),
            )
            .await?,
    )
}
pub(crate) async fn current(
    State(state): State<AppState>,
    Path(raw): Path<String>,
    Extension(budget): Extension<RequestBudget>,
    headers: HeaderMap,
) -> Result<Response> {
    let secret = cookie(&headers)?.ok_or(UNAUTH)?;
    let csrf = secret.csrf();
    let proof = state
        .authority
        .inspect_session(tenant(&raw)?, secret, budget.remaining())
        .await?;
    Ok(Json(project_session(proof.identity(), proof.view(), csrf)).into_response())
}
pub(crate) async fn refresh(
    State(state): State<AppState>,
    Path(raw): Path<String>,
    Extension(budget): Extension<RequestBudget>,
    headers: HeaderMap,
) -> Result<Response> {
    let secret = cookie(&headers)?.ok_or(UNAUTH)?;
    csrf(&headers, &secret)?;
    issued(
        state
            .authority
            .refresh_session(tenant(&raw)?, secret, budget.remaining())
            .await?,
    )
}
async fn actor(
    state: &AppState,
    raw: &str,
    headers: &HeaderMap,
    budget: RequestBudget,
) -> Result<AuthenticatedSession> {
    let secret = cookie(headers)?.ok_or(UNAUTH)?;
    csrf(headers, &secret)?;
    Ok(state
        .authority
        .inspect_session(tenant(raw)?, secret, budget.remaining())
        .await?)
}
pub(crate) async fn logout(
    State(state): State<AppState>,
    Path(raw): Path<String>,
    Extension(budget): Extension<RequestBudget>,
    headers: HeaderMap,
) -> Result<Response> {
    let proof = actor(&state, &raw, &headers, budget).await?;
    state
        .authority
        .revoke_current_session(proof, budget.remaining())
        .await?;
    Ok(clear_cookie())
}
pub(crate) async fn logout_all(
    State(state): State<AppState>,
    Path(raw): Path<String>,
    Extension(budget): Extension<RequestBudget>,
    headers: HeaderMap,
) -> Result<Response> {
    let proof = actor(&state, &raw, &headers, budget).await?;
    state
        .authority
        .revoke_all_sessions(proof, budget.remaining())
        .await?;
    Ok(clear_cookie())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pagination {
    cursor: Option<SessionId>,
    limit: Option<u16>,
}
pub(crate) async fn list(
    State(state): State<AppState>,
    Path(raw): Path<String>,
    Extension(budget): Extension<RequestBudget>,
    query: std::result::Result<Query<Pagination>, axum::extract::rejection::QueryRejection>,
    headers: HeaderMap,
) -> Result<Response> {
    let Query(page) = query.map_err(|_| BAD)?;
    let secret = cookie(&headers)?.ok_or(UNAUTH)?;
    let proof = state
        .authority
        .inspect_session(tenant(&raw)?, secret, budget.remaining())
        .await?;
    Ok(Json(
        state
            .authority
            .list_sessions(
                proof,
                page.cursor,
                page.limit.unwrap_or(50),
                budget.remaining(),
            )
            .await?,
    )
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reauthentication {
    password: String,
}
pub(crate) async fn reauthenticate(
    State(state): State<AppState>,
    Path(raw): Path<String>,
    Extension(budget): Extension<RequestBudget>,
    request: Request,
) -> Result<Response> {
    if unique(request.headers(), "x-identity-request")? != Some("1") {
        return Err(FORBIDDEN);
    }
    let proof = actor(&state, &raw, request.headers(), budget).await?;
    let peer = request
        .extensions()
        .get::<crate::ClientAddress>()
        .ok_or(HttpError::from(AuthorityError::Unavailable))?
        .0;
    let source = AttemptSource::parse(&peer.to_string())?;
    let Json(input) = tokio::time::timeout_at(
        budget.cutoff(),
        Json::<Reauthentication>::from_request(request, &state),
    )
    .await
    .map_err(|_| HttpError::request_timeout())?
    .map_err(|_| BAD)?;
    issued(
        state
            .authority
            .reauthenticate_local(
                proof,
                Password::new(input.password).map_err(|_| UNAUTH)?,
                source,
                budget.remaining(),
            )
            .await?,
    )
}
