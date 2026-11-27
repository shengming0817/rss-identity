//! Explicit programmatic routes; hosts own TLS, trusted ClientAddress and IP admission.
use crate::{AppState, HttpConfig, boundary::*};
use axum::{
    Extension, Json, Router,
    extract::{FromRequest, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use rss_identity_core::account::{LoginKey, Password};
use rss_identity_postgres::{AttemptSource, Authority, AuthorityError};
use rss_identity_web_credentials::{bearer_credential, bearer_presentation};
use serde::Deserialize;

/// Opt-in: mount only after applying the product's programmatic network admission.
/// The browser router does not implicitly enable these routes.
pub fn bearer_router(authority: Authority, config: HttpConfig) -> Result<Router, AuthorityError> {
    authority.require_runtime()?;
    let state = AppState { authority, config };
    Ok(Router::new().nest(
        "/api/v1/identity",
        Router::new()
            .route("/tenants/{tenant}/bearer/login", post(login))
            .route("/tenants/{tenant}/bearer/logout", post(logout))
            .layer(axum::extract::DefaultBodyLimit::max(4096))
            .route_layer(middleware::from_fn_with_state(state.clone(), boundary))
            .with_state(state),
    ))
}
fn secure(mut response: Response) -> Response {
    if response.status() == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer"),
        );
    }
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    response
}
async fn boundary(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    let budget = match RequestBudget::for_request(&request, state.config.timeout()) {
        Ok(budget) => budget,
        Err(error) => return secure(error.into_response()),
    };
    request.extensions_mut().insert(budget);
    let admitted = if request.uri().to_string().len() > 8192 || request.uri().query().is_some() {
        Err(BAD)
    } else {
        bearer_presentation(request.headers()).map_err(HttpError::from)
    };
    secure(match admitted {
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    login: String,
    password: String,
}
async fn login(
    State(state): State<AppState>,
    Execution(binding): Execution,
    Extension(budget): Extension<RequestBudget>,
    request: Request,
) -> Result<Response, HttpError> {
    if request.headers().contains_key(header::AUTHORIZATION) {
        return Err(BAD);
    }
    let address = request
        .extensions()
        .get::<crate::ClientAddress>()
        .ok_or(HttpError::from(AuthorityError::Unavailable))?
        .0;
    let source = AttemptSource::parse(&address.to_string())?;
    let Json(input) = tokio::time::timeout_at(
        budget.cutoff(),
        Json::<Login>::from_request(request, &state),
    )
    .await
    .map_err(|_| HttpError::request_timeout())?
    .map_err(|_| BAD)?;
    let issued = state
        .authority
        .login_local_bearer(
            binding,
            LoginKey::parse(&input.login).map_err(|_| UNAUTH)?,
            Password::new(input.password).map_err(|_| UNAUTH)?,
            source,
            budget.remaining(),
        )
        .await?;
    let view = issued.view();
    Ok(Json(serde_json::json!({
        "accessToken": issued.secret().expose(), "tokenType": "Bearer",
        "sessionId": view.id.to_string(), "principalId": issued.identity().principal_id.as_uuid(),
        "idleExpiresAt": view.idle_expires_at, "absoluteExpiresAt": view.absolute_expires_at
    }))
    .into_response())
}
async fn logout(
    State(state): State<AppState>,
    Execution(binding): Execution,
    Extension(budget): Extension<RequestBudget>,
    headers: HeaderMap,
) -> Result<StatusCode, HttpError> {
    let proof = state
        .authority
        .inspect_bearer(binding, bearer_credential(&headers)?, budget.remaining())
        .await?;
    state
        .authority
        .revoke_current_session(proof, budget.remaining())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
