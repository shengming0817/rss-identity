//! Explicit programmatic routes; hosts own TLS, trusted ClientAddress and IP admission.
use crate::{AppState, HttpConfig, boundary::*};
use axum::{
    Extension, Json, Router,
    extract::{FromRequest, Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use rss_identity_core::{
    account::{LoginKey, Password},
    session::BearerSecret,
};
use rss_identity_postgres::{AttemptSource, AuthenticatedSession, Authority, AuthorityError};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
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
    request
        .extensions_mut()
        .insert(RequestBudget::new(state.config.timeout));
    let admitted = if request.uri().to_string().len() > 8192 || request.uri().query().is_some() {
        Err(BAD)
    } else {
        bearer_presentation(request.headers())
    };
    secure(match admitted {
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    })
}
fn credential(headers: &HeaderMap) -> Result<BearerSecret, HttpError> {
    bearer_presentation(headers)?;
    let value = unique(headers, "authorization")?.ok_or(UNAUTH)?;
    let (scheme, secret) = value.split_once(' ').ok_or(UNAUTH)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(UNAUTH);
    }
    BearerSecret::parse(secret.into()).map_err(|_| UNAUTH)
}
/// A successful call is API activity and renews idle within the original absolute deadline.
/// It never accepts Cookie/API Key fallback or performs product authorization.
/// The second result is request-local only, for bounded product revalidation.
pub async fn authenticate_bearer_request(
    authority: &Authority,
    config: &HttpConfig,
    tenant: TenantId,
    headers: &HeaderMap,
    deadline: OperationDeadline,
) -> Result<(AuthenticatedSession, BearerSecret), Response> {
    let budget = RequestBudget::new(deadline.timeout().min(config.timeout));
    let result = async {
        let retained = credential(headers)?;
        let secret = BearerSecret::parse(retained.expose().into()).map_err(|_| UNAUTH)?;
        let proof = authority
            .authenticate_bearer(tenant, secret, budget.remaining())
            .await?;
        Ok((proof, retained))
    }
    .await;
    result.map_err(|e: HttpError| secure(e.into_response()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    login: String,
    password: String,
}
async fn login(
    State(state): State<AppState>,
    Path(raw): Path<String>,
    Extension(budget): Extension<RequestBudget>,
    request: Request,
) -> Result<Response, HttpError> {
    if request.headers().contains_key(header::AUTHORIZATION) {
        return Err(BAD);
    }
    let tenant = tenant(&raw)?;
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
            tenant,
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
    Path(raw): Path<String>,
    Extension(budget): Extension<RequestBudget>,
    headers: HeaderMap,
) -> Result<StatusCode, HttpError> {
    let proof = state
        .authority
        .inspect_bearer(tenant(&raw)?, credential(&headers)?, budget.remaining())
        .await?;
    state
        .authority
        .revoke_current_session(proof, budget.remaining())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bearer_presentation_rejects_duplicates_mixed_and_malformed_credentials() {
        let token = "a".repeat(64);
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        assert_eq!(credential(&headers).unwrap().expose(), token);
        for (name, value) in [
            ("authorization", format!("Bearer {token}")),
            ("x-api-key", "key".into()),
            ("cookie", "__Host-identity-session=broken".into()),
        ] {
            let mut mixed = headers.clone();
            mixed.append(name, value.parse().unwrap());
            assert!(credential(&mixed).is_err());
        }
        for value in [
            "Basic secret",
            "Bearer ",
            "Bearer abc",
            "Bearer  ",
            "Bearer a,b",
        ] {
            headers.insert("authorization", value.parse().unwrap());
            assert!(credential(&headers).is_err());
        }
        assert!(!format!("{:?}", BearerSecret::parse(token.clone()).unwrap()).contains(&token));
    }
}
