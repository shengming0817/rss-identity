use crate::{boundary::*, *};
use rss_transactional_messaging::fence::ExecutionBinding;

use axum::{
    Extension, Json,
    body::Body,
    extract::{FromRequest, Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};

use rss_identity_core::{
    account::Password,
    federation::{ProviderId, callback::CallbackOutcome},
    session::SessionSecret,
};

use rss_identity_postgres::{
    AttemptSource, AuthenticatedSession, FederatedOutcome, FederatedRedirect, Federation,
};

use serde::Deserialize;

use rss_identity_web_credentials::{BrowserBinding, issued_cookie, operation_cookie};

#[derive(Clone)]
struct FederationState {
    federation: Federation,
    local: AppState,
}

/// Optional OIDC routes; merge with `router` for local authentication.
pub fn federated_router(
    federation: Federation,
    config: HttpConfig,
) -> Result<Router, AuthorityError> {
    let authority = federation.authority();

    let management = crate::providers::router(federation.clone(), config.clone())?;
    let local = AppState {
        authority: authority.clone(),
        config: config.clone(),
    };

    let reconcile = middleware::from_fn_with_state(federation.clone(), reconcile_profiles);
    let state = FederationState {
        federation,
        local: local.clone(),
    };

    let routes = Router::new()
        .route("/tenants/{tenant}/login-options", get(options))
        .route("/tenants/{tenant}/session/security", get(security))
        .route("/tenants/{tenant}/oidc/{provider}/login", post(begin))
        .route("/tenants/{tenant}/oidc/{provider}/link", post(link))
        .route("/tenants/{tenant}/oidc/{provider}/step-up", post(step_up))
        .route_layer(reconcile)
        .route(
            "/oidc/callback",
            get(callback).head(|| async { StatusCode::METHOD_NOT_ALLOWED }),
        )
        .layer(axum::extract::DefaultBodyLimit::max(4096))
        .route_layer(middleware::from_fn_with_state(
            local,
            boundary::request_boundary,
        ))
        .with_state(state);

    Ok(crate::mount(routes.merge(management)))
}

async fn reconcile_profiles(
    State(federation): State<Federation>,
    Execution(binding): Execution,
    Extension(budget): Extension<Deadline>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    if let Err(error) = federation
        .reconcile_assurance_profiles(binding, budget)
        .await
    {
        let mut response = StatusCode::SERVICE_UNAVAILABLE.into_response();
        response
            .extensions_mut()
            .insert(HttpFailure::Authority(error));
        return response;
    }
    next.run(request).await
}

async fn options(
    State(s): State<FederationState>,
    Execution(binding): Execution,
    Extension(b): Extension<Deadline>,
) -> Result<Response, crate::accounts::Error> {
    Ok(Json(dto::LoginOptions {
        providers: s
            .federation
            .login_options(binding, b)
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    })
    .into_response())
}
async fn security(
    State(state): State<FederationState>,
    Execution(binding): Execution,
    Extension(budget): Extension<Deadline>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let secret = cookie(&headers)?.ok_or(UNAUTH)?;
    let actor = state
        .local
        .authority
        .inspect_session(binding, secret, budget)
        .await?;
    let security = state
        .federation
        .current_session_security(actor, budget)
        .await?;
    Ok(Json(crate::dto::SessionSecurity::from(security)).into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Begin {
    return_target: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BeginStepUp {
    return_target: String,
    operation: crate::webauthn::Operation,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Link {
    return_target: String,
    password: Option<String>,
}

fn source(request: &Request) -> Result<AttemptSource, HttpError> {
    let peer = request
        .extensions()
        .get::<crate::ClientAddress>()
        .ok_or(HttpError::from(AuthorityError::Unavailable))?
        .0;

    Ok(AttemptSource::parse(&peer.to_string())?)
}

async fn actor(
    state: &FederationState,
    binding: ExecutionBinding,
    headers: &HeaderMap,
    budget: Deadline,
    required: bool,
) -> Result<Option<AuthenticatedSession>, HttpError> {
    if !request_marker(headers)? {
        return Err(FORBIDDEN);
    }

    if let Some(secret) = login_cookie(headers)? {
        match state
            .local
            .authority
            .inspect_session(
                binding,
                SessionSecret::parse(secret.expose().into()).map_err(|_| UNAUTH)?,
                budget,
            )
            .await
        {
            Ok(proof) => {
                csrf(headers, &secret)?;

                return Ok(Some(proof));
            }

            Err(AuthorityError::Rejected) if !required => {}

            Err(e) => return Err(e.into()),
        }
    }

    if required { Err(UNAUTH) } else { Ok(None) }
}

fn redirect_response(
    redirect: FederatedRedirect,
    set_cookie: Option<header::HeaderValue>,
) -> Result<Response, HttpError> {
    let mut response = Json(serde_json::json!({
    "authorizationUrl":redirect.url}
    ))
    .into_response();

    if let Some(header) = set_cookie {
        response.headers_mut().insert(header::SET_COOKIE, header);
    }

    Ok(response)
}

async fn begin(
    State(state): State<FederationState>,
    Path((_raw, provider)): Path<(String, ProviderId)>,
    Execution(binding): Execution,
    Extension(budget): Extension<Deadline>,
    request: Request,
) -> Result<Response, HttpError> {
    let actor = actor(&state, binding, request.headers(), budget, false).await?;

    let browser = BrowserBinding::start(request.headers())?;

    let source = source(&request)?;

    let Json(input) = tokio::time::timeout_at(
        budget.instant().into(),
        Json::<Begin>::from_request(request, &state),
    )
    .await
    .map_err(|_| HttpError::request_timeout())?
    .map_err(|_| BAD)?;

    let redirect = state
        .federation
        .begin_login(
            rss_identity_postgres::LoginRequest {
                binding,
                provider,
                browser: browser.value,
                target: input.return_target,
                replacement: actor,
                source,
            },
            budget,
        )
        .await?;

    redirect_response(redirect, browser.set_cookie)
}

async fn step_up(
    State(state): State<FederationState>,
    Path((_raw, provider)): Path<(String, ProviderId)>,
    Execution(binding): Execution,
    Extension(budget): Extension<Deadline>,
    request: Request,
) -> Result<Response, HttpError> {
    let actor = actor(&state, binding, request.headers(), budget, true).await?;

    let browser = BrowserBinding::start(request.headers())?;

    let source = source(&request)?;

    let host = request
        .extensions()
        .get::<rss_identity_core::step_up::StepUpContext>()
        .cloned();
    let Json(input) = tokio::time::timeout_at(
        budget.instant().into(),
        Json::<BeginStepUp>::from_request(request, &state),
    )
    .await
    .map_err(|_| HttpError::request_timeout())?
    .map_err(|_| BAD)?;

    let actor = actor.ok_or(UNAUTH)?;
    let context = input.operation.context(&actor, host)?;
    let redirect = state
        .federation
        .begin_step_up(
            rss_identity_postgres::LoginRequest {
                binding,
                provider,
                browser: browser.value,
                target: input.return_target,
                replacement: Some(actor),
                source,
            },
            context,
            budget,
        )
        .await?;

    redirect_response(redirect, browser.set_cookie)
}

async fn link(
    State(state): State<FederationState>,
    Path((_raw, provider)): Path<(String, ProviderId)>,
    Execution(binding): Execution,
    Extension(budget): Extension<Deadline>,
    request: Request,
) -> Result<Response, HttpError> {
    let actor = actor(&state, binding, request.headers(), budget, true)
        .await?
        .ok_or(UNAUTH)?;

    let browser = BrowserBinding::start(request.headers())?;

    let source = source(&request)?;

    let Json(input) =
        tokio::time::timeout_at(budget.instant().into(), Json::<Link>::from_request(request, &state))
            .await
            .map_err(|_| HttpError::request_timeout())?
            .map_err(|_| BAD)?;

    let password = input
        .password
        .map(Password::new)
        .transpose()
        .map_err(|_| UNAUTH)?;

    let redirect = state
        .federation
        .begin_link(
            rss_identity_postgres::LinkRequest {
                actor,
                target_provider: provider,
                password,
                browser: browser.value,
                target: input.return_target,
                source,
            },
            budget,
        )
        .await?;

    redirect_response(redirect, browser.set_cookie)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Callback {
    state: String,
    code: Option<String>,
    error: Option<String>,
    iss: String,
    #[serde(rename = "error_description")]
    _error_description: Option<String>,
    #[serde(rename = "error_uri")]
    _error_uri: Option<String>,
    #[serde(rename = "session_state")]
    _session_state: Option<String>,
}

async fn callback(
    state: State<FederationState>,
    budget: Extension<Deadline>,
    headers: HeaderMap,
    query: Result<Query<Callback>, axum::extract::rejection::QueryRejection>,
) -> Response {
    match callback_result(state, budget, headers, query).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}
pub(crate) fn callback_failure(reason: &str) -> Response {
    // Only closed literals selected in this module reach Location.
    axum::response::Redirect::to(&format!("/auth/error?reason={reason}")).into_response()
}

/// Keep host diagnostics in response parts while replacing the browser projection.
pub async fn protect_callback(request: Request, next: axum::middleware::Next) -> Response {
    let callback = request.method() == axum::http::Method::GET
        && request.uri().path() == "/api/v1/identity/oidc/callback";
    let response = next.run(request).await;
    if callback && (response.status().is_client_error() || response.status().is_server_error()) {
        return callback_error_response(response);
    }
    response
}

pub(crate) fn callback_error_response(response: Response) -> Response {
    let (parts, _) = response.into_parts();
    let reason = if parts.status == StatusCode::SERVICE_UNAVAILABLE {
        "unavailable"
    } else {
        "failed"
    };
    (
        parts.extensions,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        callback_failure(reason),
    )
        .into_response()
}

async fn callback_result(
    State(state): State<FederationState>,
    Extension(budget): Extension<Deadline>,
    headers: HeaderMap,
    query: Result<Query<Callback>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, HttpError> {
    let Query(query) = query.map_err(|_| BAD)?;
    let outcome = CallbackOutcome::from_parts(query.code, query.error).map_err(|_| BAD)?;

    let browser = BrowserBinding::require(&headers)?;

    let code = match outcome {
        CallbackOutcome::Code(code) => code,
        CallbackOutcome::Denied { cancelled } => {
            state
                .federation
                .cancel(
                    query.state,
                    browser,
                    query.iss,
                    login_cookie(&headers)?,
                    budget,
                )
                .await?;
            return Ok(callback_failure(if cancelled {
                "cancelled"
            } else {
                "failed"
            }));
        }
    };
    let outcome = state
        .federation
        .complete(
            query.state,
            browser,
            code,
            query.iss,
            login_cookie(&headers)?,
            budget,
        )
        .await?;

    let (location, cookie) = match outcome {
        FederatedOutcome::Redirect(redirect) => (redirect.url, None),
        FederatedOutcome::StepUp { grant, return_url } => {
            (return_url, Some(operation_cookie(&grant, std::time::SystemTime::now())?))
        }
        FederatedOutcome::Session {
            issued,
            return_url,
            link_result,
        } => {
            let location = if let Some(result) = link_result {
                let mut url = url::Url::parse(&return_url).map_err(|_| BAD)?;
                url.query_pairs_mut()
                    .append_pair("identity_result", result.as_str());
                url.to_string()
            } else {
                return_url
            };
            (location, Some(issued_cookie(&issued)?.header))
        }
    };

    let mut response = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::REFERRER_POLICY, "no-referrer")
        .body(Body::empty())
        .map_err(|_| BAD)?;

    if let Some(cookie) = cookie {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }

    Ok(response)
}

#[cfg(test)]
mod callback_tests {
    use super::*;
    use rss_identity_core::federation::FederationError;
    use rss_identity_postgres::AuthorityError;
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct HostMarker;

    #[tokio::test]
    async fn callback_error_projection_keeps_all_host_extensions_and_hides_body() {
        for (error, reason) in [
            (
                AuthorityError::Federation(FederationError::Claims),
                "failed",
            ),
            (AuthorityError::Unavailable, "unavailable"),
        ] {
            let mut response = HttpError::from(error).into_response();
            response.extensions_mut().insert(HostMarker);
            response.headers_mut().insert(
                header::SET_COOKIE,
                "must-not-forward=secret".parse().unwrap(),
            );
            let response = callback_error_response(response);
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(
                response.headers()[header::LOCATION],
                format!("/auth/error?reason={reason}")
            );
            assert_eq!(
                response.extensions().get::<HttpFailure>(),
                Some(&HttpFailure::Authority(error))
            );
            assert_eq!(response.extensions().get::<HostMarker>(), Some(&HostMarker));
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            assert!(
                axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }
}
