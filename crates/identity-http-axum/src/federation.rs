use crate::{boundary::*, *};

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
    federation::{ProviderId, random_secret},
    session::SessionSecret,
};

use rss_identity_postgres::{
    AttemptSource, AuthenticatedSession, FederatedOutcome, FederatedRedirect, Federation,
};

use serde::Deserialize;

use zeroize::Zeroizing;

const BROWSER: &str = "__Host-identity-oidc-browser";

#[derive(Clone)]
struct FederationState {
    federation: Federation,
    local: AppState,
}

/// Mount the existing local session routes and persistent OIDC routes on the same authority.
pub fn federated_router(
    federation: Federation,
    config: HttpConfig,
) -> Result<Router, AuthorityError> {
    let authority = federation.authority();

    let local = AppState {
        authority: authority.clone(),
        config: config.clone(),
    };

    let state = FederationState {
        federation,
        local: local.clone(),
    };

    let routes = Router::new()
        .route(
            "/api/v1/tenants/{tenant}/oidc/{provider}/login",
            post(begin),
        )
        .route("/api/v1/tenants/{tenant}/oidc/{provider}/link", post(link))
        .route(
            "/api/v1/oidc/callback",
            get(callback).head(|| async { StatusCode::METHOD_NOT_ALLOWED }),
        )
        .layer(axum::extract::DefaultBodyLimit::max(4096))
        .layer(middleware::from_fn_with_state(
            local,
            boundary::request_boundary,
        ))
        .with_state(state);

    Ok(router(authority, config)?.merge(routes))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Begin {
    client_id: String,
    return_target: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Link {
    client_id: String,
    return_target: String,
    password: Option<String>,
}

fn browser(headers: &HeaderMap, create: bool) -> Result<(String, bool), HttpError> {
    match named_cookie(headers, BROWSER)? {
        Some(v)
            if v.len() == 43
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') =>
        {
            Ok((v.into(), false))
        }

        None if create => Ok((
            random_secret()
                .map_err(|e| HttpError::from(AuthorityError::from(e)))?
                .to_string(),
            true,
        )),
        _ => Err(UNAUTH),
    }
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
    tenant: rss_request_context::TenantId,
    headers: &HeaderMap,
    budget: RequestBudget,
    required: bool,
) -> Result<Option<AuthenticatedSession>, HttpError> {
    if unique(headers, "x-identity-request")? != Some("1") {
        return Err(FORBIDDEN);
    }

    if let Some(secret) = login_cookie(headers)? {
        match state
            .local
            .authority
            .inspect_session(
                tenant,
                SessionSecret::parse(secret.expose().into()).map_err(|_| UNAUTH)?,
                budget.remaining(),
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
    browser: &str,
    created: bool,
) -> Result<Response, HttpError> {
    let mut response = Json(serde_json::json!({
    "authorization_url":redirect.url}
    ))
    .into_response();

    if created {
        response.headers_mut().insert(
            header::SET_COOKIE,
            format!("{BROWSER}={browser}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600")
                .parse()
                .map_err(|_| BAD)?,
        );
    }

    Ok(response)
}

async fn begin(
    State(state): State<FederationState>,
    Path((raw, provider)): Path<(String, ProviderId)>,
    Extension(budget): Extension<RequestBudget>,
    request: Request,
) -> Result<Response, HttpError> {
    let tenant = tenant(&raw)?;

    let actor = actor(&state, tenant, request.headers(), budget, false).await?;

    let (browser, created) = browser(request.headers(), true)?;

    let source = source(&request)?;

    let Json(input) = tokio::time::timeout_at(
        budget.cutoff(),
        Json::<Begin>::from_request(request, &state),
    )
    .await
    .map_err(|_| HttpError::request_timeout())?
    .map_err(|_| BAD)?;

    let redirect = state
        .federation
        .begin_login(
            rss_identity_postgres::LoginRequest {
                tenant,
                provider,
                browser: browser.clone(),
                client: input.client_id,
                target: input.return_target,
                replacement: actor,
                source,
            },
            budget.remaining(),
        )
        .await?;

    redirect_response(redirect, &browser, created)
}

async fn link(
    State(state): State<FederationState>,
    Path((raw, provider)): Path<(String, ProviderId)>,
    Extension(budget): Extension<RequestBudget>,
    request: Request,
) -> Result<Response, HttpError> {
    let tenant = tenant(&raw)?;

    let actor = actor(&state, tenant, request.headers(), budget, true)
        .await?
        .ok_or(UNAUTH)?;

    let (browser, created) = browser(request.headers(), true)?;

    let source = source(&request)?;

    let Json(input) =
        tokio::time::timeout_at(budget.cutoff(), Json::<Link>::from_request(request, &state))
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
                browser: browser.clone(),
                client: input.client_id,
                target: input.return_target,
                source,
            },
            budget.remaining(),
        )
        .await?;

    redirect_response(redirect, &browser, created)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    budget: Extension<RequestBudget>,
    headers: HeaderMap,
    query: Result<Query<Callback>, axum::extract::rejection::QueryRejection>,
) -> Response {
    match callback_result(state, budget, headers, query).await {
        Ok(response) => response,
        Err(error) => callback_failure(if error.0 == StatusCode::SERVICE_UNAVAILABLE {
            "unavailable"
        } else {
            "failed"
        }),
    }
}
pub(crate) fn callback_failure(reason: &str) -> Response {
    // Only closed literals selected in this module reach Location.
    axum::response::Redirect::to(&format!("/auth/error?reason={reason}")).into_response()
}

async fn callback_result(
    State(state): State<FederationState>,
    Extension(budget): Extension<RequestBudget>,
    headers: HeaderMap,
    query: Result<Query<Callback>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, HttpError> {
    let Query(query) = query.map_err(|_| BAD)?;
    if query.code.is_some() == query.error.is_some() {
        return Err(BAD);
    }

    let (browser, _) = browser(&headers, false)?;

    if let Some(error) = query.error {
        state
            .federation
            .cancel(
                query.state,
                browser,
                query.iss,
                login_cookie(&headers)?,
                budget.remaining(),
            )
            .await?;
        return Ok(callback_failure(if error == "access_denied" {
            "cancelled"
        } else {
            "failed"
        }));
    }
    let outcome = state
        .federation
        .complete(
            query.state,
            browser,
            Zeroizing::new(query.code.ok_or(BAD)?),
            query.iss,
            login_cookie(&headers)?,
            budget.remaining(),
        )
        .await?;

    let (location, cookie) = match outcome {
        FederatedOutcome::Redirect(redirect) => (redirect.url, None),
        FederatedOutcome::Session {
            issued,
            return_url,
            link_result,
        } => {
            let age = issued.cookie_max_age();

            if age == 0 {
                return Err(AuthorityError::Unavailable.into());
            }

            let location = if let Some(result) = link_result {
                let mut url = url::Url::parse(&return_url).map_err(|_| BAD)?;
                url.query_pairs_mut()
                    .append_pair("identity_result", result.as_str());
                url.to_string()
            } else {
                return_url
            };
            (location, Some(session_cookie(issued.secret(), age)))
        }
    };

    let mut response = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::REFERRER_POLICY, "no-referrer")
        .body(Body::empty())
        .map_err(|_| BAD)?;

    if let Some(cookie) = cookie {
        response
            .headers_mut()
            .insert(header::SET_COOKIE, cookie.parse().map_err(|_| BAD)?);
    }

    Ok(response)
}
