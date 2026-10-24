use crate::AppState;
use axum::{
    Json,
    extract::{OriginalUri, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use rss_identity_core::session::SessionSecret;
use rss_identity_postgres::AuthorityError;
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use std::time::{Duration, Instant};

const SESSION_COOKIE_NAME: &str = "__Host-identity-session";

#[derive(Clone)]
pub struct HttpConfig {
    pub(crate) origin: String,
    pub(crate) timeout: Duration,
}
#[derive(Debug, thiserror::Error)]
#[error("Identity requires a canonical HTTPS origin and a nonzero bounded request timeout")]
pub struct HttpConfigError;
impl HttpConfig {
    pub fn new(origin: &str, timeout: Duration) -> Result<Self, HttpConfigError> {
        let url = url::Url::parse(origin).map_err(|_| HttpConfigError)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.origin().ascii_serialization() != origin
            || timeout.is_zero()
            || timeout > Duration::from_secs(60)
        {
            return Err(HttpConfigError);
        }
        Ok(Self {
            origin: origin.into(),
            timeout,
        })
    }
}
#[derive(Clone, Copy)]
pub(crate) struct RequestBudget(Instant);
impl RequestBudget {
    pub fn new(timeout: Duration) -> Self {
        Self(Instant::now() + timeout)
    }
    pub fn cutoff(self) -> tokio::time::Instant {
        self.0.into()
    }
    pub fn remaining(self) -> OperationDeadline {
        OperationDeadline::from_remaining(self.0.saturating_duration_since(Instant::now()))
    }
}
/// Non-secret response extension for host diagnostics; never included in the public body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpFailure {
    Authority(AuthorityError),
    RequestTimeout,
}
#[derive(Debug)]
pub(crate) struct HttpError(
    pub StatusCode,
    pub &'static str,
    pub(crate) Option<HttpFailure>,
);
pub(crate) const BAD: HttpError = HttpError(StatusCode::BAD_REQUEST, "malformed_request", None);
pub(crate) const UNAUTH: HttpError =
    HttpError(StatusCode::UNAUTHORIZED, "invalid_credential", None);
pub(crate) const FORBIDDEN: HttpError = HttpError(StatusCode::FORBIDDEN, "csrf_rejected", None);
impl HttpError {
    pub(crate) fn request_timeout() -> Self {
        Self(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity_unavailable",
            Some(HttpFailure::RequestTimeout),
        )
    }
}
impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let mut response = (self.0, Json(serde_json::json!({"code":self.1}))).into_response();
        if let Some(HttpFailure::Authority(AuthorityError::RateLimited {
            retry_after_seconds,
        })) = self.2
        {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                axum::http::HeaderValue::from(retry_after_seconds.get()),
            );
        }
        if let Some(class) = self.2 {
            response.extensions_mut().insert(class);
        }
        response
    }
}
impl From<AuthorityError> for HttpError {
    fn from(error: AuthorityError) -> Self {
        let mut response = match error {
            AuthorityError::InteractionRequired => {
                Self(StatusCode::FORBIDDEN, "interaction_required", None)
            }
            AuthorityError::Cancelled => {
                Self(StatusCode::CONFLICT, "authentication_cancelled", None)
            }
            AuthorityError::InvalidInput => BAD,
            AuthorityError::Federation(error) => match error {
                rss_identity_core::federation::FederationError::Configuration => BAD,
                rss_identity_core::federation::FederationError::Conflict => {
                    Self(StatusCode::CONFLICT, "identity_link_conflict", None)
                }
                rss_identity_core::federation::FederationError::StaleConfiguration => {
                    Self(StatusCode::CONFLICT, "configuration_changed", None)
                }
                rss_identity_core::federation::FederationError::Unavailable => Self(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "identity_unavailable",
                    None,
                ),
                rss_identity_core::federation::FederationError::Provider(f) => {
                    use rss_identity_core::federation::{ProviderReason, ProviderStage};
                    if f.stage == ProviderStage::Exchange
                        && f.reason == ProviderReason::CodeRejected
                    {
                        UNAUTH
                    } else {
                        Self(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "identity_unavailable",
                            None,
                        )
                    }
                }
                _ => UNAUTH,
            },
            AuthorityError::Rejected | AuthorityError::RuleRejected(_) => UNAUTH,
            AuthorityError::RateLimited { .. } => {
                Self(StatusCode::TOO_MANY_REQUESTS, "rate_limited", None)
            }
            _ => Self(
                StatusCode::SERVICE_UNAVAILABLE,
                "identity_unavailable",
                None,
            ),
        };
        response.2 = Some(HttpFailure::Authority(error));
        response
    }
}
pub(crate) fn tenant(value: &str) -> Result<TenantId, HttpError> {
    TenantId::parse(value).map_err(|_| BAD)
}
pub(crate) fn unique<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, HttpError> {
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .map(|h| h.to_str().map_err(|_| BAD))
        .transpose()?;
    if values.next().is_some() {
        return Err(BAD);
    }
    Ok(first)
}
pub(crate) fn cookie_presentation(headers: &HeaderMap) -> Result<(), HttpError> {
    if headers.contains_key(header::AUTHORIZATION) || headers.contains_key("x-api-key") {
        return Err(BAD);
    }
    Ok(())
}
pub(crate) fn bearer_presentation(headers: &HeaderMap) -> Result<(), HttpError> {
    if named_cookie(headers, SESSION_COOKIE_NAME)?.is_some() || headers.contains_key("x-api-key") {
        return Err(BAD);
    }
    Ok(())
}
pub(crate) fn cookie(headers: &HeaderMap) -> Result<Option<SessionSecret>, HttpError> {
    cookie_presentation(headers)?;
    cookie_value(headers)?
        .map(|value| SessionSecret::parse(value.into()).map_err(|_| UNAUTH))
        .transpose()
}
/// A damaged single value cannot prevent password recovery; ambiguous headers still fail.
pub(crate) fn login_cookie(headers: &HeaderMap) -> Result<Option<SessionSecret>, HttpError> {
    Ok(cookie_value(headers)?.and_then(|value| SessionSecret::parse(value.into()).ok()))
}
fn cookie_value(headers: &HeaderMap) -> Result<Option<&str>, HttpError> {
    named_cookie(headers, SESSION_COOKIE_NAME)
}
pub(crate) fn named_cookie<'a>(
    headers: &'a HeaderMap,
    name_expected: &str,
) -> Result<Option<&'a str>, HttpError> {
    let mut found = None;
    let mut size = 0;
    for value in headers.get_all(header::COOKIE) {
        size += value.as_bytes().len();
        if size > 8192 {
            return Err(BAD);
        }
        for part in value.to_str().map_err(|_| BAD)?.split(';') {
            let Some((name, value)) = part.trim().split_once('=') else {
                return Err(BAD);
            };
            if name == name_expected {
                if found.is_some() {
                    return Err(BAD);
                }
                found = Some(value);
            }
        }
    }
    Ok(found)
}
pub(crate) fn same_origin(headers: &HeaderMap, config: &HttpConfig) -> Result<(), HttpError> {
    match unique(headers, "origin") {
        Ok(Some(origin)) if origin == config.origin => Ok(()),
        _ => Err(FORBIDDEN),
    }
}
pub(crate) fn csrf(headers: &HeaderMap, secret: &SessionSecret) -> Result<(), HttpError> {
    if !secret.check_csrf(unique(headers, "x-csrf-token")?.ok_or(FORBIDDEN)?) {
        return Err(FORBIDDEN);
    }
    Ok(())
}
pub(crate) fn session_cookie(secret: &SessionSecret, max_age: u64) -> String {
    format!(
        "{SESSION_COOKIE_NAME}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}",
        secret.expose()
    )
}
pub(crate) fn clear_cookie() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!("{SESSION_COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
            .parse()
            .expect("constant header"),
    );
    response
}
pub(crate) async fn request_boundary(
    State(state): State<AppState>,
    OriginalUri(original_uri): OriginalUri,
    mut request: Request,
    next: Next,
) -> Response {
    let callback = request.method() == axum::http::Method::GET
        && original_uri.path() == "/api/v1/identity/oidc/callback";
    let budget = RequestBudget::new(state.config.timeout);
    request.extensions_mut().insert(budget);
    let origin = if original_uri.to_string().len() > 8192
        || cookie_presentation(request.headers()).is_err()
    {
        Err(BAD)
    } else if request.method().is_safe() {
        Ok(())
    } else {
        same_origin(request.headers(), &state.config)
    };
    let mut response = match origin {
        // Authority/RSS owns bounded settlement after a transaction starts. A second
        // timeout around this future could discard its CommitUnknown/RollbackFailed result.
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    };
    if callback && (response.status().is_client_error() || response.status().is_server_error()) {
        response = crate::federation::callback_error_response(response);
    }
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;
    #[tokio::test]
    async fn login_and_management_preserve_the_same_retry_contract() {
        let error = AuthorityError::RateLimited {
            retry_after_seconds: std::num::NonZeroU32::new(600).unwrap(),
        };
        for response in [
            HttpError::from(error).into_response(),
            crate::management::Error::from(error).into_response(),
        ] {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(response.headers()[header::RETRY_AFTER], "600");
            assert_eq!(
                response.extensions().get::<HttpFailure>(),
                Some(&HttpFailure::Authority(error))
            );
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"code":"rate_limited"})
            );
        }
    }
}
