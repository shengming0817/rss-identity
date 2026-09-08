use crate::AppState;
use axum::{
    Json,
    extract::{Request, State},
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
    timeout: Duration,
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
pub(crate) struct HttpError(pub StatusCode, pub &'static str, Option<HttpFailure>);
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
        if let Some(class) = self.2 {
            response.extensions_mut().insert(class);
        }
        response
    }
}
impl From<AuthorityError> for HttpError {
    fn from(error: AuthorityError) -> Self {
        let mut response = match error {
            AuthorityError::Invalid => BAD,
            AuthorityError::Rejected | AuthorityError::RuleRejected(_) => UNAUTH,
            AuthorityError::RateLimited => {
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
pub(crate) fn cookie(headers: &HeaderMap) -> Result<Option<SessionSecret>, HttpError> {
    cookie_value(headers)?
        .map(|value| SessionSecret::parse(value.into()).map_err(|_| UNAUTH))
        .transpose()
}
/// A damaged single value cannot prevent password recovery; ambiguous headers still fail.
pub(crate) fn login_cookie(headers: &HeaderMap) -> Result<Option<SessionSecret>, HttpError> {
    Ok(cookie_value(headers)?.and_then(|value| SessionSecret::parse(value.into()).ok()))
}
fn cookie_value(headers: &HeaderMap) -> Result<Option<&str>, HttpError> {
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
            if name == SESSION_COOKIE_NAME {
                if found.is_some() {
                    return Err(BAD);
                }
                found = Some(value);
            }
        }
    }
    Ok(found)
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
    mut request: Request,
    next: Next,
) -> Response {
    let budget = RequestBudget(Instant::now() + state.config.timeout);
    request.extensions_mut().insert(budget);
    let origin = if request.method().is_safe() {
        Ok(())
    } else {
        match unique(request.headers(), "origin") {
            Ok(Some(origin)) if origin == state.config.origin => Ok(()),
            _ => Err(FORBIDDEN),
        }
    };
    let mut response = match origin {
        // Authority/RSS owns bounded settlement after a transaction starts. A second
        // timeout around this future could discard its CommitUnknown/RollbackFailed result.
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}
