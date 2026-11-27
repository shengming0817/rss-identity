use crate::AppState;
pub(crate) use crate::error::*;
use axum::{
    extract::{OriginalUri, Request, State},
    http::header,
    middleware::Next,
    response::{IntoResponse, Response},
};
use rss_identity_postgres::AuthorityError;
pub(crate) use rss_identity_web_credentials::{cookie, csrf, login_cookie, request_marker};
use rss_identity_web_credentials::{cookie_presentation, same_origin};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(crate) struct RequestBudget(rss_request_context::Deadline);
impl RequestBudget {
    pub(crate) fn for_request(request: &Request, timeout: Duration) -> Result<Self, HttpError> {
        let mut budget = Self::new(timeout)?;
        if let Some(cutoff) = request.extensions().get::<rss_request_context::Deadline>() {
            budget.0 = budget.0.shortened_to(cutoff.instant());
        }
        if budget
            .0
            .remaining(Instant::now())
            .unwrap_or_default()
            .is_zero()
        {
            return Err(HttpError::request_timeout());
        }
        Ok(budget)
    }

    pub fn new(timeout: Duration) -> Result<Self, HttpError> {
        if timeout.is_zero() {
            return Err(HttpError::request_timeout());
        }
        Instant::now()
            .checked_add(timeout)
            .map(|at| Self(rss_request_context::Deadline::at(at)))
            .ok_or_else(HttpError::request_timeout)
    }
    pub fn cutoff(self) -> tokio::time::Instant {
        self.0.instant().into()
    }
    pub fn remaining(self) -> OperationDeadline {
        OperationDeadline::from_remaining(self.0.remaining(Instant::now()).unwrap_or_default())
    }
}
pub(crate) fn tenant(value: &str) -> Result<TenantId, HttpError> {
    TenantId::parse(value).map_err(|_| BAD)
}
pub(crate) async fn request_boundary(
    State(state): State<AppState>,
    OriginalUri(original_uri): OriginalUri,
    mut request: Request,
    next: Next,
) -> Response {
    let budget = match RequestBudget::for_request(&request, state.config.timeout()) {
        Ok(budget) => budget,
        Err(error) => return error.into_response(),
    };
    request.extensions_mut().insert(budget);
    let origin = if original_uri.to_string().len() > 8192
        || cookie_presentation(request.headers()).is_err()
    {
        Err(BAD)
    } else if request.method().is_safe() {
        Ok(())
    } else {
        same_origin(request.headers(), &state.config).map_err(HttpError::from)
    };
    let mut response = match origin {
        // Authority/RSS owns bounded settlement after a transaction starts. A second
        // timeout around this future could discard its CommitUnknown/RollbackFailed result.
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    };
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

/// Host-installed execution identity, checked against the route before authentication.
pub(crate) struct Execution(pub rss_transactional_messaging::fence::ExecutionBinding);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Execution {
    type Rejection = HttpError;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        use axum::extract::Path;
        let Path(params) =
            Path::<std::collections::HashMap<String, String>>::from_request_parts(parts, state)
                .await
                .map_err(|_| BAD)?;
        let selected = tenant(params.get("tenant").ok_or(BAD)?)?;
        let binding = parts
            .extensions
            .get::<rss_transactional_messaging::fence::ExecutionBinding>()
            .copied()
            .ok_or_else(|| HttpError::from(AuthorityError::Unavailable))?;
        if selected != binding.tenant() {
            return Err(UNAUTH);
        }
        Ok(Self(binding))
    }
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;
    use axum::http::StatusCode;
    #[tokio::test]
    async fn login_and_management_preserve_the_same_retry_contract() {
        let error = AuthorityError::RateLimited {
            retry_after_seconds: std::num::NonZeroU32::new(600).unwrap(),
        };
        for response in [
            HttpError::from(error).into_response(),
            crate::accounts::Error::from(error).into_response(),
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
