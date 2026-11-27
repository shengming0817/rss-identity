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
pub(crate) use rss_request_context::Deadline;
use rss_request_context::TenantId;
use std::time::{Duration, Instant};

pub(crate) fn request_deadline(
    request: &Request,
    timeout: Duration,
    now: Instant,
) -> Result<Deadline, HttpError> {
    let mut deadline = Deadline::at(
        now.checked_add(timeout)
            .ok_or_else(HttpError::request_timeout)?,
    );
    if let Some(host) = request.extensions().get::<Deadline>() {
        deadline = deadline.shortened_to(host.instant());
    }
    if deadline.is_expired(now) {
        return Err(HttpError::request_timeout());
    }
    Ok(deadline)
}
pub(crate) fn bind_deadline(request: &mut Request, state: &AppState) -> Result<(), HttpError> {
    use rss_request_context::Clock;
    let timer = state.authority.execution_timer();
    let deadline = request_deadline(request, state.config.timeout(), timer.now())?;
    request.extensions_mut().insert(deadline);
    request.extensions_mut().insert(timer.clone());
    Ok(())
}

/// Only cancel the inbound body reader. Transaction settlement owns its own deadline arbitration.
pub(crate) async fn read_body<T, E, F>(
    mut request: Request,
    deadline: Deadline,
    read: impl FnOnce(Request) -> F,
) -> Result<T, HttpError>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    use rss_request_context::{ExecutionTimer, SharedExecutionTimer};
    let timer = request
        .extensions_mut()
        .remove::<SharedExecutionTimer>()
        .ok_or_else(|| HttpError::from(AuthorityError::Unavailable))?;
    tokio::select! {
        biased;
        _ = timer.sleep_until(deadline) => Err(HttpError::request_timeout()),
        value = read(request) => value.map_err(|_| BAD),
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
    if let Err(error) = bind_deadline(&mut request, &state) {
        return private_response(error.into_response());
    }
    let origin = if original_uri.to_string().len() > 8192
        || cookie_presentation(request.headers()).is_err()
    {
        Err(BAD)
    } else if request.method().is_safe() {
        Ok(())
    } else {
        same_origin(request.headers(), &state.config).map_err(HttpError::from)
    };
    let response = match origin {
        // Authority/RSS owns bounded settlement after a transaction starts. A second
        // timeout around this future could discard its CommitUnknown/RollbackFailed result.
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    };
    private_response(response)
}

fn private_response(mut response: Response) -> Response {
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

#[cfg(test)]
mod body_deadline_tests {
    use super::*;
    use axum::http::StatusCode;
    use rss_request_context::{Clock, ExecutionTimer, SharedExecutionTimer};

    struct ManualTimer(tokio::sync::watch::Receiver<Instant>);
    impl Clock for ManualTimer {
        fn now(&self) -> Instant {
            *self.0.borrow()
        }
    }
    impl ExecutionTimer for ManualTimer {
        async fn sleep_until(&self, deadline: Deadline) {
            self.0
                .clone()
                .wait_for(|now| deadline.is_expired(*now))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn pending_body_expires_on_the_host_clock() {
        let now = Instant::now() + Duration::from_secs(3600);
        let deadline = Deadline::at(now + Duration::from_secs(30));
        let (advance, clock) = tokio::sync::watch::channel(now);
        let mut request = Request::default();
        request
            .extensions_mut()
            .insert(SharedExecutionTimer::new(ManualTimer(clock)));
        let (started, reading) = tokio::sync::oneshot::channel();
        let reader = tokio::spawn(read_body(request, deadline, |_| async move {
            started.send(()).unwrap();
            std::future::pending::<Result<(), ()>>().await
        }));
        reading.await.unwrap();
        advance.send(deadline.instant()).unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(2), reader)
            .await
            .unwrap()
            .unwrap();
        let response = outcome.unwrap_err().into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.extensions().get::<HttpFailure>(),
            Some(&HttpFailure::RequestTimeout)
        );
    }
}
