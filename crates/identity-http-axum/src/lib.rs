//! Instance-local authentication HTTP adapter; no listener or forwarded-header trust.
//! ref: axum extract/state.rs @ c59208c86fded335cd85e388030ad59347b0e5ae.
mod boundary;
mod dto;
mod federation;
mod handlers;
mod management;
mod provider_management;
use axum::{
    Router, middleware,
    routing::{get, post},
};
pub use boundary::{HttpConfig, HttpConfigError, HttpFailure};
pub use federation::federated_router;
use rss_identity_postgres::{Authority, AuthorityError};

#[derive(Clone)]
struct AppState {
    authority: Authority,
    config: HttpConfig,
}

/// Mount behind TLS at the configured origin. Host middleware must insert [`ClientAddress`]
/// from its trusted transport before entering these routes. Axum `ConnectInfo<SocketAddr>`
/// alone is insufficient. For a direct connection use the accepted peer's IP; behind a
/// proxy validate the peer before interpreting any forwarded header. See the embedding guide.
pub fn router(authority: Authority, config: HttpConfig) -> Result<Router, AuthorityError> {
    authority.require_runtime()?;
    let management = management::management_router(authority.clone(), config.clone())?;
    let state = AppState { authority, config };
    Ok(Router::new()
        .route("/api/v2/tenants/{tenant}/login", post(handlers::login))
        .route(
            "/api/v2/tenants/{tenant}/session/reauthenticate",
            post(handlers::reauthenticate),
        )
        .route("/api/v2/tenants/{tenant}/session", get(handlers::current))
        .route(
            "/api/v2/tenants/{tenant}/session/refresh",
            post(handlers::refresh),
        )
        .route(
            "/api/v2/tenants/{tenant}/session/logout",
            post(handlers::logout),
        )
        .route(
            "/api/v2/tenants/{tenant}/sessions/logout-all",
            post(handlers::logout_all),
        )
        .route("/api/v2/tenants/{tenant}/sessions", get(handlers::list))
        .layer(axum::extract::DefaultBodyLimit::max(4096))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            boundary::request_boundary,
        ))
        .with_state(state)
        .merge(management))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::{cookie, csrf, session_cookie};
    #[test]
    fn session_origin_configuration_is_explicit_and_canonical() {
        assert!(
            HttpConfig::new(
                "https://identity.example.test",
                std::time::Duration::from_secs(10)
            )
            .is_ok()
        );
        for bad in [
            "http://identity.example.test",
            "https://identity.example.test/",
            "https://user@identity.example.test",
            "https://identity.example.test/path",
            "https://identity.example.test?x=1",
            "https://identity.example.test#fragment",
        ] {
            assert!(HttpConfig::new(bad, std::time::Duration::from_secs(10)).is_err());
        }
    }
    #[test]
    fn session_cookie_and_csrf_are_strict() {
        let secret = rss_identity_core::session::SessionSecret::generate().unwrap();
        let header = session_cookie(&secret, 100);
        assert_eq!(
            header,
            format!(
                "__Host-identity-session={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=100",
                secret.expose()
            )
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "cookie",
            format!("__Host-identity-session={}", secret.expose())
                .parse()
                .unwrap(),
        );
        headers.insert("x-csrf-token", secret.csrf().parse().unwrap());
        assert!(csrf(&headers, &cookie(&headers).unwrap().unwrap()).is_ok());
        headers.append(
            "cookie",
            format!("__Host-identity-session={}", secret.expose())
                .parse()
                .unwrap(),
        );
        assert!(cookie(&headers).is_err());
    }
    #[tokio::test]
    async fn session_failure_classes_remain_internal_and_distinct() {
        use crate::boundary::{HttpError, HttpFailure};
        use axum::{body::to_bytes, response::IntoResponse};
        use rss_identity_postgres::{AuthorityError, StorageFailure};
        for error in [
            AuthorityError::CommitUnknown(StorageFailure::Transient),
            AuthorityError::RollbackFailed(StorageFailure::Transient),
            AuthorityError::Fenced,
            AuthorityError::Configuration,
            AuthorityError::DeadlineElapsed,
        ] {
            let response = HttpError::from(error).into_response();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            );
            assert_eq!(
                response.extensions().get::<HttpFailure>(),
                Some(&HttpFailure::Authority(error))
            );
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"code":"identity_unavailable"})
            );
        }
    }
}

/// Client attribution supplied by the hosting transport after its proxy trust check.
/// Required by password login, reauthentication and password changes. For direct TLS hosts,
/// map accepted Axum `ConnectInfo<SocketAddr>` to this extension in host middleware. Forwarded
/// headers are never interpreted by this adapter. The raw peer remains in `ConnectInfo`.
#[derive(Clone, Copy, Debug)]
pub struct ClientAddress(pub std::net::IpAddr);

/// Host-selected activity policy. Passive background reads never extend idle expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionActivity {
    Passive,
    /// Requires the configured Origin, X-Identity-Request: 1 and credential-bound CSRF.
    Active,
}

/// Authenticate a host resource request using the same strict cookie/CSRF boundary as the routes.
/// Active requests extend idle expiry; passive reads do not. Both recheck authoritative state.
/// The returned proof is request-local. The zeroizing credential is for server-side protocol
/// continuation only: do not log it, expose it in a response or cache a successful proof.
/// Hosts still own resource authorization, activity selection and successful response no-store.
/// The smaller of the caller budget and HTTP timeout bounds the operation. Await settlement;
/// do not wrap this future in a timeout that could discard a committed/unknown outcome.
pub async fn authenticate_request(
    authority: &Authority,
    config: &HttpConfig,
    tenant: rss_request_context::TenantId,
    headers: &axum::http::HeaderMap,
    activity: SessionActivity,
    deadline: rss_transactional_messaging::policy::OperationDeadline,
) -> Result<
    (
        rss_identity_postgres::AuthenticatedSession,
        rss_identity_core::session::SessionSecret,
    ),
    axum::response::Response,
> {
    use axum::response::IntoResponse;
    let budget = boundary::RequestBudget::new(deadline.timeout().min(config.timeout));
    let result = async {
        authority.require_runtime()?;
        if activity == SessionActivity::Active {
            boundary::same_origin(headers, config)?;
            if boundary::unique(headers, "x-identity-request")? != Some("1") {
                return Err(boundary::FORBIDDEN);
            }
        }
        let secret = boundary::cookie(headers)?.ok_or(boundary::UNAUTH)?;
        if activity == SessionActivity::Active {
            boundary::csrf(headers, &secret)?;
        }
        let credential = rss_identity_core::session::SessionSecret::parse(secret.expose().into())
            .map_err(|_| boundary::UNAUTH)?;
        let proof = match activity {
            SessionActivity::Passive => {
                authority
                    .inspect_session(tenant, secret, budget.remaining())
                    .await
            }
            SessionActivity::Active => {
                authority
                    .authenticate_session(tenant, secret, budget.remaining())
                    .await
            }
        }?;
        Ok((proof, credential))
    }
    .await;
    result.map_err(|error: boundary::HttpError| {
        let mut response = error.into_response();
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        response.headers_mut().insert(
            axum::http::header::REFERRER_POLICY,
            axum::http::HeaderValue::from_static("no-referrer"),
        );
        response
    })
}
