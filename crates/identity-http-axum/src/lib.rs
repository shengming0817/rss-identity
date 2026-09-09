//! Central Identity session HTTP adapter; no listener or forwarded-header trust.
//! ref: axum extract/state.rs @ c59208c86fded335cd85e388030ad59347b0e5ae.
mod boundary;
mod downstream;
pub use downstream::{DownstreamDiagnostic, downstream_router};
mod federation;
mod handlers;
mod management;
use axum::{
    Router, middleware,
    routing::{get, post},
};
pub use boundary::{HttpConfig, HttpConfigError, HttpFailure};
pub use federation::federated_router;
pub use management::management_router;
use rss_identity_postgres::{Authority, AuthorityError};

#[derive(Clone)]
struct AppState {
    authority: Authority,
    config: HttpConfig,
}

/// Mount behind TLS at the configured origin. Supply Axum ConnectInfo<SocketAddr> from
/// the accepted connection; a reverse proxy requires a separately trusted transport adapter.
pub fn router(authority: Authority, config: HttpConfig) -> Result<Router, AuthorityError> {
    authority.require_runtime()?;
    let state = AppState { authority, config };
    Ok(Router::new()
        .route("/api/v1/tenants/{tenant}/login", post(handlers::login))
        .route("/api/v1/tenants/{tenant}/session", get(handlers::current))
        .route(
            "/api/v1/tenants/{tenant}/session/refresh",
            post(handlers::refresh),
        )
        .route(
            "/api/v1/tenants/{tenant}/session/logout",
            post(handlers::logout),
        )
        .route(
            "/api/v1/tenants/{tenant}/sessions/logout-all",
            post(handlers::logout_all),
        )
        .route("/api/v1/tenants/{tenant}/sessions", get(handlers::list))
        .layer(axum::extract::DefaultBodyLimit::max(4096))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            boundary::request_boundary,
        ))
        .with_state(state))
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
