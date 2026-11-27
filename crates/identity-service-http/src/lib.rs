//! HTTP contract of the standalone Identity service.
//! ref: axum extract/state.rs @ c59208c86fded335cd85e388030ad59347b0e5ae.
mod bearer;
mod boundary;
mod routes;
use routes::mount;
pub use routes::{ServiceEndpoints, routes};
mod dto;
mod error;
mod oidc;
pub use oidc::protect_callback;
mod accounts;
mod profiles;
mod providers;
mod session;
use axum::{
    Router, middleware,
    routing::{get, post},
};
pub use error::{HttpError, HttpFailure};
use rss_identity_web_credentials::HttpConfig;

use rss_identity_postgres::{Authority, AuthorityError};

#[derive(Clone)]
struct AppState {
    authority: Authority,
    config: HttpConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn session_failure_classes_remain_internal_and_distinct() {
        use crate::boundary::{HttpError, HttpFailure};
        use axum::{body::to_bytes, response::IntoResponse};
        use rss_identity_postgres::{AuthorityError, StorageFailure};
        for error in [
            AuthorityError::RolledBack(StorageFailure::Transient),
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

mod webauthn;

#[cfg(test)]
mod budget_tests {
    use super::*;
    #[test]
    fn request_budget_validates_finite_time_and_overflow() {
        for seconds in [120, 3600] {
            let duration = std::time::Duration::from_secs(seconds);
            assert!(HttpConfig::new("https://identity.example.test", duration).is_ok());
            assert!(boundary::RequestBudget::new(duration).is_ok());
        }
        for duration in [std::time::Duration::ZERO, std::time::Duration::MAX] {
            assert!(HttpConfig::new("https://identity.example.test", duration).is_err());
            assert!(boundary::RequestBudget::new(duration).is_err());
        }
    }
}
