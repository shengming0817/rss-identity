use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use rss_identity_postgres::AuthorityError;
use rss_identity_web_credentials::CredentialError;
/// Non-secret response extension for host diagnostics; never included in the public body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpFailure {
    Authority(AuthorityError),
    RequestTimeout,
}
#[derive(Debug)]
pub struct HttpError(
    pub(crate) StatusCode,
    pub(crate) &'static str,
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

impl From<CredentialError> for HttpError {
    fn from(error: CredentialError) -> Self {
        match error {
            CredentialError::Malformed => BAD,
            CredentialError::Invalid => UNAUTH,
            CredentialError::Forbidden => FORBIDDEN,
            CredentialError::Deadline => Self::request_timeout(),
            CredentialError::Authority(e) => Self::from(e),
        }
    }
}
