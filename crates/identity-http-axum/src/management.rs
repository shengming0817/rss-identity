//! Instance-local management. Domain authorization is rechecked in the mutation transaction.
use crate::{AppState, HttpConfig, boundary::*};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rss_identity_core::{
    PrincipalId,
    account::{AccountKey, AccountRuleError, LoginKey, Password},
    federation::FederationError,
};
use rss_identity_postgres::{
    AccountView, AttemptSource, AuthenticatedSession, Authority, AuthorityError,
};
use serde::{Deserialize, de::DeserializeOwned};

#[derive(Clone)]
struct Management {
    authority: Authority,
}
pub(crate) struct Error(HttpError);
impl From<HttpError> for Error {
    fn from(e: HttpError) -> Self {
        Self(e)
    }
}
impl From<AuthorityError> for Error {
    fn from(error: AuthorityError) -> Self {
        let (status, code) = match error {
            AuthorityError::Rejected => (StatusCode::UNAUTHORIZED, "invalid_credential"),
            AuthorityError::ReauthenticationFailed => {
                (StatusCode::FORBIDDEN, "reauthentication_failed")
            }
            AuthorityError::RuleRejected(AccountRuleError::InsufficientPrivilege) => {
                (StatusCode::FORBIDDEN, "insufficient_privilege")
            }
            AuthorityError::RuleRejected(AccountRuleError::AlreadyExists) => {
                (StatusCode::CONFLICT, "account_already_exists")
            }
            AuthorityError::RuleRejected(AccountRuleError::ReauthenticationRequired) => {
                (StatusCode::FORBIDDEN, "reauthentication_required")
            }
            AuthorityError::RuleRejected(AccountRuleError::Rejected)
            | AuthorityError::Invalid
            | AuthorityError::Federation(FederationError::Configuration) => {
                (StatusCode::BAD_REQUEST, "malformed_request")
            }
            AuthorityError::Federation(FederationError::ProviderLimitReached) => {
                (StatusCode::CONFLICT, "provider_limit_reached")
            }
            AuthorityError::Federation(FederationError::StaleConfiguration) => {
                (StatusCode::CONFLICT, "configuration_changed")
            }
            AuthorityError::Federation(FederationError::Conflict) => {
                (StatusCode::CONFLICT, "identity_link_conflict")
            }
            AuthorityError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            _ => (StatusCode::SERVICE_UNAVAILABLE, "identity_unavailable"),
        };
        Self(HttpError(
            status,
            code,
            Some(crate::HttpFailure::Authority(error)),
        ))
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}
type Result<T> = std::result::Result<T, Error>;
/// Local account management, independent of upstream federation.
pub fn management_router(
    authority: Authority,
    config: HttpConfig,
) -> std::result::Result<Router, AuthorityError> {
    authority.require_runtime()?;
    let local = AppState {
        authority: authority.clone(),
        config,
    };
    Ok(Router::new()
        .route(
            "/api/v2/tenants/{tenant}/accounts",
            get(accounts).post(create_account),
        )
        .route(
            "/api/v2/tenants/{tenant}/accounts/{principal}/enabled",
            post(enabled),
        )
        .route(
            "/api/v2/tenants/{tenant}/accounts/{principal}/membership",
            post(membership),
        )
        .route(
            "/api/v2/tenants/{tenant}/accounts/{principal}/password",
            post(reset_password),
        )
        .route(
            "/api/v2/tenants/{tenant}/account/password",
            post(own_password),
        )
        .layer(axum::extract::DefaultBodyLimit::max(32768))
        .route_layer(middleware::from_fn_with_state(local, request_boundary))
        .with_state(Management { authority }))
}
async fn actor(
    s: &Management,
    t: &str,
    h: &HeaderMap,
    b: RequestBudget,
    write: bool,
) -> Result<AuthenticatedSession> {
    let secret = cookie(h)?.ok_or(UNAUTH)?;
    if write {
        if unique(h, "x-identity-request")? != Some("1") {
            return Err(FORBIDDEN.into());
        }
        csrf(h, &secret)?;
    }
    Ok(s.authority
        .inspect_session(tenant(t)?, secret, b.remaining())
        .await?)
}
pub(crate) async fn body<T: DeserializeOwned>(request: Request, b: RequestBudget) -> Result<T> {
    let bytes =
        tokio::time::timeout_at(b.cutoff(), axum::body::to_bytes(request.into_body(), 32768))
            .await
            .map_err(|_| HttpError::request_timeout())?
            .map_err(|_| BAD)?;
    serde_json::from_slice(&bytes).map_err(|_| BAD.into())
}
fn target(t: &str, p: &str) -> Result<AccountKey> {
    Ok(AccountKey {
        tenant: tenant(t)?,
        principal: PrincipalId::parse(p).map_err(|_| BAD)?,
    })
}
fn password(s: String) -> Result<Password> {
    Password::new(s).map_err(|_| BAD.into())
}
fn account(state: rss_identity_core::account::AccountState) -> Response {
    Json(crate::dto::Account::from(AccountView::new(state, None))).into_response()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    cursor: Option<String>,
    limit: Option<u16>,
}
async fn accounts(
    State(s): State<Management>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    h: HeaderMap,
    q: std::result::Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Response> {
    let Query(page) = q.map_err(|_| BAD)?;
    let actor = actor(&s, &t, &h, b, false).await?;
    Ok(Json(crate::dto::AccountPage::from(
        s.authority
            .list_accounts(
                actor,
                page.cursor
                    .as_deref()
                    .map(PrincipalId::parse)
                    .transpose()
                    .map_err(|_| BAD)?,
                page.limit.unwrap_or(50),
                b.remaining(),
            )
            .await?,
    ))
    .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateAccount {
    login: String,
    password: String,
}
async fn create_account(
    State(s): State<Management>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    r: Request,
) -> Result<Response> {
    let actor = actor(&s, &t, r.headers(), b, true).await?;
    let v: CreateAccount = body(r, b).await?;
    let name = LoginKey::parse(&v.login).map_err(|_| BAD)?;
    let canonical_login = name.as_str().to_owned();
    let state = s
        .authority
        .create_local_account(actor, name, password(v.password)?, b.remaining())
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(crate::dto::Account::from(AccountView::new(
            state,
            Some(canonical_login),
        ))),
    )
        .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Toggle {
    enabled: bool,
}
async fn enabled(
    State(s): State<Management>,
    Path((t, p)): Path<(String, String)>,
    Extension(b): Extension<RequestBudget>,
    r: Request,
) -> Result<Response> {
    let actor = actor(&s, &t, r.headers(), b, true).await?;
    let v: Toggle = body(r, b).await?;
    Ok(account(
        s.authority
            .set_account_enabled(actor, target(&t, &p)?, v.enabled, b.remaining())
            .await?,
    ))
}
async fn membership(
    State(s): State<Management>,
    Path((t, p)): Path<(String, String)>,
    Extension(b): Extension<RequestBudget>,
    r: Request,
) -> Result<Response> {
    let actor = actor(&s, &t, r.headers(), b, true).await?;
    let v: Toggle = body(r, b).await?;
    Ok(account(
        s.authority
            .set_account_membership(actor, target(&t, &p)?, v.enabled, b.remaining())
            .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reset {
    password: String,
}
async fn reset_password(
    State(s): State<Management>,
    Path((t, p)): Path<(String, String)>,
    Extension(b): Extension<RequestBudget>,
    r: Request,
) -> Result<Response> {
    let actor = actor(&s, &t, r.headers(), b, true).await?;
    let v: Reset = body(r, b).await?;
    Ok(account(
        s.authority
            .reset_local_password(actor, target(&t, &p)?, password(v.password)?, b.remaining())
            .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangePassword {
    current_password: String,
    password: String,
}
async fn own_password(
    State(s): State<Management>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    r: Request,
) -> Result<Response> {
    let actor = actor(&s, &t, r.headers(), b, true).await?;
    let peer = r
        .extensions()
        .get::<crate::ClientAddress>()
        .ok_or(AuthorityError::Unavailable)?
        .0;
    let source = AttemptSource::parse(&peer.to_string())?;
    let v: ChangePassword = body(r, b).await?;
    Ok(account(
        s.authority
            .change_own_password(
                actor,
                password(v.current_password)?,
                password(v.password)?,
                source,
                b.remaining(),
            )
            .await?,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn management_rejections_are_not_login_failures() {
        for (error, status, code) in [
            (
                AuthorityError::RuleRejected(AccountRuleError::Rejected),
                StatusCode::BAD_REQUEST,
                "malformed_request",
            ),
            (
                AuthorityError::Rejected,
                StatusCode::UNAUTHORIZED,
                "invalid_credential",
            ),
            (
                AuthorityError::RuleRejected(AccountRuleError::InsufficientPrivilege),
                StatusCode::FORBIDDEN,
                "insufficient_privilege",
            ),
            (
                AuthorityError::ReauthenticationFailed,
                StatusCode::FORBIDDEN,
                "reauthentication_failed",
            ),
            (
                AuthorityError::RuleRejected(AccountRuleError::ReauthenticationRequired),
                StatusCode::FORBIDDEN,
                "reauthentication_required",
            ),
        ] {
            let value = Error::from(error);
            assert_eq!(value.0.0, status);
            assert_eq!(value.0.1, code);
        }
    }
}
