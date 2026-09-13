//! Central-session management. Domain authorization is rechecked in the mutation transaction.
use crate::{AppState, HttpConfig, boundary::*};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use rss_identity_core::{
    PrincipalId,
    account::{AccountKey, AccountRuleError, LoginKey, Password},
    federation::*,
};
use rss_identity_postgres::{
    AccountView, AttemptSource, AuthenticatedSession, AuthorityError, Federation, LocalAccountRole,
};
use serde::{Deserialize, de::DeserializeOwned};

#[derive(Clone)]
struct Management {
    federation: Federation,
}
struct Error(HttpError);
impl From<HttpError> for Error {
    fn from(e: HttpError) -> Self {
        Self(e)
    }
}
impl From<AuthorityError> for Error {
    fn from(error: AuthorityError) -> Self {
        let (status, code) = match error {
            AuthorityError::Platform(
                rss_identity_core::platform::PlatformError::LastAdministrator,
            ) => (StatusCode::CONFLICT, "last_platform_administrator"),
            AuthorityError::Platform(rss_identity_core::platform::PlatformError::Forbidden) => {
                (StatusCode::FORBIDDEN, "insufficient_privilege")
            }
            AuthorityError::Platform(rss_identity_core::platform::PlatformError::Invalid) => {
                (StatusCode::BAD_REQUEST, "malformed_request")
            }
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
            AuthorityError::RuleRejected(AccountRuleError::LastAdministrator) => {
                (StatusCode::CONFLICT, "last_administrator")
            }
            AuthorityError::Invalid
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
/// Mount once alongside `federated_router` and `downstream_router` on the same HTTPS origin.
pub fn management_router(
    federation: Federation,
    config: HttpConfig,
) -> std::result::Result<Router, AuthorityError> {
    let authority = federation.authority();
    authority.require_runtime()?;
    let local = AppState { authority, config };
    Ok(Router::new()
        .route("/api/v1/tenants/{tenant}/login-options", get(options))
        .route(
            "/api/v1/tenants/{tenant}/accounts",
            get(accounts).post(create_account),
        )
        .route(
            "/api/v1/tenants/{tenant}/accounts/{principal}/enabled",
            post(enabled),
        )
        .route(
            "/api/v1/tenants/{tenant}/accounts/{principal}/administrator",
            post(administrator),
        )
        .route(
            "/api/v1/tenants/{tenant}/accounts/{principal}/membership",
            post(membership),
        )
        .route(
            "/api/v1/tenants/{tenant}/accounts/{principal}/password",
            post(reset_password),
        )
        .route(
            "/api/v1/tenants/{tenant}/account/password",
            post(own_password),
        )
        .route(
            "/api/v1/tenants/{tenant}/providers",
            get(providers).post(create_provider),
        )
        .route(
            "/api/v1/tenants/{tenant}/providers/{provider}",
            put(update_provider),
        )
        .route(
            "/api/v1/tenants/{tenant}/providers/{provider}/enabled",
            post(provider_enabled),
        )
        .route(
            "/api/v1/tenants/{tenant}/providers/{provider}/test",
            post(test_provider),
        )
        .layer(axum::extract::DefaultBodyLimit::max(32768))
        .layer(middleware::from_fn_with_state(local, request_boundary))
        .with_state(Management { federation }))
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
    Ok(s.federation
        .authority()
        .inspect_session(tenant(t)?, secret, b.remaining())
        .await?)
}
async fn body<T: DeserializeOwned>(request: Request, b: RequestBudget) -> Result<T> {
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
    Json(AccountView::new(state, None)).into_response()
}
async fn options(
    State(s): State<Management>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
) -> Result<Response> {
    Ok(Json(serde_json::json!({"providers":s.federation.login_options(tenant(&t)?,b.remaining()).await?})).into_response())
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
    Ok(Json(
        s.federation
            .authority()
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
    )
    .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateAccount {
    login: String,
    password: String,
    role: LocalAccountRole,
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
        .federation
        .authority()
        .create_local_account(actor, name, password(v.password)?, v.role, b.remaining())
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(AccountView::new(state, Some(canonical_login))),
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
        s.federation
            .authority()
            .set_account_enabled(actor, target(&t, &p)?, v.enabled, b.remaining())
            .await?,
    ))
}
async fn administrator(
    State(s): State<Management>,
    Path((t, p)): Path<(String, String)>,
    Extension(b): Extension<RequestBudget>,
    r: Request,
) -> Result<Response> {
    let actor = actor(&s, &t, r.headers(), b, true).await?;
    let v: Toggle = body(r, b).await?;
    Ok(account(
        s.federation
            .authority()
            .set_account_administrator(actor, target(&t, &p)?, v.enabled, b.remaining())
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
        s.federation
            .authority()
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
        s.federation
            .authority()
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
        s.federation
            .authority()
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
async fn providers(
    State(s): State<Management>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    h: HeaderMap,
) -> Result<Response> {
    let actor = actor(&s, &t, &h, b, false).await?;
    Ok(Json(
        serde_json::json!({"providers":s.federation.list_providers(actor,b.remaining()).await?}),
    )
    .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateProvider {
    settings: ProviderSettingsInput,
    client_secret: String,
    ca_pem: Option<String>,
}
async fn create_provider(
    State(s): State<Management>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    r: Request,
) -> Result<Response> {
    let actor = actor(&s, &t, r.headers(), b, true).await?;
    let v: CreateProvider = body(r, b).await?;
    let credentials =
        ProviderCredentials::new(v.client_secret, v.ca_pem).map_err(AuthorityError::from)?;
    let settings = ProviderSettings::try_from(v.settings).map_err(AuthorityError::from)?;
    Ok((
        StatusCode::CREATED,
        Json(
            s.federation
                .create_provider(actor, settings, credentials, b.remaining())
                .await?,
        ),
    )
        .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateProvider {
    expected_version: i64,
    settings: ProviderSettingsInput,
    client_secret: String,
    ca_pem: Option<String>,
}
async fn update_provider(
    State(s): State<Management>,
    Path((t, p)): Path<(String, ProviderId)>,
    Extension(b): Extension<RequestBudget>,
    r: Request,
) -> Result<Response> {
    let actor = actor(&s, &t, r.headers(), b, true).await?;
    let v: UpdateProvider = body(r, b).await?;
    let credentials =
        ProviderCredentials::new(v.client_secret, v.ca_pem).map_err(AuthorityError::from)?;
    let settings = ProviderSettings::try_from(v.settings).map_err(AuthorityError::from)?;
    Ok(Json(
        s.federation
            .update_provider(
                actor,
                p,
                v.expected_version,
                settings,
                credentials,
                b.remaining(),
            )
            .await?,
    )
    .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderToggle {
    expected_version: i64,
    enabled: bool,
}
async fn provider_enabled(
    State(s): State<Management>,
    Path((t, p)): Path<(String, ProviderId)>,
    Extension(b): Extension<RequestBudget>,
    r: Request,
) -> Result<Response> {
    let actor = actor(&s, &t, r.headers(), b, true).await?;
    let v: ProviderToggle = body(r, b).await?;
    Ok(Json(
        s.federation
            .enable_provider(actor, p, v.expected_version, v.enabled, b.remaining())
            .await?,
    )
    .into_response())
}
async fn test_provider(
    State(s): State<Management>,
    Path((t, p)): Path<(String, ProviderId)>,
    Extension(b): Extension<RequestBudget>,
    h: HeaderMap,
) -> Result<Response> {
    let actor = actor(&s, &t, &h, b, true).await?;
    match s.federation.test_provider(actor, p, b.remaining()).await {
        Ok(report) => Ok(Json(serde_json::json!({"passed":true,"report":report})).into_response()),
        Err(AuthorityError::Federation(
            error @ (FederationError::Provider(_) | FederationError::Unavailable),
        )) => Ok(
            Json(serde_json::json!({"passed":false,"diagnostic":error.diagnostic()}))
                .into_response(),
        ),
        Err(error) => Err(error.into()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn management_rejections_are_not_login_failures() {
        for (error, status, code) in [
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
                AuthorityError::RuleRejected(AccountRuleError::LastAdministrator),
                StatusCode::CONFLICT,
                "last_administrator",
            ),
        ] {
            let value = Error::from(error);
            assert_eq!(value.0.0, status);
            assert_eq!(value.0.1, code);
        }
    }
}
