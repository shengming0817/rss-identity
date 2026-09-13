//! Platform HTTP operations share central sessions and the transaction authority.
use crate::{AppState, boundary::*};
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
    account::{LoginKey, Password},
    platform::PlatformError,
};
use rss_identity_postgres::{
    AuthenticatedSession, Authority, AuthorityError, NewTenantAdministrator, PlatformOperation,
};
use serde::{Deserialize, de::DeserializeOwned};
use uuid::Uuid;

struct Error(HttpError);
impl From<HttpError> for Error {
    fn from(e: HttpError) -> Self {
        Self(e)
    }
}
impl From<AuthorityError> for Error {
    fn from(e: AuthorityError) -> Self {
        let (status, code) = match e {
            AuthorityError::Platform(PlatformError::Forbidden) => {
                (StatusCode::FORBIDDEN, "platform_administrator_required")
            }
            AuthorityError::Platform(PlatformError::Invalid) => {
                (StatusCode::BAD_REQUEST, "invalid_platform_request")
            }
            AuthorityError::Platform(PlatformError::NotObserved) => {
                (StatusCode::NOT_FOUND, "operation_not_observed")
            }
            AuthorityError::Platform(PlatformError::LastAdministrator) => {
                (StatusCode::CONFLICT, "last_platform_administrator")
            }
            AuthorityError::Platform(PlatformError::Conflict) => {
                (StatusCode::CONFLICT, "platform_conflict")
            }
            AuthorityError::Platform(PlatformError::Capacity) => {
                (StatusCode::CONFLICT, "tenant_limit_reached")
            }
            AuthorityError::CommitUnknown(_) | AuthorityError::RollbackFailed(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "operation_outcome_unknown")
            }
            AuthorityError::NotStarted(_)
            | AuthorityError::RolledBack(_)
            | AuthorityError::Fenced => {
                (StatusCode::SERVICE_UNAVAILABLE, "operation_not_completed")
            }
            _ => return Self(e.into()),
        };
        Self(HttpError(status, code, Some(HttpFailure::Authority(e))))
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}
type Result<T> = std::result::Result<T, Error>;
/// Mount on the central origin. No caller-supplied domain selects the platform authority.
pub fn platform_router(
    authority: Authority,
    config: HttpConfig,
) -> std::result::Result<Router, AuthorityError> {
    authority.require_runtime()?;
    let state = AppState { authority, config };
    Ok(Router::new()
        .route("/api/v1/platform", get(context))
        .route("/api/v1/platform/tenants", get(list).post(create))
        .route("/api/v1/platform/tenants/{tenant}", get(detail))
        .route(
            "/api/v1/platform/tenants/{tenant}/administrators",
            post(add),
        )
        .route("/api/v1/platform/operations/{operation}", get(operation))
        .route("/api/v1/platform/accounts/{principal}/role", post(role))
        .layer(axum::extract::DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            request_boundary,
        ))
        .with_state(state))
}
async fn actor(
    s: &AppState,
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
    let actor = s
        .authority
        .inspect_session(s.authority.system_domain(), secret, b.remaining())
        .await?;
    if !actor.identity().platform_administrator {
        return Err(AuthorityError::Platform(PlatformError::Forbidden).into());
    }
    Ok(actor)
}
async fn body<T: DeserializeOwned>(r: Request, b: RequestBudget) -> Result<T> {
    let bytes = tokio::time::timeout_at(b.cutoff(), axum::body::to_bytes(r.into_body(), 8192))
        .await
        .map_err(|_| HttpError::request_timeout())?
        .map_err(|_| BAD)?;
    serde_json::from_slice(&bytes).map_err(|_| BAD.into())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Administrator {
    operation_id: Uuid,
    principal_id: String,
    login: String,
    password: String,
}
impl Administrator {
    fn input(self, target: &str) -> Result<NewTenantAdministrator> {
        Ok(NewTenantAdministrator {
            operation_id: self.operation_id,
            tenant: tenant(target)?,
            principal: PrincipalId::parse(&self.principal_id).map_err(|_| BAD)?,
            login: LoginKey::parse(&self.login).map_err(|_| BAD)?,
            password: Password::new(self.password).map_err(|_| BAD)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    tenant_id: String,
    name: String,
    administrator: Administrator,
}
async fn context(
    State(s): State<AppState>,
    Extension(b): Extension<RequestBudget>,
    h: HeaderMap,
) -> Result<Response> {
    let actor = actor(&s, &h, b, false).await?;
    Ok(Json(serde_json::json!({"system_domain_id":s.authority.system_domain().to_string(),"identity":actor.identity()})).into_response())
}
async fn create(
    State(s): State<AppState>,
    Extension(b): Extension<RequestBudget>,
    r: Request,
) -> Result<Response> {
    let actor = actor(&s, r.headers(), b, true).await?;
    let v: Create = body(r, b).await?;
    let target = tenant(&v.tenant_id)?;
    let result = s
        .authority
        .provision_business_tenant(
            actor,
            v.name,
            v.administrator.input(&v.tenant_id)?,
            b.remaining(),
        )
        .await?;
    let _ = s.authority.activate_registered_tenants(b.remaining()).await;
    Ok(operation_response(
        result,
        s.authority.tenant_active(target),
    ))
}
fn operation_response(result: PlatformOperation, active: bool) -> Response {
    (
        if active {
            StatusCode::CREATED
        } else {
            StatusCode::ACCEPTED
        },
        Json(serde_json::json!({"operation":result,"active":active})),
    )
        .into_response()
}
async fn add(
    State(s): State<AppState>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    r: Request,
) -> Result<Response> {
    let actor = actor(&s, r.headers(), b, true).await?;
    let v: Administrator = body(r, b).await?;
    let result = s
        .authority
        .add_business_tenant_administrator(actor, v.input(&t)?, b.remaining())
        .await?;
    Ok(operation_response(result, true))
}
async fn operation(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    Extension(b): Extension<RequestBudget>,
    h: HeaderMap,
) -> Result<Response> {
    let actor = actor(&s, &h, b, false).await?;
    let result = s
        .authority
        .platform_operation(actor, id, b.remaining())
        .await?;
    let _ = s.authority.activate_registered_tenants(b.remaining()).await;
    let active = s.authority.tenant_active(tenant(&result.tenant_id)?);
    Ok(Json(serde_json::json!({"operation":result,"active":active})).into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    cursor: Option<String>,
    limit: Option<u16>,
}
async fn list(
    State(s): State<AppState>,
    Extension(b): Extension<RequestBudget>,
    Query(p): Query<Page>,
    h: HeaderMap,
) -> Result<Response> {
    let actor = actor(&s, &h, b, false).await?;
    Ok(Json(
        s.authority
            .list_tenants(
                actor,
                p.cursor.as_deref().map(tenant).transpose()?,
                p.limit.unwrap_or(50),
                b.remaining(),
            )
            .await?,
    )
    .into_response())
}
async fn detail(
    State(s): State<AppState>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    h: HeaderMap,
) -> Result<Response> {
    let actor = actor(&s, &h, b, false).await?;
    Ok(Json(
        s.authority
            .tenant_detail(actor, tenant(&t)?, b.remaining())
            .await?,
    )
    .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Role {
    granted: bool,
}
async fn role(
    State(s): State<AppState>,
    Path(p): Path<String>,
    Extension(b): Extension<RequestBudget>,
    r: Request,
) -> Result<Response> {
    let actor = actor(&s, r.headers(), b, true).await?;
    let v: Role = body(r, b).await?;
    let state = s
        .authority
        .set_platform_role(
            actor,
            PrincipalId::parse(&p).map_err(|_| BAD)?,
            v.granted,
            b.remaining(),
        )
        .await?;
    Ok(Json(serde_json::json!({"principal_id":state.key().principal.as_uuid(),"auth_epoch":state.epoch(),"platform_administrator":v.granted})).into_response())
}
