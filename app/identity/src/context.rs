//! One protected reference resource; navigation hints share the host's management policy.
//! ref: axum extract/state.rs @ c59208c86fded335cd85e388030ad59347b0e5ae.
use crate::{AppError, assembly::BootstrapPolicy, config::RuntimeConfig};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use rss_identity_postgres::Authority;
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
struct Context {
    authority: Authority,
    policy: Arc<BootstrapPolicy>,
    timeout: Duration,
}
pub fn router(authority: Authority, config: &RuntimeConfig) -> Result<Router, AppError> {
    Ok(Router::new()
        .route(
            "/api/identity-host/v1/tenants/{tenant}/context",
            get(context),
        )
        .with_state(Context {
            authority,
            policy: Arc::new(BootstrapPolicy(config.bootstrap_keys()?)),
            timeout: config.budgets.request(),
        }))
}
async fn context(
    State(state): State<Context>,
    Path(raw): Path<String>,
    headers: HeaderMap,
) -> Response {
    let mut response = match TenantId::parse(&raw) {
        Err(_) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"code":"malformed_request"}))).into_response(),
        Ok(tenant) => match rss_identity_http_axum::inspect_session(&state.authority, tenant, &headers, OperationDeadline::from_remaining(state.timeout)).await {
            Err(response) => response,
            Ok(session) => Json(serde_json::json!({
                "tenantId":session.account().tenant.to_string(),
                "principalId":session.account().principal.as_uuid().to_string(),
                "sessionId":session.view().id.to_string(),
                "navigation":{"manageAccounts":state.policy.is_manager(session.account()),"manageProviders":state.policy.is_manager(session.account())}
            })).into_response(),
        }
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    response
}
