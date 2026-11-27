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
use rss_identity_web_credentials::{HttpConfig, SessionActivity, authenticate_request};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
struct Context {
    authority: Authority,
    storage: crate::config::StorageConfig,
    policy: Arc<BootstrapPolicy>,
    timeout: Duration,
    http: HttpConfig,
}
pub fn router(
    authority: Authority,
    config: &RuntimeConfig,
    http: HttpConfig,
) -> Result<Router, AppError> {
    Ok(Router::new()
        .route(
            "/api/v1/identity-host/tenants/{tenant}/context",
            get(context),
        )
        .with_state(Context {
            authority,
            storage: config.storage.clone(),
            policy: Arc::new(BootstrapPolicy(
                config.bootstrap_keys()?,
                std::time::Duration::from_secs(u64::from(
                    config.authority.operation_proof_seconds.get(),
                )),
            )),
            timeout: config.budgets.request(),
            http,
        }))
}
async fn context(
    State(state): State<Context>,
    Path(raw): Path<String>,
    deadline: Option<axum::Extension<rss_request_context::Deadline>>,
    headers: HeaderMap,
) -> Response {
    let deadline = deadline
        .map(|d| crate::assembly::deadline(d.0))
        .unwrap_or_else(|| OperationDeadline::from_remaining(state.timeout));
    let response = match TenantId::parse(&raw) {
        Err(_) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"code":"malformed_request"}))).into_response(),
        Ok(tenant) => match state.storage.binding(tenant) {
          Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
          Ok(binding) => match authenticate_request(&state.authority, &state.http, binding, &headers, SessionActivity::Passive, deadline).await {
            Err(error) => rss_identity_service_http::HttpError::from(error).into_response(),
            Ok((session, _credential)) => Json(serde_json::json!({
                "tenantId":session.account().tenant.to_string(),
                "principalId":session.account().principal.as_uuid().to_string(),
                "sessionId":session.view().id.to_string(),
                "navigation":{"manageAccounts":state.policy.is_manager(session.account()),"manageProviders":state.policy.is_manager(session.account())}
            })).into_response(),
        }}
    };
    private_response(response)
}
fn private_response(mut response: Response) -> Response {
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
