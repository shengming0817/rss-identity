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
use rss_identity_core::assurance::{Acr, Assurance};
use rss_identity_http_axum::{HttpConfig, SessionActivity, authenticate_request};
use rss_identity_postgres::Authority;
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
struct Context {
    authority: Authority,
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
            "/api/identity-host/v1/tenants/{tenant}/context",
            get(context),
        )
        .route(
            "/api/identity-host/v1/tenants/{tenant}/mfa-example",
            get(mfa_example),
        )
        .with_state(Context {
            authority,
            policy: Arc::new(BootstrapPolicy(config.bootstrap_keys()?)),
            timeout: config.budgets.request(),
            http,
        }))
}
async fn context(
    State(state): State<Context>,
    Path(raw): Path<String>,
    headers: HeaderMap,
) -> Response {
    let response = match TenantId::parse(&raw) {
        Err(_) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"code":"malformed_request"}))).into_response(),
        Ok(tenant) => match authenticate_request(&state.authority, &state.http, tenant, &headers, SessionActivity::Passive, OperationDeadline::from_remaining(state.timeout)).await {
            Err(response) => response,
            Ok((session, _credential)) => Json(serde_json::json!({
                "tenantId":session.account().tenant.to_string(),
                "principalId":session.account().principal.as_uuid().to_string(),
                "sessionId":session.view().id.to_string(),
                "navigation":{"manageAccounts":state.policy.is_manager(session.account()),"manageProviders":state.policy.is_manager(session.account())}
            })).into_response(),
        }
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

/// Maximum accepted age of MFA for the protected reference resource.
pub const MFA_MAX_AGE_SECONDS: i64 = 300;

fn fresh_mfa(facts: &Assurance, now: i64) -> bool {
    facts.acr() == Acr::Mfa
        && facts
            .auth_time()
            .and_then(|time| now.checked_sub(time))
            .is_some_and(|age| (0..MFA_MAX_AGE_SECONDS).contains(&age))
}
async fn mfa_example(
    State(state): State<Context>,
    Path(raw): Path<String>,
    headers: HeaderMap,
) -> Response {
    let response = async {
        let tenant = match TenantId::parse(&raw) {
            Ok(tenant) => tenant,
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"code":"malformed_request"}))).into_response(),
        };
        let session = match authenticate_request(&state.authority, &state.http, tenant, &headers, SessionActivity::Passive, OperationDeadline::from_remaining(state.timeout)).await {
            Ok((session, _credential)) => session,
            Err(response) => return response,
        };
        let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok().and_then(|d| i64::try_from(d.as_secs()).ok()) {
            Some(now) => now,
            None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"code":"identity_unavailable"}))).into_response(),
        };
        let facts = match session.assurance() {
            Ok(facts) => facts,
            Err(_) => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"code":"invalid_credential"}))).into_response(),
        };
        if !fresh_mfa(facts, now) {
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({"code":"reauthentication_required"}))).into_response();
        }
        Json(serde_json::json!({"tenantId":session.account().tenant.to_string(),"principalId":session.account().principal.as_uuid().to_string(),"sessionId":session.view().id.to_string(),"authentication":{"acr":facts.acr(),"authTime":facts.auth_time()}})).into_response()
    }.await;
    private_response(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_identity_core::assurance::{Acr, Assurance};
    #[test]
    fn mfa_freshness_rejects_missing_future_and_exact_expiry() {
        let facts = |time, acr| Assurance::new(time, acr, vec![]).unwrap();
        assert!(fresh_mfa(&facts(Some(1000), Acr::Mfa), 1000));
        assert!(fresh_mfa(&facts(Some(1000), Acr::Mfa), 1299));
        assert!(!fresh_mfa(&facts(Some(1000), Acr::Mfa), 1300));
        assert!(!fresh_mfa(&facts(Some(1001), Acr::Mfa), 1000));
        assert!(!fresh_mfa(&facts(None, Acr::Unspecified), 1000));
        assert!(!fresh_mfa(&facts(Some(1000), Acr::Unspecified), 1000));
    }
}
