//! Reference-host execution coordinates. Tenant registration remains in the host-owned database.
use crate::{assembly, config::RuntimeConfig};
use axum::{
    extract::{FromRequestParts, Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use rss_identity_postgres::{Federation, RpGeneration};
use rss_request_context::TenantId;
use std::{collections::HashMap, sync::Arc};

#[derive(Clone)]
pub(crate) struct ExecutionState {
    pub config: Arc<RuntimeConfig>,
    pub federation: Option<Federation>,
}
pub(crate) async fn scope(
    State(state): State<ExecutionState>,
    request: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();
    let Ok(cutoff) = crate::config::cutoff(state.config.budgets.request_seconds) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let cutoff = parts
        .extensions
        .get::<rss_request_context::Deadline>()
        .map_or(cutoff, |host| cutoff.shortened_to(host.instant()));
    parts.extensions.insert(cutoff);
    let params = Path::<HashMap<String, String>>::from_request_parts(&mut parts, &()).await;
    if let Ok(Path(params)) = params
        && let Some(raw) = params.get("tenant")
    {
        let Ok(tenant) = TenantId::parse(raw) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        let Ok(binding) = state.config.storage.binding(tenant) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let Ok(generation) = RpGeneration::new(state.config.webauthn_generation) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        parts.extensions.insert(binding);
        parts.extensions.insert(generation);
        let path = parts.uri.path();
        if (path.contains("/oidc/")
            || path.ends_with("/login-options")
            || path.ends_with("/session/security"))
            && let Some(federation) = &state.federation
            && let Err(error) = federation
                .reconcile_assurance_profiles(binding, assembly::deadline(cutoff))
                .await
        {
            let mut response = StatusCode::SERVICE_UNAVAILABLE.into_response();
            response
                .extensions_mut()
                .insert(rss_identity_service_http::HttpFailure::Authority(error));
            return response;
        }
    }
    next.run(Request::from_parts(parts, body)).await
}
