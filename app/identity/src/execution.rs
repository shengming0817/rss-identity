//! Reference-host execution coordinates. Tenant registration remains in the host-owned database.
use crate::config::RuntimeConfig;
use axum::{
    extract::{FromRequestParts, Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use rss_identity_postgres::RpGeneration;
use rss_request_context::TenantId;
use std::{collections::HashMap, sync::Arc};

pub(crate) async fn scope(
    State(config): State<Arc<RuntimeConfig>>,
    request: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();
    let params = Path::<HashMap<String, String>>::from_request_parts(&mut parts, &()).await;
    if let Ok(Path(params)) = params
        && let Some(raw) = params.get("tenant")
    {
        let Ok(tenant) = TenantId::parse(raw) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        let Ok(binding) = config.storage.binding(tenant) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let Ok(generation) = RpGeneration::new(config.webauthn_generation) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        parts.extensions.insert(binding);
        parts.extensions.insert(generation);
    }
    next.run(Request::from_parts(parts, body)).await
}
