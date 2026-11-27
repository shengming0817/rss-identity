use crate::*;
use rss_identity_postgres::{Federation, WebauthnAuthority};

/// Product endpoints that require explicit host assembly and admission.
#[derive(Default)]
pub struct ServiceEndpoints {
    pub federation: Option<Federation>,
    pub webauthn: Option<WebauthnAuthority>,
    pub programmatic_bearer: bool,
}

pub fn routes(
    authority: Authority,
    config: HttpConfig,
    endpoints: ServiceEndpoints,
) -> Result<Router, AuthorityError> {
    let mut routes = local_routes(authority.clone(), config.clone())?;
    if let Some(federation) = endpoints.federation {
        routes = routes.merge(oidc::federated_router(federation, config.clone())?);
    }
    if let Some(webauthn) = endpoints.webauthn {
        routes = routes.merge(webauthn::webauthn_router(webauthn, config.clone())?);
    }
    if endpoints.programmatic_bearer {
        routes = routes.merge(bearer::bearer_router(authority, config)?);
    }
    Ok(routes)
}
/// Mount behind TLS at the configured origin. Host middleware must insert [`ClientAddress`]
/// from its trusted transport, and an explicit `ExecutionBinding` extension, before entering these routes. Axum `ConnectInfo<SocketAddr>`
/// alone is insufficient. For a direct connection use the accepted peer's IP; behind a
/// proxy validate the peer before interpreting any forwarded header. See the embedding guide.
fn local_routes(authority: Authority, config: HttpConfig) -> Result<Router, AuthorityError> {
    authority.require_runtime()?;
    let management = accounts::management_router(authority.clone(), config.clone())?;
    let profiles = profiles::router(authority.clone(), config.clone())?;
    let state = AppState { authority, config };
    Ok(mount(
        Router::new()
            .route("/tenants/{tenant}/login", post(session::login))
            .route(
                "/tenants/{tenant}/session/reauthenticate",
                post(session::reauthenticate),
            )
            .route("/tenants/{tenant}/session", get(session::current))
            .route("/tenants/{tenant}/session/refresh", post(session::refresh))
            .route("/tenants/{tenant}/session/logout", post(session::logout))
            .route(
                "/tenants/{tenant}/sessions/logout-all",
                post(session::logout_all),
            )
            .route("/tenants/{tenant}/sessions", get(session::list))
            .layer(axum::extract::DefaultBodyLimit::max(4096))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                boundary::request_boundary,
            ))
            .with_state(state)
            .merge(management)
            .merge(profiles),
    ))
}

pub(crate) fn mount(routes: Router) -> Router {
    Router::new().nest("/api/v1/identity", routes)
}
