//! The test host chooses execution coordinates before entering the public router.
pub fn scoped<B>(mut request: axum::http::Request<B>) -> axum::http::Request<B> {
    let segments = request.uri().path().split('/').collect::<Vec<_>>();
    let tenant = segments
        .windows(2)
        .find(|p| p[0] == "tenants")
        .and_then(|p| rss_request_context::TenantId::parse(p[1]).ok());
    if let Some(tenant) = tenant {
        request
            .extensions_mut()
            .insert(crate::support::binding(tenant));
        request
            .extensions_mut()
            .insert(rss_identity_postgres::RpGeneration::new(1).unwrap());
    }
    request
}
