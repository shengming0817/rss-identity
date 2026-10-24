//! Independent fixed-revision public consumer with a real PostgreSQL host.
mod live_session_consumer;
use rss_identity_core::{PrincipalId, account::AccountKey, step_up::StepUpContext};
use rss_identity_http_axum::HttpConfig;
use rss_identity_postgres::{Authority, WebauthnAuthority, webauthn_management_context};
use std::time::Duration;

// Compile the real public composition surface without relying on internal modules or test-support.
async fn compose(authority: Authority) -> Result<axum::Router, Box<dyn std::error::Error>> {
    let w = WebauthnAuthority::connect(
        authority,
        "identity.example.test".into(),
        url::Url::parse("https://identity.example.test")?,
        rss_transactional_messaging::policy::OperationDeadline::from_remaining(
            Duration::from_secs(10),
        ),
    )
    .await?;
    Ok(rss_identity_http_axum::webauthn_router(
        w,
        HttpConfig::new("https://identity.example.test", Duration::from_secs(10))?,
    )?)
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = AccountKey {
        tenant: rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111")?,
        principal: PrincipalId::generate(),
    };
    let register = webauthn_management_context(key, "register", None)?;
    let recover = webauthn_management_context(key, "recover", None)?;
    assert_ne!(register, recover);
    let copy: StepUpContext = serde_json::from_str(&serde_json::to_string(&register)?)?;
    assert_eq!(copy, register);
    assert!(StepUpContext::new("\ninvalid".into(), [0; 32]).is_err());
    assert!(
        rss_identity_oidc::enterprise::Es256EnterpriseSigner::new(
            "test".into(),
            b"not a private key"
        )
        .is_err()
    );
    let _factory = compose;
    live_session_consumer::run().await?;
    println!(
        "fixed-revision public consumer: context isolation, strict decoding and adapter composition passed"
    );
    Ok(())
}
