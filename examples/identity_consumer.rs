//! Independent fixed-revision public consumer with a real PostgreSQL host.
mod live_session_consumer;
use rss_identity_core::{PrincipalId, account::AccountKey, step_up::StepUpContext};
use rss_identity_postgres::webauthn_management_context;
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
    live_session_consumer::run().await?;
    println!(
        "fixed-revision public consumer: context isolation, strict decoding and adapter composition passed"
    );
    Ok(())
}
