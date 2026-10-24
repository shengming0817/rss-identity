//! Real PG + real WebAuthn cryptography using a software test authenticator, not hardware evidence.
mod support;
use rss_identity_core::step_up::StepUpContext;
use rss_identity_postgres::*;
use sqlx::Row;
use support::*;
use url::Url;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
const ORIGIN: &str = "https://identity.example.test";
async fn actor(f: &Fixture, s: &IssuedSession) -> anyhow::Result<AuthenticatedSession> {
    Ok(f.store
        .inspect_session(
            f.key.tenant,
            rss_identity_core::session::SessionSecret::parse(s.secret().expose().into())?,
            deadline(),
        )
        .await?)
}
async fn consume(
    f: &Fixture,
    s: &IssuedSession,
    context: &StepUpContext,
    grant: &str,
    commit: bool,
) -> anyhow::Result<bool> {
    let proof = actor(f, s).await?;
    let mut tx = f.owner.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(f.key.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL ROLE identity_runtime")
        .execute(&mut *tx)
        .await?;
    let accepted = consume_step_up_on(&mut tx, &proof, context, grant)
        .await
        .is_ok();
    if accepted && commit {
        tx.commit().await?
    } else {
        tx.rollback().await?
    }
    Ok(accepted)
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn webauthn_self_service_and_atomic_operation_proofs() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let s = f.login().await?;
    let w = WebauthnAuthority::new(
        f.store.clone(),
        "identity.example.test".into(),
        Url::parse(ORIGIN)?,
    )?;
    let mut key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let registration = w
        .begin_registration(
            actor(&f, &s).await?,
            "laptop".into(),
            false,
            RegistrationAuthorization::First,
            deadline(),
        )
        .await?;
    let response = key.do_registration(Url::parse(ORIGIN)?, registration.options)?;
    let credential = w
        .finish_registration(actor(&f, &s).await?, registration.id, response, deadline())
        .await?;
    assert_eq!(w.list(actor(&f, &s).await?, deadline()).await?.len(), 1);
    assert!(
        w.begin_registration(
            actor(&f, &s).await?,
            "bypass".into(),
            false,
            RegistrationAuthorization::First,
            deadline()
        )
        .await
        .is_err()
    );
    let context = StepUpContext::new("device.erase".into(), [9; 32]).unwrap();
    let a = w
        .begin_authentication(actor(&f, &s).await?, context.clone(), deadline())
        .await?;
    let response = key.do_authentication(Url::parse(ORIGIN)?, a.options)?;
    let copy = serde_json::from_value(serde_json::to_value(&response)?)?;
    let (left, right) = tokio::join!(
        w.finish_authentication(actor(&f, &s).await?, a.id, response, deadline()),
        w.finish_authentication(actor(&f, &s).await?, a.id, copy, deadline())
    );
    assert_ne!(left.is_ok(), right.is_ok());
    let grant = left.or(right)?;
    let wrong = StepUpContext::new("device.erase".into(), [8; 32]).unwrap();
    assert!(!consume(&f, &s, &wrong, grant.expose(), true).await?);
    assert!(
        consume(&f, &s, &context, grant.expose(), false).await?,
        "rollback preserves proof"
    );
    assert!(consume(&f, &s, &context, grant.expose(), true).await?);
    assert!(!consume(&f, &s, &context, grant.expose(), true).await?);
    let remove = webauthn_management_context(f.key, "remove", Some(credential.id))?;
    let a = w
        .begin_authentication(actor(&f, &s).await?, remove, deadline())
        .await?;
    let response = key.do_authentication(Url::parse(ORIGIN)?, a.options)?;
    let grant = w
        .finish_authentication(actor(&f, &s).await?, a.id, response, deadline())
        .await?;
    w.remove(
        actor(&f, &s).await?,
        credential.id,
        grant.expose().into(),
        deadline(),
    )
    .await?;
    assert!(w.list(actor(&f, &s).await?, deadline()).await?.is_empty());
    assert!(
        w.begin_registration(
            actor(&f, &s).await?,
            "reset bypass".into(),
            false,
            RegistrationAuthorization::First,
            deadline()
        )
        .await
        .is_err()
    );
    let row = sqlx::query("SELECT enrolled,epoch FROM identity_authority.webauthn_accounts")
        .fetch_one(&f.owner)
        .await?;
    assert!(row.try_get::<bool, _>("enrolled")?);
    assert!(row.try_get::<i64, _>("epoch")? > 1);
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn webauthn_cancellation_expiry_revocation_and_origin() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let s = f.login().await?;
    let w = WebauthnAuthority::new(
        f.store.clone(),
        "identity.example.test".into(),
        Url::parse(ORIGIN)?,
    )?;
    let mut key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let start = w
        .begin_registration(
            actor(&f, &s).await?,
            "key".into(),
            false,
            RegistrationAuthorization::First,
            deadline(),
        )
        .await?;
    let response = key.do_registration(Url::parse(ORIGIN)?, start.options)?;
    w.cancel(actor(&f, &s).await?, start.id, deadline()).await?;
    assert!(
        w.finish_registration(actor(&f, &s).await?, start.id, response, deadline())
            .await
            .is_err()
    );
    let start = w
        .begin_registration(
            actor(&f, &s).await?,
            "key".into(),
            false,
            RegistrationAuthorization::First,
            deadline(),
        )
        .await?;
    let response = key.do_registration(Url::parse(ORIGIN)?, start.options)?;
    let mut bad = serde_json::to_value(&response)?;
    bad["response"]["clientDataJSON"] = serde_json::json!("e30");
    assert!(
        w.finish_registration(
            actor(&f, &s).await?,
            start.id,
            serde_json::from_value(bad)?,
            deadline()
        )
        .await
        .is_err()
    );
    w.finish_registration(actor(&f, &s).await?, start.id, response, deadline())
        .await?;
    let context = StepUpContext::new("test".into(), [1; 32]).unwrap();
    let start = w
        .begin_authentication(actor(&f, &s).await?, context.clone(), deadline())
        .await?;
    let response = key.do_authentication(Url::parse(ORIGIN)?, start.options)?;
    sqlx::query("UPDATE identity_authority.webauthn_ceremonies SET created_at=created_at-121,expires_at=expires_at-121").execute(&f.owner).await?;
    assert!(
        w.finish_authentication(actor(&f, &s).await?, start.id, response, deadline())
            .await
            .is_err()
    );
    let start = w
        .begin_authentication(actor(&f, &s).await?, context.clone(), deadline())
        .await?;
    let response = key.do_authentication(Url::parse(ORIGIN)?, start.options)?;
    let grant = w
        .finish_authentication(actor(&f, &s).await?, start.id, response, deadline())
        .await?;
    let another = f.login().await?;
    assert!(!consume(&f, &another, &context, grant.expose(), true).await?);
    sqlx::query("UPDATE identity_authority.webauthn_credentials SET revoked=true,epoch=epoch+1")
        .execute(&f.owner)
        .await?;
    assert!(!consume(&f, &s, &context, grant.expose(), true).await?);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn webauthn_uv_and_registration_event_rollback() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let session = f.login().await?;
    let w = WebauthnAuthority::new(
        f.store.clone(),
        "identity.example.test".into(),
        Url::parse(ORIGIN)?,
    )?;
    let start = w
        .begin_registration(
            actor(&f, &session).await?,
            "no UV".into(),
            false,
            RegistrationAuthorization::First,
            deadline(),
        )
        .await?;
    let mut options = serde_json::to_value(start.options)?;
    options["publicKey"]["authenticatorSelection"]["userVerification"] =
        serde_json::json!("discouraged");
    let mut no_uv = WebauthnAuthenticator::new(SoftPasskey::new(false));
    let response = no_uv.do_registration(Url::parse(ORIGIN)?, serde_json::from_value(options)?)?;
    assert!(
        w.finish_registration(actor(&f, &session).await?, start.id, response, deadline())
            .await
            .is_err()
    );
    w.cancel(actor(&f, &session).await?, start.id, deadline())
        .await?;
    let start = w
        .begin_registration(
            actor(&f, &session).await?,
            "atomic".into(),
            false,
            RegistrationAuthorization::First,
            deadline(),
        )
        .await?;
    let mut key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let response = key.do_registration(Url::parse(ORIGIN)?, start.options)?;
    let copy = serde_json::from_value(serde_json::to_value(&response)?)?;
    sqlx::raw_sql("CREATE FUNCTION public.fail_webauthn_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE TRIGGER fail_webauthn_event BEFORE INSERT ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.fail_webauthn_event();").execute(&f.owner).await?;
    assert!(
        w.finish_registration(actor(&f, &session).await?, start.id, response, deadline())
            .await
            .is_err()
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity_authority.webauthn_credentials")
            .fetch_one(&f.owner)
            .await?;
    assert_eq!(count, 0);
    sqlx::raw_sql("DROP TRIGGER fail_webauthn_event ON rss_transactional_messaging.outbox; DROP FUNCTION public.fail_webauthn_event();").execute(&f.owner).await?;
    w.finish_registration(actor(&f, &session).await?, start.id, copy, deadline())
        .await?;
    f.close().await;
    Ok(())
}
