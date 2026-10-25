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
    let w = WebauthnAuthority::connect(
        f.store.clone(),
        "identity.example.test".into(),
        Url::parse(ORIGIN)?,
        deadline(),
    )
    .await?;
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
    let w = WebauthnAuthority::connect(
        f.store.clone(),
        "identity.example.test".into(),
        Url::parse(ORIGIN)?,
        deadline(),
    )
    .await?;
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
    let w = WebauthnAuthority::connect(
        f.store.clone(),
        "identity.example.test".into(),
        Url::parse(ORIGIN)?,
        deadline(),
    )
    .await?;
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
    sqlx::raw_sql("CREATE FUNCTION public.fail_webauthn_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE TRIGGER fail_webauthn_event BEFORE INSERT ON rss_audit.records FOR EACH ROW EXECUTE FUNCTION public.fail_webauthn_event();").execute(&f.owner).await?;
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
    sqlx::raw_sql("DROP TRIGGER fail_webauthn_event ON rss_audit.records; DROP FUNCTION public.fail_webauthn_event();").execute(&f.owner).await?;
    w.finish_registration(actor(&f, &session).await?, start.id, copy, deadline())
        .await?;
    f.close().await;
    Ok(())
}

async fn management_grant(
    f: &Fixture,
    w: &WebauthnAuthority,
    s: &IssuedSession,
    key: &mut WebauthnAuthenticator<SoftPasskey>,
    operation: &str,
) -> anyhow::Result<StepUpGrant> {
    let context = webauthn_management_context(f.key, operation, None)?;
    let start = w
        .begin_authentication(actor(f, s).await?, context, deadline())
        .await?;
    let response = key.do_authentication(Url::parse(ORIGIN)?, start.options)?;
    Ok(
        w.finish_authentication(actor(f, s).await?, start.id, response, deadline())
            .await?,
    )
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn webauthn_add_and_recovery_revoke_prior_authorization_atomically() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let s = f.login().await?;
    let w = WebauthnAuthority::connect(
        f.store.clone(),
        "identity.example.test".into(),
        Url::parse(ORIGIN)?,
        deadline(),
    )
    .await?;
    let mut first = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let start = Box::pin(w.begin_registration(
        actor(&f, &s).await?,
        "first".into(),
        false,
        RegistrationAuthorization::First,
        deadline(),
    ))
    .await?;
    let response = first.do_registration(Url::parse(ORIGIN)?, start.options)?;
    Box::pin(w.finish_registration(actor(&f, &s).await?, start.id, response, deadline())).await?;
    let grant = management_grant(&f, &w, &s, &mut first, "register").await?;
    assert!(
        Box::pin(w.begin_registration(
            actor(&f, &s).await?,
            "wrong purpose".into(),
            true,
            RegistrationAuthorization::StepUp(grant.expose().into()),
            deadline()
        ))
        .await
        .is_err()
    );
    let start = Box::pin(w.begin_registration(
        actor(&f, &s).await?,
        "second".into(),
        false,
        RegistrationAuthorization::StepUp(grant.expose().into()),
        deadline(),
    ))
    .await?;
    assert!(
        Box::pin(w.begin_registration(
            actor(&f, &s).await?,
            "replay".into(),
            false,
            RegistrationAuthorization::StepUp(grant.expose().into()),
            deadline()
        ))
        .await
        .is_err()
    );
    let mut second = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let response = second.do_registration(Url::parse(ORIGIN)?, start.options)?;
    Box::pin(w.finish_registration(actor(&f, &s).await?, start.id, response, deadline())).await?;
    let old = management_grant(&f, &w, &s, &mut first, "register").await?;
    let pending = Box::pin(w.begin_authentication(
        actor(&f, &s).await?,
        StepUpContext::new("pending".into(), [4; 32]).unwrap(),
        deadline(),
    ))
    .await?;
    let pending_response = first.do_authentication(Url::parse(ORIGIN)?, pending.options)?;
    let recovery = management_grant(&f, &w, &s, &mut second, "recover").await?;
    let start = Box::pin(w.begin_registration(
        actor(&f, &s).await?,
        "recovered".into(),
        true,
        RegistrationAuthorization::StepUp(recovery.expose().into()),
        deadline(),
    ))
    .await?;
    let mut new_key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let response = new_key.do_registration(Url::parse(ORIGIN)?, start.options)?;
    let copy = serde_json::from_value(serde_json::to_value(&response)?)?;
    sqlx::raw_sql("CREATE FUNCTION public.fail_recovery_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE TRIGGER fail_recovery_event BEFORE INSERT ON rss_audit.records FOR EACH ROW EXECUTE FUNCTION public.fail_recovery_event();").execute(&f.owner).await?;
    assert!(
        Box::pin(w.finish_registration(actor(&f, &s).await?, start.id, response, deadline()))
            .await
            .is_err()
    );
    assert_eq!(w.list(actor(&f, &s).await?, deadline()).await?.len(), 2);
    sqlx::raw_sql("DROP TRIGGER fail_recovery_event ON rss_audit.records;DROP FUNCTION public.fail_recovery_event();").execute(&f.owner).await?;
    Box::pin(w.finish_registration(actor(&f, &s).await?, start.id, copy, deadline())).await?;
    assert_eq!(w.list(actor(&f, &s).await?, deadline()).await?.len(), 1);
    assert!(
        !consume(
            &f,
            &s,
            &webauthn_management_context(f.key, "register", None)?,
            old.expose(),
            true
        )
        .await?
    );
    assert!(
        Box::pin(w.finish_authentication(
            actor(&f, &s).await?,
            pending.id,
            pending_response,
            deadline()
        ))
        .await
        .is_err()
    );
    assert!(
        Box::pin(w.begin_registration(
            actor(&f, &s).await?,
            "first bypass".into(),
            false,
            RegistrationAuthorization::First,
            deadline()
        ))
        .await
        .is_err()
    );
    // The host's recovery policy is checked at begin and final settlement.
    f.policy.revoke(f.key);
    assert!(
        Box::pin(w.begin_registration(
            actor(&f, &s).await?,
            "host recovery".into(),
            true,
            RegistrationAuthorization::HostRecovery,
            deadline()
        ))
        .await
        .is_err()
    );
    f.policy.allow(f.key);
    let start = Box::pin(w.begin_registration(
        actor(&f, &s).await?,
        "host recovery".into(),
        true,
        RegistrationAuthorization::HostRecovery,
        deadline(),
    ))
    .await?;
    let mut host_key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let response = host_key.do_registration(Url::parse(ORIGIN)?, start.options)?;
    f.policy.revoke(f.key);
    let copy = serde_json::from_value(serde_json::to_value(&response)?)?;
    assert!(
        Box::pin(w.finish_registration(actor(&f, &s).await?, start.id, response, deadline()))
            .await
            .is_err()
    );
    f.policy.allow(f.key);
    Box::pin(w.finish_registration(actor(&f, &s).await?, start.id, copy, deadline())).await?;
    assert_eq!(w.list(actor(&f, &s).await?, deadline()).await?.len(), 1);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn webauthn_rp_generation_fences_old_processes_and_proofs() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let session = f.login().await?;
    let w = WebauthnAuthority::connect(
        f.store.clone(),
        "example.test".into(),
        Url::parse(ORIGIN)?,
        deadline(),
    )
    .await?;
    let mut key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let start = w
        .begin_registration(
            actor(&f, &session).await?,
            "old origin".into(),
            false,
            RegistrationAuthorization::First,
            deadline(),
        )
        .await?;
    let response = key.do_registration(Url::parse(ORIGIN)?, start.options)?;
    w.finish_registration(actor(&f, &session).await?, start.id, response, deadline())
        .await?;
    let grant = management_grant(&f, &w, &session, &mut key, "register").await?;
    let newer = Url::parse("https://new.example.test")?;
    assert!(
        WebauthnAuthority::connect(
            f.store.clone(),
            "example.test".into(),
            newer.clone(),
            deadline()
        )
        .await
        .is_err(),
        "runtime cannot silently change active configuration"
    );
    let mut tx = f.owner.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(A)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL ROLE identity_runtime")
        .execute(&mut *tx)
        .await?;
    assert!(
        activate_webauthn_rp_on(&mut tx, f.instance, f.key.tenant, "example.test", &newer, 1)
            .await
            .is_err()
    );
    tx.rollback().await?;
    let mut tx = f.owner.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(A)
        .execute(&mut *tx)
        .await?;
    assert_eq!(
        activate_webauthn_rp_on(&mut tx, f.instance, f.key.tenant, "example.test", &newer, 1)
            .await?,
        2
    );
    tx.commit().await?;
    assert!(
        !consume(
            &f,
            &session,
            &webauthn_management_context(f.key, "register", None)?,
            grant.expose(),
            true
        )
        .await?
    );
    assert!(
        w.begin_authentication(
            actor(&f, &session).await?,
            StepUpContext::new("old.process".into(), [2; 32]).unwrap(),
            deadline()
        )
        .await
        .is_err()
    );
    // Uninitialized admitted tenants also have a pinned RP row; change their deployment settings.
    for tenant in [SYSTEM, B] {
        let mut tx = f.owner.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO identity_authority.guard(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING").bind(tenant).execute(&mut *tx).await?;
        activate_webauthn_rp_on(
            &mut tx,
            f.instance,
            rss_request_context::TenantId::parse(tenant)?,
            "example.test",
            &newer,
            1,
        )
        .await?;
        tx.commit().await?;
    }
    let current =
        WebauthnAuthority::connect(f.store.clone(), "example.test".into(), newer, deadline())
            .await?;
    assert!(
        current
            .begin_registration(
                actor(&f, &session).await?,
                "old proof".into(),
                false,
                RegistrationAuthorization::StepUp(grant.expose().into()),
                deadline()
            )
            .await
            .is_err()
    );
    assert!(
        current
            .begin_registration(
                actor(&f, &session).await?,
                "first bypass".into(),
                false,
                RegistrationAuthorization::First,
                deadline()
            )
            .await
            .is_err()
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn expired_other_subject_backlog_does_not_lock_out_self_service() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let session = f.login().await?;
    let w = WebauthnAuthority::connect(
        f.store.clone(),
        "identity.example.test".into(),
        Url::parse(ORIGIN)?,
        deadline(),
    )
    .await?;
    let other = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO identity_authority.accounts(tenant_id,principal_id) VALUES($1::uuid,$2)",
    )
    .bind(A)
    .bind(other)
    .execute(&f.owner)
    .await?;
    let initial = w
        .begin_registration(
            actor(&f, &session).await?,
            "initial".into(),
            false,
            RegistrationAuthorization::First,
            deadline(),
        )
        .await?;
    for (principal, count, age) in [(other, 129, 600), (f.key.principal.as_uuid(), 8, 300)] {
        sqlx::query("INSERT INTO identity_authority.webauthn_ceremonies(tenant_id,id,principal_id,session_id,auth_epoch,membership_epoch,credential_epoch,rp_config,state,created_at,expires_at) SELECT tenant_id,gen_random_uuid(),$2,session_id,auth_epoch,membership_epoch,credential_epoch,rp_config,state,created_at-$4,expires_at-$4 FROM identity_authority.webauthn_ceremonies CROSS JOIN generate_series(1,$3) WHERE id=$1").bind(initial.id).bind(principal).bind(count).bind(age).execute(&f.owner).await?;
    }
    let retry = w
        .begin_registration(
            actor(&f, &session).await?,
            "available".into(),
            false,
            RegistrationAuthorization::First,
            deadline(),
        )
        .await?;
    w.cancel(actor(&f, &session).await?, initial.id, deadline())
        .await?;
    let mut key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let response = key.do_registration(Url::parse(ORIGIN)?, retry.options)?;
    w.finish_registration(actor(&f, &session).await?, retry.id, response, deadline())
        .await?;
    let grant = management_grant(&f, &w, &session, &mut key, "register").await?;
    for (principal, count, age) in [(other, 129, 900), (f.key.principal.as_uuid(), 32, 600)] {
        sqlx::query("INSERT INTO identity_authority.step_up_grants(tenant_id,token_hash,principal_id,session_id,auth_epoch,membership_epoch,context,source,authenticated_at,expires_at) SELECT tenant_id,decode(md5(random()::text)||md5(random()::text),'hex'),$2,session_id,auth_epoch,membership_epoch,context,source,authenticated_at-$4,expires_at-$4 FROM identity_authority.step_up_grants CROSS JOIN generate_series(1,$3) WHERE token_hash=$1").bind(rss_identity_core::federation::digest(grant.expose()).as_slice()).bind(principal).bind(count).bind(age).execute(&f.owner).await?;
    }
    management_grant(&f, &w, &session, &mut key, "register").await?;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn same_configuration_rotation_invalidates_pending_first_enrollment() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let session = f.login().await?;
    let origin = Url::parse(ORIGIN)?;
    let w = WebauthnAuthority::connect(
        f.store.clone(),
        "example.test".into(),
        origin.clone(),
        deadline(),
    )
    .await?;
    let start = w
        .begin_registration(
            actor(&f, &session).await?,
            "pending".into(),
            false,
            RegistrationAuthorization::First,
            deadline(),
        )
        .await?;
    let mut key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let response = key.do_registration(origin.clone(), start.options)?;
    let mut tx = f.owner.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(A)
        .execute(&mut *tx)
        .await?;
    assert_eq!(
        activate_webauthn_rp_on(
            &mut tx,
            f.instance,
            f.key.tenant,
            "example.test",
            &origin,
            1
        )
        .await?,
        2
    );
    tx.commit().await?;
    let current =
        WebauthnAuthority::connect(f.store.clone(), "example.test".into(), origin, deadline())
            .await?;
    assert!(
        current
            .finish_registration(actor(&f, &session).await?, start.id, response, deadline())
            .await
            .is_err()
    );
    assert!(
        current
            .list(actor(&f, &session).await?, deadline())
            .await?
            .is_empty()
    );
    current
        .begin_registration(
            actor(&f, &session).await?,
            "fresh".into(),
            false,
            RegistrationAuthorization::First,
            deadline(),
        )
        .await?;
    f.close().await;
    Ok(())
}
