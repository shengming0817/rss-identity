mod federation_support;
#[allow(dead_code)]
mod support;
use federation_support::*;
use rss_identity_core::federation::*;
use rss_identity_postgres::*;
use rss_transactional_messaging_postgres::PgTransactionFault;
use std::sync::atomic::Ordering;
use support::*;
use zeroize::Zeroizing;

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_security_is_subject_bound_and_revocable() -> anyhow::Result<()> {
    use rss_identity_core::assurance::{Acr, Amr};
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let s = service(&f, upstream.clone());
    let p = enabled(&f, &s).await?;
    let local = session(&f).await?;
    let snapshot = s
        .current_session_security(
            f.store
                .inspect_session(f.key.tenant, secret(&local), deadline())
                .await?,
            deadline(),
        )
        .await?;
    assert_eq!(snapshot.session_id, local.view().id.to_string());
    assert_eq!(snapshot.authentication.auth_time, local.view().auth_time);
    assert_eq!(snapshot.authentication.acr, Acr::Unspecified);
    assert_eq!(snapshot.authentication.amr, [Amr::Pwd]);
    assert!(snapshot.eligible_step_up_providers.is_empty());
    // An enabled trusted provider is not enough: no linked identity, no attempt.
    assert!(step_begin(&f, &s, &p, &local).await.is_err());
    let attempts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity_authority.oidc_transactions")
            .fetch_one(&f.owner)
            .await?;
    assert_eq!(attempts, 0);

    let linked = issued(finish(&s, begin(&f, &s, &p).await?, "alice").await?);
    let other = enabled(&f, &s).await?;
    let _other_subject = issued(finish(&s, begin(&f, &s, &other).await?, "alice").await?);
    let snapshot = s
        .current_session_security(
            f.store
                .inspect_session(f.key.tenant, secret(&linked), deadline())
                .await?,
            deadline(),
        )
        .await?;
    assert_eq!(snapshot.eligible_step_up_providers.len(), 1);
    assert_eq!(
        snapshot.eligible_step_up_providers[0]
            .provider_id
            .to_string(),
        p.id.to_string()
    );
    assert_eq!(snapshot.authentication.acr, Acr::Unspecified);
    // A capability can be withdrawn without changing the persisted interpretation identity.
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.owner)
            .await?;
    *upstream.assurance.lock().unwrap() = Some(rss_identity_core::assurance::Assurance::new(
        Some(now),
        Acr::Mfa,
        vec![],
    )?);
    let token = step_begin(&f, &s, &p, &linked).await?;
    upstream.step_up_disabled.store(true, Ordering::SeqCst);
    let before = upstream.calls.load(Ordering::SeqCst);
    assert!(step_finish(&s, token, &linked, "alice").await.is_err());
    assert_eq!(upstream.calls.load(Ordering::SeqCst), before);
    upstream.step_up_disabled.store(false, Ordering::SeqCst);
    let token = step_begin(&f, &s, &p, &linked).await?;
    let withdraw = upstream.clone();
    *upstream.hook.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
            withdraw.step_up_disabled.store(true, Ordering::SeqCst);
            Ok(())
        })
    }));
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_authority.sessions")
        .fetch_one(&f.owner)
        .await?;
    assert!(step_finish(&s, token, &linked, "alice").await.is_err());
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_authority.sessions")
        .fetch_one(&f.owner)
        .await?;
    assert_eq!(before, after);
    upstream.step_up_disabled.store(false, Ordering::SeqCst);
    *upstream.assurance.lock().unwrap() = None;
    // Different upstream subject for the same principal must not duplicate the provider.
    upstream.trusted_assurance.store(false, Ordering::SeqCst);
    assert!(
        s.current_session_security(
            f.store
                .inspect_session(f.key.tenant, secret(&linked), deadline())
                .await?,
            deadline()
        )
        .await
        .is_err(),
        "facts from an unsynchronized approval must not be displayed"
    );
    upstream.trusted_assurance.store(true, Ordering::SeqCst);
    sqlx::query("INSERT INTO identity_authority.external_identities(tenant_id,identity_id,principal_id,provider_id,issuer,subject) SELECT tenant_id,$1,principal_id,provider_id,issuer,'second-subject' FROM identity_authority.external_identities WHERE provider_id=$2::uuid")
        .bind(uuid::Uuid::new_v4()).bind(p.id.to_string()).execute(&f.owner).await?;
    let snapshot = s
        .current_session_security(
            f.store
                .inspect_session(f.key.tenant, secret(&linked), deadline())
                .await?,
            deadline(),
        )
        .await?;
    assert_eq!(snapshot.eligible_step_up_providers.len(), 1);
    let proof = f
        .store
        .inspect_session(f.key.tenant, secret(&linked), deadline())
        .await?;
    s.enable_provider(actor(&f).await?, p.id, p.version, false, deadline())
        .await?;
    assert!(s.current_session_security(proof, deadline()).await.is_err());
    assert!(step_begin(&f, &s, &p, &linked).await.is_err());
    upstream.trusted_assurance.store(false, Ordering::SeqCst);
    s.reconcile_assurance_profiles(f.key.tenant, deadline())
        .await?;
    let snapshot = s
        .current_session_security(
            f.store
                .inspect_session(f.key.tenant, secret(&local), deadline())
                .await?,
            deadline(),
        )
        .await?;
    assert!(snapshot.eligible_step_up_providers.is_empty());
    assert_eq!(snapshot.authentication.acr, Acr::Unspecified);
    f.close().await;
    Ok(())
}

async fn step_begin(
    f: &Fixture,
    s: &Federation,
    p: &ProviderView,
    session: &IssuedSession,
) -> anyhow::Result<String> {
    f.reset_attempts().await?;
    Ok(state(
        s.begin_step_up(
            LoginRequest {
                tenant: f.key.tenant,
                provider: p.id,
                browser: BROWSER.into(),
                client: "identity".into(),
                target: "home".into(),
                replacement: Some(
                    f.store
                        .inspect_session(f.key.tenant, secret(session), deadline())
                        .await?,
                ),
                source: source(),
            },
            deadline(),
        )
        .await?,
    ))
}

async fn step_finish(
    s: &Federation,
    token: String,
    session: &IssuedSession,
    subject: &str,
) -> Result<FederatedOutcome, AuthorityError> {
    s.complete(
        token,
        BROWSER.into(),
        Zeroizing::new(subject.into()),
        "https://idp.example.test".into(),
        Some(secret(session)),
        deadline(),
    )
    .await
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn federation_step_up_binding_and_settlement() -> anyhow::Result<()> {
    use rss_identity_core::assurance::Assurance;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let s = service(&f, upstream.clone());
    let p = enabled(&f, &s).await?;
    let old = issued(finish(&s, begin(&f, &s, &p).await?, "alice").await?);
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.owner)
            .await?;
    for (time, acr) in [
        (None, rss_identity_core::assurance::Acr::Unspecified),
        (Some(now - 1000), rss_identity_core::assurance::Acr::Mfa),
        (Some(now + 1000), rss_identity_core::assurance::Acr::Mfa),
        (Some(now), rss_identity_core::assurance::Acr::Unspecified),
    ] {
        *upstream.assurance.lock().unwrap() = Some(Assurance::new(time, acr, vec![])?);
        let token = step_begin(&f, &s, &p, &old).await?;
        assert!(step_finish(&s, token, &old, "alice").await.is_err());
        f.store
            .inspect_session(f.key.tenant, secret(&old), deadline())
            .await?;
    }
    *upstream.assurance.lock().unwrap() = Some(Assurance::new(
        Some(now),
        rss_identity_core::assurance::Acr::Mfa,
        vec![],
    )?);
    let token = step_begin(&f, &s, &p, &old).await?;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_authority.accounts")
        .fetch_one(&f.owner)
        .await?;
    assert!(
        step_finish(&s, token, &old, "unlinked-subject")
            .await
            .is_err()
    );
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_authority.accounts")
        .fetch_one(&f.owner)
        .await?;
    assert_eq!(before, after, "step-up must never JIT");
    let token = step_begin(&f, &s, &p, &old).await?;
    let before_groups = stored_facts(&f, &old).await?;
    *upstream.groups.lock().unwrap() = vec!["/step-up".into()];
    let upgraded = issued(step_finish(&s, token.clone(), &old, "alice").await?);
    let after_groups = stored_facts(&f, &upgraded).await?;
    assert_ne!(
        before_groups["groups"]["snapshot_id"],
        after_groups["groups"]["snapshot_id"]
    );
    assert_eq!(
        after_groups["groups"]["values"],
        serde_json::json!(["/step-up"])
    );
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&old), deadline())
            .await
            .is_err()
    );
    assert!(step_finish(&s, token, &upgraded, "alice").await.is_err());
    let facts: serde_json::Value = sqlx::query_scalar(
        "SELECT auth_facts FROM identity_authority.sessions WHERE session_id=$1::uuid",
    )
    .bind(upgraded.view().id.to_string())
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(facts["assurance"]["acr"], "mfa");
    assert_eq!(facts["assurance"]["auth_time"], now);
    // A config edit after beginning the flow invalidates the exact persisted binding.
    let token = step_begin(&f, &s, &p, &upgraded).await?;
    let p = s
        .update_provider(
            actor(&f).await?,
            p.id,
            p.version,
            settings(),
            rss_identity_core::federation::ProviderCredentials::new("fixture-secret".into(), None)
                .unwrap(),
            deadline(),
        )
        .await?;
    assert!(step_finish(&s, token, &upgraded, "alice").await.is_err());
    // Recreate a usable session; revocation between begin and callback rejects before exchange.
    let current = issued(finish(&s, begin(&f, &s, &p).await?, "alice").await?);
    let token = step_begin(&f, &s, &p, &current).await?;
    f.store
        .revoke_all_sessions(
            f.store
                .inspect_session(f.key.tenant, secret(&current), deadline())
                .await?,
            deadline(),
        )
        .await?;
    let calls = upstream.calls.load(Ordering::SeqCst);
    assert!(step_finish(&s, token, &current, "alice").await.is_err());
    assert_eq!(upstream.calls.load(Ordering::SeqCst), calls);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn federation_configuration_authorization_and_versions() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let s = service(&f, upstream.clone());
    let p = enabled(&f, &s).await?;
    let mut next = settings().input();
    next.jit = false;
    assert!(
        s.update_provider(
            actor(&f).await?,
            p.id,
            1,
            next.clone().try_into()?,
            rss_identity_core::federation::ProviderCredentials::new("fixture-secret".into(), None)
                .unwrap(),
            deadline()
        )
        .await
        .is_err()
    );
    let updated = s
        .update_provider(
            actor(&f).await?,
            p.id,
            p.version,
            next.try_into()?,
            rss_identity_core::federation::ProviderCredentials::new("fixture-secret".into(), None)
                .unwrap(),
            deadline(),
        )
        .await?;
    assert_eq!(updated.version, p.version + 1);
    s.test_provider(actor(&f).await?, p.id, deadline()).await?;
    upstream.fail.store(true, Ordering::SeqCst);
    let report = s.test_provider(actor(&f).await?, p.id, deadline()).await;
    assert!(matches!(
        report,
        Err(AuthorityError::Federation(FederationError::Provider(
            ProviderFailure {
                stage: ProviderStage::Jwks,
                reason: ProviderReason::Unavailable
            }
        )))
    ));
    upstream.fail.store(false, Ordering::SeqCst);
    *upstream.hook.lock().unwrap() = Some(Box::new(|| Box::pin(std::future::pending())));
    let timed = s
        .test_provider(
            actor(&f).await?,
            p.id,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                std::time::Duration::from_secs(2),
            ),
        )
        .await;
    assert!(matches!(
        timed,
        Err(AuthorityError::Federation(FederationError::Unavailable))
    ));
    let timed_events = events(&f).await?;
    assert_eq!(
        timed_events.last().unwrap()["action"],
        "provider_test_failed"
    );
    assert_eq!(
        timed_events.last().unwrap()["diagnostic"]["reason"],
        "timeout"
    );
    upstream.fail.store(true, Ordering::SeqCst);
    let _ = s.test_provider(actor(&f).await?, p.id, deadline()).await;
    upstream.fail.store(false, Ordering::SeqCst);
    let audits = events(&f).await?;
    let last = audits.last().unwrap();
    assert_eq!(last["action"], "provider_test_failed");
    assert_eq!(last["config_version"], updated.version);
    assert_eq!(
        last["diagnostic"],
        serde_json::json!({"stage":"jwks","reason":"unavailable"})
    );
    assert_eq!(
        s.list_providers(actor(&f).await?, deadline()).await?.len(),
        1
    );
    let mut invalid = settings().input();
    invalid.issuer = "https://different.test".into();
    assert!(
        s.update_provider(
            actor(&f).await?,
            p.id,
            updated.version,
            invalid.try_into()?,
            rss_identity_core::federation::ProviderCredentials::new("fixture-secret".into(), None)
                .unwrap(),
            deadline()
        )
        .await
        .is_err()
    );
    f.store
        .create_local_account(
            actor(&f).await?,
            login("member"),
            password(),
            rss_identity_postgres::LocalAccountRole::Member,
            deadline(),
        )
        .await?;
    let member = f
        .store
        .verify_password(
            f.key.tenant,
            login("member"),
            password(),
            source(),
            deadline(),
        )
        .await?;
    assert!(
        s.create_provider(
            support::session_actor(&f.store, member).await?,
            settings(),
            rss_identity_core::federation::ProviderCredentials::new("fixture-secret".into(), None)
                .unwrap(),
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
async fn federation_state_restart_expiry_and_replay() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let s = service(&f, upstream.clone());
    let p = enabled(&f, &s).await?;
    let token = begin(&f, &s, &p).await?;
    assert!(
        s.complete(
            token.clone(),
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into(),
            Zeroizing::new("alice".into()),
            "https://idp.example.test".into(),
            None,
            deadline()
        )
        .await
        .is_err()
    );
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    let restarted = service(&f, upstream.clone());
    let (a, b) = tokio::join!(
        finish(&s, token.clone(), "alice"),
        finish(&restarted, token.clone(), "alice")
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    assert!(finish(&s, token, "alice").await.is_err());
    let expired = begin(&f, &s, &p).await?;
    sqlx::query("UPDATE identity_authority.oidc_transactions SET created_at=created_at-600,expires_at=expires_at-600").execute(&f.owner).await?;
    assert!(finish(&s, expired, "alice").await.is_err());
    let mut bad = begin(&f, &s, &p).await?.into_bytes();
    bad[30] = if bad[30] == b'A' { b'B' } else { b'A' };
    assert!(finish(&s, String::from_utf8(bad)?, "alice").await.is_err());
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn federation_jit_isolated_subjects_and_membership() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let s = service(&f, upstream.clone());
    let p = enabled(&f, &s).await?;
    f.store
        .create_local_account(
            actor(&f).await?,
            login("same@example.test"),
            password(),
            rss_identity_postgres::LocalAccountRole::Member,
            deadline(),
        )
        .await?;
    let first = issued(finish(&s, begin(&f, &s, &p).await?, "alice").await?);
    let second = issued(finish(&s, begin(&f, &s, &p).await?, "bob").await?);
    let a = f
        .store
        .inspect_session(f.key.tenant, secret(&first), deadline())
        .await?;
    let b = f
        .store
        .inspect_session(f.key.tenant, secret(&second), deadline())
        .await?;
    assert_ne!(a.account(), b.account());
    let other = enabled(&f, &s).await?;
    let across_provider = issued(finish(&s, begin(&f, &s, &other).await?, "alice").await?);
    let distinct = f
        .store
        .inspect_session(f.key.tenant, secret(&across_provider), deadline())
        .await?;
    assert_ne!(a.account(), distinct.account());
    // Seed tenant B as deployment provisioning; the product has no self-service tenant creation.
    sqlx::query("INSERT INTO identity_authority.guard(tenant_id) VALUES($1::uuid)")
        .bind(B)
        .execute(&f.owner)
        .await?;
    sqlx::query("INSERT INTO identity_authority.accounts(tenant_id,principal_id,enabled,administrator,emergency,auth_epoch) SELECT $1::uuid,principal_id,enabled,administrator,emergency,auth_epoch FROM identity_authority.accounts WHERE tenant_id=$2::uuid AND principal_id=$3").bind(B).bind(A).bind(f.key.principal.as_uuid()).execute(&f.owner).await?;
    sqlx::query("INSERT INTO identity_authority.memberships(tenant_id,principal_id,active,epoch) SELECT $1::uuid,principal_id,active,epoch FROM identity_authority.memberships WHERE tenant_id=$2::uuid AND principal_id=$3").bind(B).bind(A).bind(f.key.principal.as_uuid()).execute(&f.owner).await?;
    sqlx::query("INSERT INTO identity_authority.local_credentials(tenant_id,principal_id,login_key,password_hash) SELECT $1::uuid,principal_id,login_key,password_hash FROM identity_authority.local_credentials WHERE tenant_id=$2::uuid AND principal_id=$3").bind(B).bind(A).bind(f.key.principal.as_uuid()).execute(&f.owner).await?;
    let tenant_b = rss_request_context::TenantId::parse(B)?;
    let admin_b = f
        .store
        .verify_password(tenant_b, login("admin"), password(), source(), deadline())
        .await?;
    let provider_b = s
        .create_provider(
            support::session_actor(&f.store, admin_b).await?,
            settings(),
            rss_identity_core::federation::ProviderCredentials::new("fixture-secret".into(), None)
                .unwrap(),
            deadline(),
        )
        .await?;
    let admin_b = f
        .store
        .verify_password(tenant_b, login("admin"), password(), source(), deadline())
        .await?;
    let provider_b = s
        .enable_provider(
            support::session_actor(&f.store, admin_b).await?,
            provider_b.id,
            provider_b.version,
            true,
            deadline(),
        )
        .await?;
    let pending_b = state(
        s.begin_login(
            LoginRequest {
                tenant: tenant_b,
                provider: provider_b.id,
                browser: BROWSER.into(),
                client: "identity".into(),
                target: "home".into(),
                replacement: None,
                source: source(),
            },
            deadline(),
        )
        .await?,
    );
    let session_b = issued(finish(&s, pending_b, "alice").await?);
    let account_b = f
        .store
        .inspect_session(tenant_b, secret(&session_b), deadline())
        .await?
        .account();
    assert_ne!(account_b.principal, a.account().principal);
    assert_eq!(account_b.tenant, tenant_b);
    let creds: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.local_credentials WHERE principal_id=$1",
    )
    .bind(a.account().principal.as_uuid())
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(creds, 0);
    let akey = a.account();
    support::apply_change(
        &f.store,
        actor(&f).await?,
        akey,
        rss_identity_core::account::AccountChange::Membership(false),
        deadline(),
    )
    .await?;
    assert!(finish(&s, begin(&f, &s, &p).await?, "alice").await.is_err());
    let mut off = p.settings.input();
    off.jit = false;
    let p = s
        .update_provider(
            actor(&f).await?,
            p.id,
            p.version,
            off.try_into()?,
            rss_identity_core::federation::ProviderCredentials::new("fixture-secret".into(), None)
                .unwrap(),
            deadline(),
        )
        .await?;
    assert!(
        finish(&s, begin(&f, &s, &p).await?, "charlie")
            .await
            .is_err()
    );
    assert!(finish(&s, begin(&f, &s, &p).await?, "bob").await.is_ok());
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn federation_config_races_and_provider_revocation() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let s = service(&f, upstream.clone());
    let p = enabled(&f, &s).await?;
    let local = session(&f).await?;
    let fed = issued(finish(&s, begin(&f, &s, &p).await?, "alice").await?);
    upstream.email_verified.store(false, Ordering::SeqCst);
    let unverified = issued(finish(&s, begin(&f, &s, &p).await?, "unverified").await?);
    let unverified_proof = f
        .store
        .inspect_session(f.key.tenant, secret(&unverified), deadline())
        .await?;
    let facts: serde_json::Value = sqlx::query_scalar(
        "SELECT auth_facts FROM identity_authority.sessions WHERE session_id=$1::uuid",
    )
    .bind(unverified_proof.view().id.to_string())
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(facts["email_verified"], false);
    assert_eq!(facts["email"], "same@example.test");
    let fed_proof = f
        .store
        .inspect_session(f.key.tenant, secret(&fed), deadline())
        .await?;
    assert_ne!(unverified_proof.account(), fed_proof.account());
    let pending = begin(&f, &s, &p).await?;
    let edited = s
        .update_provider(
            actor(&f).await?,
            p.id,
            p.version,
            p.settings.clone(),
            rss_identity_core::federation::ProviderCredentials::new("fixture-secret".into(), None)
                .unwrap(),
            deadline(),
        )
        .await?;
    assert!(matches!(
        finish(&s, pending, "alice").await,
        Err(AuthorityError::Federation(
            FederationError::StaleConfiguration
        ))
    ));
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&fed), deadline())
            .await
            .is_err()
    );
    upstream.groups.lock().unwrap().clear();
    let current_session = issued(finish(&s, begin(&f, &s, &edited).await?, "alice").await?);
    let current_proof = f
        .store
        .inspect_session(f.key.tenant, secret(&current_session), deadline())
        .await?;
    for (id, groups, version) in [
        (fed_proof.view().id, serde_json::json!(["staff"]), p.version),
        (
            current_proof.view().id,
            serde_json::json!([]),
            edited.version,
        ),
    ] {
        let facts: serde_json::Value = sqlx::query_scalar(
            "SELECT auth_facts FROM identity_authority.sessions WHERE session_id=$1::uuid",
        )
        .bind(id.to_string())
        .fetch_one(&f.owner)
        .await?;
        assert_eq!(facts["groups"]["values"], groups);
        assert_eq!(facts["provider_config_version"], version);
    }
    let pending = begin(&f, &s, &edited).await?;
    let next = s.clone();
    let admin_proof = actor(&f).await?;
    let id = edited.id;
    let version = edited.version;
    *upstream.hook.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
            next.enable_provider(admin_proof, id, version, false, deadline())
                .await
                .map_err(|_| FederationError::Unavailable)?;
            Ok(())
        })
    }));
    assert!(finish(&s, pending, "alice").await.is_err());
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&fed), deadline())
            .await
            .is_err()
    );
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&current_session), deadline())
            .await
            .is_err()
    );
    let reenabled = s
        .enable_provider(actor(&f).await?, p.id, version + 1, true, deadline())
        .await?;
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&fed), deadline())
            .await
            .is_err()
    );
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&local), deadline())
            .await
            .is_ok()
    );
    assert!(
        finish(&s, begin(&f, &s, &reenabled).await?, "alice")
            .await
            .is_ok()
    );
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn federation_atomic_events_and_unknown_commit() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let s = service(&f, upstream.clone());
    let p = enabled(&f, &s).await?;
    let management_sessions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity_authority.sessions")
            .fetch_one(&f.owner)
            .await?;
    let pending = begin(&f, &s, &p).await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        finish(&s, pending.clone(), "alice").await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    assert!(finish(&s, pending, "alice").await.is_err());
    let pending = begin(&f, &s, &p).await?;
    let runtime = f.runtime.clone();
    *upstream.hook.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
            runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
            Ok(())
        })
    }));
    assert!(matches!(
        finish(&s, pending.clone(), "alice").await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    assert!(finish(&s, pending, "alice").await.is_err());
    let persisted:(i64,i64,i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM identity_authority.accounts),(SELECT count(*) FROM identity_authority.memberships),(SELECT count(*) FROM identity_authority.external_identities),(SELECT count(*) FROM identity_authority.sessions),(SELECT count(*) FROM identity_authority.local_credentials)").fetch_one(&f.owner).await?;
    assert_eq!(persisted, (3, 3, 1, management_sessions + 1, 2));
    let committed = events(&f).await?;
    let pair = &committed[committed.len() - 2..];
    assert_eq!(pair[0]["action"], "jit_created");
    assert_eq!(pair[1]["action"], "created");
    assert_eq!(pair[0]["principal"], pair[1]["principal"]);
    assert_eq!(pair[0]["provider_id"], p.id.to_string());
    assert_eq!(pair[0]["config_version"], p.version);
    let before: f64 =
        sqlx::query_scalar("SELECT count(*)::float8 FROM identity_authority.accounts")
            .fetch_one(&f.owner)
            .await?;
    sqlx::raw_sql("CREATE FUNCTION public.fail_federation_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE TRIGGER fail_federation_event BEFORE INSERT ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.fail_federation_event();").execute(&f.owner).await?;
    assert!(finish(&s, begin(&f, &s, &p).await?, "bob").await.is_err());
    let after: f64 = sqlx::query_scalar("SELECT count(*)::float8 FROM identity_authority.accounts")
        .fetch_one(&f.owner)
        .await?;
    assert_eq!(before, after);

    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn federation_local_and_federated_linking() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let s = service(&f, upstream.clone());
    let p = enabled(&f, &s).await?;
    let local = session(&f).await?;
    let proof = f
        .store
        .inspect_session(f.key.tenant, secret(&local), deadline())
        .await?;
    let link = state(
        s.begin_link(
            rss_identity_postgres::LinkRequest {
                actor: proof,
                target_provider: p.id,
                password: Some(password()),
                browser: BROWSER.into(),
                client: "identity".into(),
                target: "home".into(),
                source: source(),
            },
            deadline(),
        )
        .await?,
    );
    let refreshed = f
        .store
        .refresh_session(f.key.tenant, secret(&local), deadline())
        .await?;
    let linked = issued(
        s.complete(
            link,
            BROWSER.into(),
            Zeroizing::new("local-link".into()),
            "https://idp.example.test".into(),
            Some(secret(&refreshed)),
            deadline(),
        )
        .await?,
    );
    assert_eq!(
        f.store
            .inspect_session(f.key.tenant, secret(&linked), deadline())
            .await?
            .account(),
        f.key
    );
    let local_facts: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT auth_facts FROM identity_authority.sessions WHERE session_id=$1::uuid",
    )
    .bind(linked.view().id.to_string())
    .fetch_one(&f.owner)
    .await?;
    assert!(
        local_facts.is_none(),
        "target groups must not become local origin"
    );
    let other = enabled(&f, &s).await?;
    let fed = issued(finish(&s, begin(&f, &s, &p).await?, "alice").await?);
    let original = stored_facts(&f, &fed).await?;
    let fed = f
        .store
        .refresh_session(f.key.tenant, secret(&fed), deadline())
        .await?;
    assert_eq!(
        stored_facts(&f, &fed).await?,
        original,
        "refresh preserves the entire snapshot"
    );
    *upstream.groups.lock().unwrap() = vec!["/source/new".into()];
    let proof = f
        .store
        .inspect_session(f.key.tenant, secret(&fed), deadline())
        .await?;
    let principal = proof.account();
    let reauth = state(
        s.begin_link(
            rss_identity_postgres::LinkRequest {
                actor: proof,
                target_provider: other.id,
                password: None,
                browser: BROWSER.into(),
                client: "identity".into(),
                target: "home".into(),
                source: source(),
            },
            deadline(),
        )
        .await?,
    );
    let second = match s
        .complete(
            reauth,
            BROWSER.into(),
            Zeroizing::new("alice".into()),
            "https://idp.example.test".into(),
            Some(secret(&fed)),
            deadline(),
        )
        .await?
    {
        FederatedOutcome::Redirect(v) => state(v),
        _ => panic!("expected target authentication"),
    };
    let source_facts: serde_json::Value = sqlx::query_scalar("SELECT source_facts FROM identity_authority.link_intents WHERE principal_id=$1 AND stage=1")
        .bind(principal.principal.as_uuid()).fetch_one(&f.owner).await?;
    assert_ne!(
        source_facts["groups"]["snapshot_id"],
        original["groups"]["snapshot_id"]
    );
    assert_eq!(
        source_facts["groups"]["values"],
        serde_json::json!(["/source/new"])
    );
    *upstream.groups.lock().unwrap() = vec!["/target/forbidden".into()];
    let linked = issued(
        s.complete(
            second,
            BROWSER.into(),
            Zeroizing::new("new-subject".into()),
            "https://idp.example.test".into(),
            Some(secret(&fed)),
            deadline(),
        )
        .await?,
    );
    assert_eq!(
        f.store
            .inspect_session(f.key.tenant, secret(&linked), deadline())
            .await?
            .account(),
        principal
    );
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&fed), deadline())
            .await
            .is_err()
    );
    assert_eq!(
        stored_facts(&f, &linked).await?,
        source_facts,
        "link must copy the source snapshot unchanged"
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn federation_link_conflict_logout_and_wrong_reauthentication() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let s = service(&f, ScriptedOidc::new());
    let p = enabled(&f, &s).await?;
    let fed = issued(finish(&s, begin(&f, &s, &p).await?, "alice").await?);
    let local = session(&f).await?;
    let proof = f
        .store
        .inspect_session(f.key.tenant, secret(&local), deadline())
        .await?;
    let pending = state(
        s.begin_link(
            LinkRequest {
                actor: proof,
                target_provider: p.id,
                password: Some(password()),
                browser: BROWSER.into(),
                client: "identity".into(),
                target: "home".into(),
                source: source(),
            },
            deadline(),
        )
        .await?,
    );
    let before = f.events().await?;
    assert!(matches!(
        s.complete(
            pending,
            BROWSER.into(),
            Zeroizing::new("alice".into()),
            "https://idp.example.test".into(),
            Some(secret(&local)),
            deadline()
        )
        .await,
        Err(AuthorityError::Federation(FederationError::Conflict))
    ));
    assert_eq!(f.events().await?, before);
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&local), deadline())
            .await
            .is_ok()
    );
    f.reset_attempts().await?;
    let proof = f
        .store
        .inspect_session(f.key.tenant, secret(&local), deadline())
        .await?;
    let pending = state(
        s.begin_link(
            LinkRequest {
                actor: proof,
                target_provider: p.id,
                password: Some(password()),
                browser: BROWSER.into(),
                client: "identity".into(),
                target: "home".into(),
                source: source(),
            },
            deadline(),
        )
        .await?,
    );
    f.store
        .revoke_current_session(
            f.store
                .inspect_session(f.key.tenant, secret(&local), deadline())
                .await?,
            deadline(),
        )
        .await?;
    assert!(
        s.complete(
            pending,
            BROWSER.into(),
            Zeroizing::new("unlinked".into()),
            "https://idp.example.test".into(),
            Some(secret(&local)),
            deadline()
        )
        .await
        .is_err()
    );
    let proof = f
        .store
        .inspect_session(f.key.tenant, secret(&fed), deadline())
        .await?;
    let pending = state(
        s.begin_link(
            LinkRequest {
                actor: proof,
                target_provider: p.id,
                password: None,
                browser: BROWSER.into(),
                client: "identity".into(),
                target: "home".into(),
                source: source(),
            },
            deadline(),
        )
        .await?,
    );
    assert!(matches!(
        s.complete(
            pending,
            BROWSER.into(),
            Zeroizing::new("another-user".into()),
            "https://idp.example.test".into(),
            Some(secret(&fed)),
            deadline()
        )
        .await,
        Err(AuthorityError::Federation(FederationError::Claims))
    ));
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity_authority.external_identities")
            .fetch_one(&f.owner)
            .await?;
    assert_eq!(rows, 1);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn federation_concurrent_jit_rls_and_schema_drift() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let s = service(&f, upstream.clone());
    let p = enabled(&f, &s).await?;
    let first = begin(&f, &s, &p).await?;
    let second = begin(&f, &s, &p).await?;
    let gate = std::sync::Arc::new(tokio::sync::Barrier::new(3));
    *upstream.gate.lock().unwrap() = Some(gate.clone());
    let s1 = s.clone();
    let s2 = s.clone();
    let a = tokio::spawn(async move { finish(&s1, first, "same-subject").await });
    let b = tokio::spawn(async move { finish(&s2, second, "same-subject").await });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while upstream.arrivals.load(Ordering::SeqCst) != 2 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?;
    let mut guard = f.owner.begin().await?;
    sqlx::query(
        "SELECT tenant_id FROM identity_authority.guard WHERE tenant_id=$1::uuid FOR UPDATE",
    )
    .bind(A)
    .execute(&mut *guard)
    .await?;
    gate.wait().await;
    tokio::time::timeout(std::time::Duration::from_secs(10),async{loop{
        let waiting:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename='identity_runtime' AND wait_event_type='Lock' AND query LIKE '%identity_authority.guard%'").fetch_one(&f.owner).await?;
        if waiting==2{break Ok::<_,sqlx::Error>(())}tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }}).await??;
    guard.commit().await?;
    let (a, b) = (a.await?, b.await?);
    let a = issued(a?);
    let b = issued(b?);
    assert_eq!(
        f.store
            .inspect_session(f.key.tenant, secret(&a), deadline())
            .await?
            .account(),
        f.store
            .inspect_session(f.key.tenant, secret(&b), deadline())
            .await?
            .account()
    );
    let count = f
        .runtime
        .local_tx(rss_request_context::TenantId::parse(B)?, deadline(), |tx| {
            Box::pin(async move {
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query_scalar::<_, i64>(
                            "SELECT count(*) FROM identity_authority.providers",
                        )
                        .fetch_one(c)
                        .await
                    })
                })
                .await
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    assert_eq!(count, 0);
    assert!(
        s.begin_login(
            LoginRequest {
                tenant: rss_request_context::TenantId::parse(B)?,
                provider: p.id,
                browser: BROWSER.into(),
                client: "identity".into(),
                target: "home".into(),
                replacement: None,
                source: source()
            },
            deadline()
        )
        .await
        .is_err()
    );
    let guards: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_authority.guard")
        .fetch_one(&f.owner)
        .await?;
    assert_eq!(guards, 2);
    sqlx::raw_sql("GRANT DELETE ON identity_authority.providers TO identity_account_runtime")
        .execute(&f.owner)
        .await?;
    assert!(matches!(
        f.probe(AuthorityProfile::Runtime).await,
        Err(AuthorityError::StorageIncompatible(
            StorageMismatch::Privileges
        ))
    ));
    sqlx::raw_sql("REVOKE DELETE ON identity_authority.providers FROM identity_account_runtime; ALTER TABLE identity_authority.oidc_transactions DROP CONSTRAINT oidc_transactions_state_hash_check").execute(&f.owner).await?;
    assert!(matches!(
        f.probe(AuthorityProfile::Runtime).await,
        Err(AuthorityError::StorageIncompatible(
            StorageMismatch::SchemaContract
        ))
    ));
    let committed = events(&f).await?;
    assert_eq!(
        committed
            .iter()
            .filter(|v| v["action"] == "jit_created")
            .count(),
        1
    );
    assert_eq!(
        committed
            .iter()
            .filter(|v| v["action"] == "logged_in")
            .count(),
        1
    );
    assert_eq!(
        committed
            .iter()
            .filter(|v| v["action"] == "created"
                && v["tenant"] == A
                && v["principal"] != f.key.principal.as_uuid().to_string())
            .count(),
        2
    );
    f.close().await;
    Ok(())
}

/// Decode the actual committed envelope and enforce its wire contract, not an ad hoc key union.
pub async fn events(f: &Fixture) -> anyhow::Result<Vec<serde_json::Value>> {
    use sha2::{Digest, Sha256};
    let rows: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT envelope FROM rss_transactional_messaging.outbox ORDER BY seq")
            .fetch_all(&f.owner)
            .await?;
    let mut values = Vec::new();
    for envelope in rows {
        let bytes: Vec<u8> = serde_json::from_value(envelope["payload"].clone())?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let (route, contract, version, schema) = match envelope["route"].as_str().unwrap() {
            "platform.changed" => (
                "platform.changed",
                "identity.platform.security",
                1,
                include_str!("../src/platform-security-event-v1.json"),
            ),
            "federation.changed" => (
                "federation.changed",
                "identity.federation.security",
                1,
                include_str!("../src/federation-security-event-v1.json"),
            ),
            "session.changed" => (
                "session.changed",
                "identity.session.security",
                1,
                include_str!("../src/session-security-event-v1.json"),
            ),
            "account.changed" => (
                "account.changed",
                "identity.account.security",
                2,
                include_str!("../src/security-event-v2.json"),
            ),
            _ => panic!("unexpected route"),
        };
        assert_eq!(envelope["route"], route);
        assert_eq!(envelope["contract"], contract);
        assert_eq!(envelope["version"], format!("v{version}"));
        assert_eq!(
            envelope["schema"],
            format!("sha256:{:x}", Sha256::digest(schema))
        );
        let schema: serde_json::Value = serde_json::from_str(schema)?;
        for required in schema["required"].as_array().unwrap() {
            assert!(value.get(required.as_str().unwrap()).is_some());
        }
        assert!(
            value
                .as_object()
                .unwrap()
                .keys()
                .all(|k| schema["properties"].get(k).is_some())
        );
        if let Some(actions) = schema["properties"]["action"]["enum"].as_array() {
            assert!(actions.contains(&value["action"]));
        }
        values.push(value);
    }
    Ok(values)
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn federation_concurrent_linking_keeps_one_owner() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let s = service(&f, upstream.clone());
    let p = enabled(&f, &s).await?;
    f.store
        .create_local_account(
            actor(&f).await?,
            login("member"),
            password(),
            rss_identity_postgres::LocalAccountRole::Member,
            deadline(),
        )
        .await?;
    let admin = session(&f).await?;
    let member = f
        .store
        .create_session(
            f.store
                .verify_password(
                    f.key.tenant,
                    login("member"),
                    password(),
                    source(),
                    deadline(),
                )
                .await?,
            None,
            deadline(),
        )
        .await?;
    let mut pending = Vec::new();
    for current in [&admin, &member] {
        let proof = f
            .store
            .inspect_session(f.key.tenant, secret(current), deadline())
            .await?;
        pending.push(state(
            s.begin_link(
                LinkRequest {
                    actor: proof,
                    target_provider: p.id,
                    password: Some(password()),
                    browser: BROWSER.into(),
                    client: "identity".into(),
                    target: "home".into(),
                    source: source(),
                },
                deadline(),
            )
            .await?,
        ));
    }
    let gate = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    *upstream.gate.lock().unwrap() = Some(gate);
    let (a, b) = tokio::join!(
        s.complete(
            pending.remove(0),
            BROWSER.into(),
            Zeroizing::new("shared".into()),
            "https://idp.example.test".into(),
            Some(secret(&admin)),
            deadline()
        ),
        s.complete(
            pending.remove(0),
            BROWSER.into(),
            Zeroizing::new("shared".into()),
            "https://idp.example.test".into(),
            Some(secret(&member)),
            deadline()
        )
    );
    let (winner, loser) = match (a, b) {
        (Ok(v), Err(AuthorityError::Federation(FederationError::Conflict))) => (v, &member),
        (Err(AuthorityError::Federation(FederationError::Conflict)), Ok(v)) => (v, &admin),
        _ => panic!("one association must win and one must conflict"),
    };
    let winner = issued(winner);
    let winner = f
        .store
        .inspect_session(f.key.tenant, secret(&winner), deadline())
        .await?
        .account();
    let loser = f
        .store
        .inspect_session(f.key.tenant, secret(loser), deadline())
        .await?
        .account();
    assert_ne!(winner, loser);
    let owner: uuid::Uuid = sqlx::query_scalar(
        "SELECT principal_id FROM identity_authority.external_identities WHERE subject='shared'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(owner, winner.principal.as_uuid());
    let committed = events(&f).await?;
    assert_eq!(
        committed.iter().filter(|v| v["action"] == "linked").count(),
        1
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn federation_step_up_unknown_commit_and_event_rollback() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let s = service(&f, upstream.clone());
    let p = enabled(&f, &s).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.owner)
            .await?;
    let upgraded = issued(finish(&s, begin(&f, &s, &p).await?, "alice").await?);
    *upstream.assurance.lock().unwrap() = Some(rss_identity_core::assurance::Assurance::new(
        Some(now),
        rss_identity_core::assurance::Acr::Mfa,
        vec![],
    )?);
    // Fault injection is after exchange, so it targets the session/event commit, not attempt claim.
    let token = step_begin(&f, &s, &p, &upgraded).await?;
    let state_hash = digest(&token);
    let sessions_before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity_authority.sessions")
            .fetch_one(&f.owner)
            .await?;
    let events_before = events(&f).await?.len();
    let runtime = f.runtime.clone();
    *upstream.hook.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
            runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
            Ok(())
        })
    }));
    assert!(matches!(
        step_finish(&s, token.clone(), &upgraded, "alice").await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    let sessions_after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity_authority.sessions")
            .fetch_one(&f.owner)
            .await?;
    assert_eq!(sessions_after, sessions_before + 1);
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&upgraded), deadline())
            .await
            .is_err()
    );
    let committed: (i64,serde_json::Value) = sqlx::query_as("SELECT count(*) OVER(), auth_facts FROM identity_authority.sessions WHERE tenant_id=$1::uuid AND principal_id=(SELECT principal_id FROM identity_authority.sessions WHERE tenant_id=$1::uuid AND session_id=$2::uuid) AND revoked_at IS NULL")
        .bind(A).bind(upgraded.view().id.to_string()).fetch_one(&f.owner).await?;
    assert_eq!(committed.0, 1);
    assert_eq!(committed.1["assurance"]["acr"], "mfa");
    assert_eq!(committed.1["assurance"]["auth_time"], now);
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.oidc_transactions WHERE state_hash=$1",
    )
    .bind(state_hash.as_slice())
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(remaining, 0);
    let committed_events = events(&f).await?;
    assert_eq!(committed_events.len(), events_before + 2);
    assert_eq!(committed_events[events_before]["action"], "stepped_up");
    assert_eq!(committed_events[events_before + 1]["action"], "created");
    assert!(step_finish(&s, token, &upgraded, "alice").await.is_err());
    let current = issued(finish(&s, begin(&f, &s, &p).await?, "alice").await?);
    let rollback_attempt = step_begin(&f, &s, &p, &current).await?;
    let rollback_hash = digest(&rollback_attempt);
    let before_sessions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity_authority.sessions")
            .fetch_one(&f.owner)
            .await?;
    let before_events = events(&f).await?.len();
    sqlx::raw_sql("CREATE FUNCTION public.fail_step_up_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE TRIGGER fail_step_up_event BEFORE INSERT ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.fail_step_up_event();").execute(&f.owner).await?;
    assert!(
        step_finish(&s, rollback_attempt.clone(), &current, "alice")
            .await
            .is_err()
    );
    sqlx::raw_sql("DROP TRIGGER fail_step_up_event ON rss_transactional_messaging.outbox; DROP FUNCTION public.fail_step_up_event();").execute(&f.owner).await?;
    let after_sessions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity_authority.sessions")
            .fetch_one(&f.owner)
            .await?;
    assert_eq!(before_sessions, after_sessions);
    assert_eq!(before_events, events(&f).await?.len());
    f.store
        .inspect_session(f.key.tenant, secret(&current), deadline())
        .await?;
    let claimed: bool = sqlx::query_scalar(
        "SELECT claimed FROM identity_authority.oidc_transactions WHERE state_hash=$1",
    )
    .bind(rollback_hash.as_slice())
    .fetch_one(&f.owner)
    .await?;
    assert!(
        claimed,
        "exchange claim remains consumed while session/event transaction rolls back"
    );
    assert!(
        step_finish(&s, rollback_attempt, &current, "alice")
            .await
            .is_err()
    );

    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn federation_assurance_change_revokes_attempts_and_sessions() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let s = service(&f, upstream.clone());
    let p = enabled(&f, &s).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.owner)
            .await?;
    *upstream.assurance.lock().unwrap() = Some(rss_identity_core::assurance::Assurance::new(
        Some(now),
        rss_identity_core::assurance::Acr::Mfa,
        vec![],
    )?);
    // A trusted assurance profile change must be settled before a restarted server opens admission.
    let prior = issued(finish(&s, begin(&f, &s, &p).await?, "alice").await?);
    let pending = step_begin(&f, &s, &p, &prior).await?;
    upstream.trusted_assurance.store(false, Ordering::SeqCst);
    s.reconcile_assurance_profiles(f.key.tenant, deadline())
        .await?;
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&prior), deadline())
            .await
            .is_err()
    );
    assert!(step_finish(&s, pending, &prior, "alice").await.is_err());
    upstream.trusted_assurance.store(true, Ordering::SeqCst);
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        s.reconcile_assurance_profiles(f.key.tenant, deadline())
            .await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    let settled_events = events(&f).await?.len();
    s.reconcile_assurance_profiles(f.key.tenant, deadline())
        .await?;
    assert_eq!(
        events(&f).await?.len(),
        settled_events,
        "settled assurance profile must not be applied twice"
    );
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&prior), deadline())
            .await
            .is_err(),
        "restored assurance profile must not resurrect an old session"
    );
    // More providers than the transaction event bound must settle in bounded batches.
    sqlx::query("INSERT INTO identity_authority.providers(tenant_id,provider_id,config_version,revocation_epoch,enabled,settings,assurance_profile,credential_version) SELECT $1::uuid,gen_random_uuid(),1,1,false,$2,decode(repeat('00',32),'hex'),1 FROM generate_series(1,9)")
        .bind(A).bind(serde_json::to_value(settings())?).execute(&f.owner).await?;
    let before_batch = events(&f).await?.len();
    s.reconcile_assurance_profiles(f.key.tenant, deadline())
        .await?;
    assert_eq!(events(&f).await?.len(), before_batch + 9);
    let unprofiled: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.providers WHERE assurance_profile=decode(repeat('00',32),'hex')",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(unprofiled, 0);
    s.reconcile_assurance_profiles(f.key.tenant, deadline())
        .await?;
    assert_eq!(events(&f).await?.len(), before_batch + 9);
    f.close().await;
    Ok(())
}

async fn stored_facts(f: &Fixture, session: &IssuedSession) -> anyhow::Result<serde_json::Value> {
    Ok(sqlx::query_scalar(
        "SELECT auth_facts FROM identity_authority.sessions WHERE session_id=$1::uuid",
    )
    .bind(session.view().id.to_string())
    .fetch_one(&f.owner)
    .await?)
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn federation_group_snapshot_storage_bounds() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let s = service(&f, upstream.clone());
    let p = enabled(&f, &s).await?;
    *upstream.groups.lock().unwrap() = (0..100)
        .map(|i| format!("{i:03}{}", "x".repeat(253)))
        .collect();
    let sized = issued(finish(&s, begin(&f, &s, &p).await?, "size-valid").await?);
    assert_eq!(
        stored_facts(&f, &sized).await?["groups"]["values"]
            .as_array()
            .unwrap()
            .len(),
        100
    );
    let sample = stored_facts(&f, &sized).await?;
    let bytes: i32 = sqlx::query_scalar("SELECT octet_length($1::jsonb::text)")
        .bind(sample)
        .fetch_one(&f.owner)
        .await?;
    let extra = 32768 - bytes;
    let mut boundary: Vec<String> = (0..100)
        .map(|i| format!("{i:03}{}", "x".repeat(253)))
        .collect();
    for n in 0..extra as usize {
        boundary[n / 253].replace_range(3 + n % 253..4 + n % 253, "\"");
    }
    *upstream.groups.lock().unwrap() = boundary.clone();
    let exact = issued(finish(&s, begin(&f, &s, &p).await?, "size-exact").await?);
    let bytes: i32 = sqlx::query_scalar("SELECT octet_length(auth_facts::text) FROM identity_authority.sessions WHERE session_id=$1::uuid").bind(exact.view().id.to_string()).fetch_one(&f.owner).await?;
    assert_eq!(bytes, 32768);
    let n = extra as usize;
    boundary[n / 253].replace_range(3 + n % 253..4 + n % 253, "\"");
    *upstream.groups.lock().unwrap() = boundary;
    assert!(
        finish(&s, begin(&f, &s, &p).await?, "size-overflow")
            .await
            .is_err()
    );
    let overflow: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.external_identities WHERE subject='size-overflow'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(
        overflow, 0,
        "oversized facts roll back the complete JIT write"
    );
    *upstream.groups.lock().unwrap() = vec!["staff".into()];
    // An external identity from a different principal cannot be attached as this session's source.
    let mismatch = sqlx::query("UPDATE identity_authority.sessions SET external_identity_id=(SELECT external_identity_id FROM identity_authority.sessions WHERE session_id=$1::uuid) WHERE session_id=$2::uuid")
        .bind(sized.view().id.to_string()).bind(exact.view().id.to_string()).execute(&f.owner).await.unwrap_err();
    assert_eq!(
        mismatch
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref(),
        Some("23503"),
        "the source/principal foreign key rejects mismatched authority"
    );
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&exact), deadline())
            .await
            .is_ok()
    );
    f.close().await;
    Ok(())
}
