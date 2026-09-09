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
        (None, Some("2")),
        (Some(now - 1000), Some("2")),
        (Some(now + 1000), Some("2")),
        (Some(now), Some("1")),
    ] {
        *upstream.assurance.lock().unwrap() =
            Some(Assurance::from_verified_oidc(time, acr, vec![], true)?);
        let token = step_begin(&f, &s, &p, &old).await?;
        assert!(step_finish(&s, token, &old, "alice").await.is_err());
        f.store
            .inspect_session(f.key.tenant, secret(&old), deadline())
            .await?;
    }
    *upstream.assurance.lock().unwrap() = Some(Assurance::from_verified_oidc(
        Some(now),
        Some("2"),
        vec![],
        true,
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
    let upgraded = issued(step_finish(&s, token.clone(), &old, "alice").await?);
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
        .update_provider(actor(&f).await?, p.id, p.version, settings(), deadline())
        .await?;
    assert!(step_finish(&s, token, &upgraded, "alice").await.is_err());
    // Fault injection is after exchange, so it targets the session/event commit, not attempt claim.
    let token = step_begin(&f, &s, &p, &upgraded).await?;
    let runtime = f.runtime.clone();
    *upstream.hook.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
            runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
            Ok(())
        })
    }));
    assert!(matches!(
        step_finish(&s, token, &upgraded, "alice").await,
        Err(AuthorityError::CommitUnknown(_))
    ));
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
    let s = service(&f, ScriptedOidc::new());
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
            .is_ok()
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
        assert_eq!(facts["groups"], groups);
        assert_eq!(facts["mapping_version"], version);
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
    assert_eq!(persisted, (2, 2, 1, management_sessions + 1, 1));
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
    let s = service(&f, ScriptedOidc::new());
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
    let other = enabled(&f, &s).await?;
    let fed = issued(finish(&s, begin(&f, &s, &p).await?, "alice").await?);
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
    assert_eq!(guards, 1);
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
