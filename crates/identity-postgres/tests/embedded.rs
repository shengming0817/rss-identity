//! Public embedding contract. These tests cannot access password candidates or session issuance internals.
mod account_directory;
mod department_lifecycle;
mod federation_support;
mod support;
use rss_identity_core::{
    InstanceId,
    account::{AccountKey, AccountRuleError, PasswordKdf},
    assurance::{Acr, Amr},
    facts::FactUnavailableReason,
    groups::GroupFactsMaxAge,
    session::{SessionPolicy, SessionSecret},
};
use rss_identity_postgres::*;
use std::{sync::Arc, time::Duration};
use support::*;
fn secret(session: &IssuedSession) -> SessionSecret {
    SessionSecret::parse(session.secret().expose().into()).unwrap()
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn own_password_change_requires_current_host_policy() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let issued = f.login().await?;
    f.policy.revoke(f.key);
    let before = f.events().await?;
    let actor = f
        .store
        .inspect_session(
            crate::support::binding(f.key.tenant),
            secret(&issued),
            deadline(),
        )
        .await?;
    assert_eq!(
        f.store
            .change_own_password(
                actor,
                password(),
                rss_identity_core::account::Password::new("replacement private password".into())?,
                source(),
                deadline()
            )
            .await
            .unwrap_err(),
        AuthorityError::RuleRejected(AccountRuleError::InsufficientPrivilege)
    );
    assert_eq!(f.events().await?, before);
    f.policy.allow(f.key);
    *f.policy.recent.write().unwrap() =
        ReauthenticationRequirement::RecentMfa(Duration::from_secs(300));
    let actor = f
        .store
        .inspect_session(
            crate::support::binding(f.key.tenant),
            secret(&issued),
            deadline(),
        )
        .await?;
    assert_eq!(
        f.store
            .change_own_password(actor, password(), password(), source(), deadline())
            .await
            .unwrap_err(),
        AuthorityError::RuleRejected(AccountRuleError::ReauthenticationRequired)
    );
    assert_eq!(f.events().await?, before);
    *f.policy.recent.write().unwrap() = ReauthenticationRequirement::None;
    let actor = f
        .store
        .inspect_session(
            crate::support::binding(f.key.tenant),
            secret(&issued),
            deadline(),
        )
        .await?;
    f.store
        .change_own_password(actor, password(), password(), source(), deadline())
        .await?;
    assert_eq!(f.events().await?, before + 1);
    assert!(
        f.store
            .inspect_session(
                crate::support::binding(f.key.tenant),
                secret(&issued),
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
async fn local_facade_reauthenticates_and_host_policy_is_current() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let first = f.login().await?;
    let actor = f
        .store
        .authenticate_session(
            crate::support::binding(f.key.tenant),
            secret(&first),
            deadline(),
        )
        .await?;
    assert_eq!(actor.instance(), f.instance);
    assert!(matches!(
        actor.groups()?,
        VerifiedGroups::Unavailable(FactUnavailableReason::LocalIdentity)
    ));
    assert_eq!(actor.assurance()?.amr(), [Amr::Pwd]);
    assert_eq!(actor.assurance()?.acr(), Acr::Unspecified);
    f.policy.revoke(f.key);
    let before = f.events().await?;
    assert_eq!(
        f.store
            .create_local_account(actor, login("forbidden"), password(), deadline())
            .await
            .unwrap_err(),
        AuthorityError::RuleRejected(AccountRuleError::InsufficientPrivilege)
    );
    assert_eq!(before, f.events().await?);
    f.policy.allow(f.key);
    *f.policy.recent.write().unwrap() =
        ReauthenticationRequirement::RecentMfa(Duration::from_secs(300));
    assert!(matches!(
        f.store
            .list_accounts(
                f.actor().await?,
                rss_identity_core::directory::AccountQuery::parse(None, None, None, None, 10)?,
                None,
                deadline()
            )
            .await,
        Err(AuthorityError::RuleRejected(
            AccountRuleError::ReauthenticationRequired
        ))
    ));
    let renewed = f
        .store
        .reauthenticate_local(
            f.store
                .inspect_session(
                    crate::support::binding(f.key.tenant),
                    secret(&first),
                    deadline(),
                )
                .await?,
            password(),
            source(),
            deadline(),
        )
        .await?;
    assert_ne!(first.view().id, renewed.view().id);
    assert!(
        f.store
            .inspect_session(
                crate::support::binding(f.key.tenant),
                secret(&first),
                deadline()
            )
            .await
            .is_err()
    );
    *f.policy.recent.write().unwrap() =
        ReauthenticationRequirement::Recent(Duration::from_secs(300));
    assert!(
        !f.store
            .list_accounts(
                f.actor().await?,
                rss_identity_core::directory::AccountQuery::parse(None, None, None, None, 10)?,
                None,
                deadline()
            )
            .await?
            .accounts
            .is_empty()
    );
    f.policy.protect(f.key);
    assert_eq!(
        f.store
            .set_account_enabled(f.actor().await?, f.key, false, deadline())
            .await
            .unwrap_err(),
        AuthorityError::RuleRejected(AccountRuleError::InsufficientPrivilege)
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn instances_tenants_and_borrowed_pool_are_separate() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let other = Fixture::new().await?;
    other.bootstrap().await?;
    let issued = f.login().await?;
    let actor = f
        .store
        .inspect_session(
            crate::support::binding(f.key.tenant),
            secret(&issued),
            deadline(),
        )
        .await?;
    assert!(
        other
            .store
            .list_accounts(
                actor,
                rss_identity_core::directory::AccountQuery::parse(None, None, None, None, 10)?,
                None,
                deadline()
            )
            .await
            .is_err()
    );
    let wrong = Authority::connect_runtime(
        f.runtime.clone(),
        Arc::new(
            PasswordKdf::new(
                std::num::NonZeroUsize::new(4).unwrap(),
                std::num::NonZeroU64::new(128 * 1024 * 1024).unwrap(),
            )
            .unwrap(),
        ),
        config(InstanceId::generate()),
        crate::support::binding(rss_request_context::TenantId::parse(crate::support::A).unwrap()),
        f.policy.clone(),
        deadline(),
    )
    .await;
    assert!(matches!(
        wrong,
        Err(AuthorityError::StorageIncompatible(
            StorageMismatch::DeploymentIdentity
        ))
    ));
    let tenant = rss_request_context::TenantId::parse("33333333-3333-4333-8333-333333333333")?;
    assert_eq!(
        f.store
            .login_local(
                crate::support::binding(tenant),
                login("admin"),
                password(),
                source(),
                None,
                deadline()
            )
            .await
            .unwrap_err(),
        AuthorityError::Fenced
    );
    assert!(
        f.store
            .set_account_enabled(
                f.actor().await?,
                AccountKey {
                    tenant: rss_request_context::TenantId::parse(B)?,
                    principal: f.key.principal
                },
                true,
                deadline()
            )
            .await
            .is_err()
    );
    let clone = Authority::connect_runtime(
        f.runtime.clone(),
        Arc::new(
            PasswordKdf::new(
                std::num::NonZeroUsize::new(4).unwrap(),
                std::num::NonZeroU64::new(128 * 1024 * 1024).unwrap(),
            )
            .unwrap(),
        ),
        f.config(),
        crate::support::binding(rss_request_context::TenantId::parse(crate::support::A).unwrap()),
        f.policy.clone(),
        deadline(),
    )
    .await?;
    drop(clone);
    assert!(
        f.store
            .inspect_session(
                crate::support::binding(f.key.tenant),
                secret(&issued),
                deadline()
            )
            .await
            .is_ok()
    );
    other.close().await;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn host_role_names_and_session_policy_survive_composition() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    sqlx::raw_sql("CREATE ROLE \"runtime odd\"\"name\" LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION").execute(&f.owner).await?;
    let mut owner = f.owner.acquire().await?;
    grant_profile(&mut owner, "runtime odd\"name", AuthorityProfile::Runtime).await?;
    drop(owner);
    let runtime = f.runtime_as("runtime odd\"name").await?;
    let old = f.login().await?;
    let config = AuthorityConfig::new(
        f.instance,
        SessionPolicy::new(60, 600)?,
        rss_audit_postgres::Integrity::Plain,
    )?;
    let changed = Authority::connect_runtime(
        runtime.clone(),
        Arc::new(
            PasswordKdf::new(
                std::num::NonZeroUsize::new(4).unwrap(),
                std::num::NonZeroU64::new(128 * 1024 * 1024).unwrap(),
            )
            .unwrap(),
        ),
        config,
        crate::support::binding(rss_request_context::TenantId::parse(crate::support::A).unwrap()),
        f.policy.clone(),
        deadline(),
    )
    .await?;
    let refreshed = changed
        .refresh_session(
            crate::support::binding(f.key.tenant),
            secret(&old),
            deadline(),
        )
        .await?;
    assert_eq!(
        refreshed.view().absolute_expires_at,
        old.view().absolute_expires_at
    );
    assert_eq!(refreshed.view().issued_at, old.view().issued_at);
    let new = changed
        .login_local(
            crate::support::binding(f.key.tenant),
            login("admin"),
            password(),
            source(),
            None,
            deadline(),
        )
        .await?;
    assert_eq!(new.view().absolute_expires_at - new.view().issued_at, 600);
    drop(changed);
    runtime.close().await;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn trusted_groups_expire_without_extending_identity_or_snapshot() -> anyhow::Result<()> {
    use federation_support::{RETURN, ScriptedOidc, begin, enabled, finish, issued};
    use rss_identity_postgres::StateSigner;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let federation = Federation::new(
        GroupFactsMaxAge::new(300)?,
        f.store.clone(),
        ScriptedOidc::new(),
        StateSigner::new([7; 32], &f.instance.to_string())?,
        FederationConfig {
            callback: "https://identity.example.test/api/v1/identity/oidc/callback".into(),
            credential_keys: credential_keys(),
            targets: std::collections::BTreeMap::from([("home".into(), RETURN.into())]),
        },
    )?;
    let provider = enabled(&f, &federation).await?;
    let session = issued(
        finish(
            &federation,
            begin(&f, &federation, &provider).await?,
            "alice",
        )
        .await?,
    );
    let actor = f
        .store
        .inspect_session(
            crate::support::binding(f.key.tenant),
            secret(&session),
            deadline(),
        )
        .await?;
    let VerifiedGroups::Available(groups) = actor.groups()? else {
        panic!("fresh groups unavailable")
    };
    assert_eq!(groups.values()?, ["staff"]);
    assert_eq!(
        groups.source().provider_id().to_string(),
        provider.id.to_string()
    );
    struct StaffPolicy;
    impl ManagementPolicy for StaffPolicy {
        fn authorize<'a>(
            &'a self,
            context: &'a ManagementContext<'a>,
            _connection: &'a mut sqlx::PgConnection,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<ReauthenticationRequirement, ManagementDenied>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                let VerifiedGroups::Available(groups) =
                    context.groups().map_err(|_| ManagementDenied)?
                else {
                    return Err(ManagementDenied);
                };
                if groups.values().map_err(|_| ManagementDenied)? != ["staff"] {
                    return Err(ManagementDenied);
                }
                Ok(ReauthenticationRequirement::None)
            })
        }
    }
    let clock = ControlledFactTime::default();
    let controlled = f.store.clone().with_fact_time(clock.clone());
    let managed = Authority::connect_runtime(
        f.runtime.clone(),
        Arc::new(
            PasswordKdf::new(
                std::num::NonZeroUsize::new(4).unwrap(),
                std::num::NonZeroU64::new(128 * 1024 * 1024).unwrap(),
            )
            .unwrap(),
        ),
        f.config(),
        crate::support::binding(rss_request_context::TenantId::parse(crate::support::A).unwrap()),
        Arc::new(StaffPolicy),
        deadline(),
    )
    .await?
    .with_fact_time(clock.clone());
    let fresh = managed
        .inspect_session(
            crate::support::binding(f.key.tenant),
            secret(&session),
            deadline(),
        )
        .await?;
    managed
        .list_accounts(
            fresh,
            rss_identity_core::directory::AccountQuery::parse(None, None, None, None, 10)?,
            None,
            deadline(),
        )
        .await?;
    let original_expiry = groups.expires_at();
    let original: serde_json::Value = sqlx::query_scalar(
        "SELECT auth_facts FROM identity_authority.sessions WHERE session_id=$1",
    )
    .bind(session.view().id.as_uuid())
    .fetch_one(&f.owner)
    .await?;
    clock.advance_to(original_expiry)?;
    clock.advance_to(original_expiry - 1)?; // A stale caller cannot rewind the floor.
    // A separate Authority remains on PG time, even over the same runtime/session.
    assert!(matches!(
        f.store
            .inspect_session(
                crate::support::binding(f.key.tenant),
                secret(&session),
                deadline()
            )
            .await?
            .groups()?,
        VerifiedGroups::Available(_)
    ));
    assert!(actor.assurance().is_ok());
    let before = f.events().await?;
    let expired = managed
        .inspect_session(
            crate::support::binding(f.key.tenant),
            secret(&session),
            deadline(),
        )
        .await?;
    assert_eq!(
        managed
            .create_local_account(
                expired,
                login("expired-group-admin"),
                password(),
                deadline()
            )
            .await
            .unwrap_err(),
        AuthorityError::RuleRejected(AccountRuleError::InsufficientPrivilege)
    );
    assert_eq!(f.events().await?, before);
    drop(managed);

    let refreshed = controlled
        .refresh_session(
            crate::support::binding(f.key.tenant),
            secret(&session),
            deadline(),
        )
        .await?;
    let current = controlled
        .inspect_session(
            crate::support::binding(f.key.tenant),
            secret(&refreshed),
            deadline(),
        )
        .await?;
    assert!(matches!(current.groups()?, VerifiedGroups::Expired));
    assert_eq!(current.view().issued_at, session.view().issued_at);
    assert!(original_expiry < current.view().absolute_expires_at);
    let persisted: serde_json::Value = sqlx::query_scalar(
        "SELECT auth_facts FROM identity_authority.sessions WHERE session_id=$1",
    )
    .bind(session.view().id.as_uuid())
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(original, persisted);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn dynamic_tenant_scope_reuses_authority_and_fences_proofs() -> anyhow::Result<()> {
    use rss_transactional_messaging::fence::{Epoch, ExecutionBinding};
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let tenant = rss_request_context::TenantId::parse("33333333-3333-4333-8333-333333333333")?;
    let scope = binding(tenant);
    let key = rss_identity_core::account::AccountKey {
        tenant,
        principal: f.key.principal,
    };
    assert!(matches!(
        f.maintenance
            .initialize(scope, key, login("admin"), password(), deadline())
            .await,
        Err(AuthorityError::Fenced)
    ));
    let guards: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.tenants WHERE tenant_id=$1::uuid",
    )
    .bind(tenant.to_string())
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(guards, 0);
    sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
        .bind(tenant.to_string())
        .execute(&f.owner)
        .await?;
    f.maintenance
        .initialize(scope, key, login("admin"), password(), deadline())
        .await?;
    let session = f
        .store
        .login_local(
            scope,
            login("admin"),
            password(),
            source(),
            None,
            deadline(),
        )
        .await?;
    let proof = f
        .store
        .inspect_session(scope, secret(&session), deadline())
        .await?;
    assert_eq!(proof.account(), key);
    assert!(
        f.store
            .inspect_session(binding(f.key.tenant), secret(&session), deadline())
            .await
            .is_err()
    );
    assert!(
        f.maintenance
            .recover_local_password(binding(f.key.tenant), key, password(), deadline())
            .await
            .is_err()
    );
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid",
    )
    .bind(tenant.to_string())
    .execute(&f.owner)
    .await?;
    let next = ExecutionBinding::new(scope.storage(), tenant, Epoch::new(2)?);
    let proof = std::sync::Arc::new(proof);
    let previous = proof.clone();
    let rejected = f
        .runtime
        .local_tx(next, deadline(), move |tx| {
            Box::pin(async move {
                tx.with_connection(move |c| {
                    Box::pin(
                        async move { Ok(recheck_authenticated_session_on(c, &previous).await) },
                    )
                })
                .await?
            })
        })
        .await
        .fold(
            |_| false,
            |_| false,
            |e| e.kind() == rss_transactional_messaging::error::MessagingErrorKind::Conflict,
            |_| false,
            |_| false,
            |_| false,
        );
    assert!(rejected);
    assert!(matches!(
        f.store
            .with_personnel_read(&proof, deadline(), |_| Box::pin(async { Ok(()) }))
            .await,
        Err(AuthorityError::Fenced)
    ));
    assert!(
        f.store
            .inspect_session(next, secret(&session), deadline())
            .await
            .is_ok()
    );
    assert!(f.login().await.is_ok());
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn group_deadline_includes_session_touch_latency() -> anyhow::Result<()> {
    use federation_support::{RETURN, ScriptedOidc, begin, enabled_department, finish, issued};
    use rss_identity_postgres::StateSigner;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let federation = Federation::new(
        GroupFactsMaxAge::new(2)?,
        f.store.clone(),
        ScriptedOidc::new(),
        StateSigner::new([7; 32], &f.instance.to_string())?,
        FederationConfig {
            callback: "https://identity.example.test/api/v1/identity/oidc/callback".into(),
            credential_keys: credential_keys(),
            targets: std::collections::BTreeMap::from([("home".into(), RETURN.into())]),
        },
    )?;
    let provider = enabled_department(&f, &federation, 2).await?;
    let session = issued(
        finish(
            &federation,
            begin(&f, &federation, &provider).await?,
            "alice",
        )
        .await?,
    );
    sqlx::raw_sql("CREATE FUNCTION identity_authority.delay_session_touch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(3); RETURN NEW; END $$; CREATE TRIGGER delay_session_touch BEFORE UPDATE OF idle_expires_at ON identity_authority.sessions FOR EACH ROW EXECUTE FUNCTION identity_authority.delay_session_touch();")
        .execute(&f.owner).await?;
    let actor = f
        .store
        .authenticate_session(
            crate::support::binding(f.key.tenant),
            secret(&session),
            deadline(),
        )
        .await?;
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.owner)
            .await?;
    assert!(
        matches!(actor.groups()?, VerifiedGroups::Expired),
        "group facts must expire before returning a delayed authentication result (DB now={database_now})"
    );
    assert!(matches!(
        actor.department_snapshot()?,
        VerifiedDepartmentSnapshot::Expired
    ));
    assert!(actor.assurance().is_ok());
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn refresh_rejects_expiry_during_writes_without_rotating_or_emitting() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    // Cover both blocking writes and both session limits. Only the selected write sleeps.
    for (column, idle, absolute) in [("idle_expires_at", 2, 120), ("token_hash", 120, 120)] {
        let session = f.login().await?;
        sqlx::query("UPDATE identity_authority.sessions SET issued_at=floor(extract(epoch FROM clock_timestamp()))::bigint + 2 - $3,local_authenticated_at=CASE WHEN authentication_source='local_password' THEN floor(extract(epoch FROM clock_timestamp()))::bigint + 2 - $3 ELSE local_authenticated_at END, idle_expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint + 2, absolute_expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint + 2, idle_timeout=$2, absolute_timeout=$3 WHERE session_id=$1")
            .bind(session.view().id.as_uuid()).bind(idle).bind(absolute).execute(&f.owner).await?;
        // The idle case keeps ample absolute lifetime, isolating the renewed idle cutoff.
        if idle == 2 {
            sqlx::query("UPDATE identity_authority.sessions SET issued_at=floor(extract(epoch FROM clock_timestamp()))::bigint,local_authenticated_at=CASE WHEN authentication_source='local_password' THEN floor(extract(epoch FROM clock_timestamp()))::bigint ELSE local_authenticated_at END, absolute_expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint + 120 WHERE session_id=$1")
                .bind(session.view().id.as_uuid()).execute(&f.owner).await?;
        }
        let before: (Vec<u8>, i64) = sqlx::query_as("SELECT token_hash,idle_expires_at FROM identity_authority.sessions WHERE session_id=$1")
            .bind(session.view().id.as_uuid()).fetch_one(&f.owner).await?;
        let events = f.events().await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE FUNCTION identity_authority.delay_refresh() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(3); RETURN NEW; END $$; CREATE TRIGGER delay_refresh BEFORE UPDATE OF {column} ON identity_authority.sessions FOR EACH ROW EXECUTE FUNCTION identity_authority.delay_refresh();")))
            .execute(&f.owner).await?;
        let result = f
            .store
            .refresh_session(
                crate::support::binding(f.key.tenant),
                secret(&session),
                deadline(),
            )
            .await;
        sqlx::raw_sql("DROP TRIGGER delay_refresh ON identity_authority.sessions; DROP FUNCTION identity_authority.delay_refresh();")
            .execute(&f.owner).await?;
        assert!(
            matches!(result, Err(AuthorityError::Rejected)),
            "refresh must reject expiry while updating {column}"
        );
        let after: (Vec<u8>, i64) = sqlx::query_as("SELECT token_hash,idle_expires_at FROM identity_authority.sessions WHERE session_id=$1")
            .bind(session.view().id.as_uuid()).fetch_one(&f.owner).await?;
        assert_eq!(
            before, after,
            "rejected refresh must roll back all session writes"
        );
        assert_eq!(f.events().await?, events);
    }
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_reads_only_require_password_presence() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let issued = f.login().await?;
    sqlx::raw_sql("REVOKE SELECT ON identity_authority.local_credentials FROM identity_runtime;
        GRANT SELECT(tenant_id,principal_id,login_key) ON identity_authority.local_credentials TO identity_runtime")
        .execute(&f.owner).await?;
    let actor = f
        .store
        .inspect_session(binding(f.key.tenant), secret(&issued), deadline())
        .await?;
    assert!(actor.identity().has_local_password);
    let page = f.store.list_sessions(actor, None, 2, deadline()).await?;
    assert_eq!(page.sessions[0].id, issued.view().id);
    assert!(f.login().await.is_err());
    f.close().await;
    Ok(())
}
