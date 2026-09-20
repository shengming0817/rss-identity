//! Public embedding contract. These tests cannot access password candidates or session issuance internals.
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
        .inspect_session(f.key.tenant, secret(&issued), deadline())
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
        .inspect_session(f.key.tenant, secret(&issued), deadline())
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
        .inspect_session(f.key.tenant, secret(&issued), deadline())
        .await?;
    f.store
        .change_own_password(actor, password(), password(), source(), deadline())
        .await?;
    assert_eq!(f.events().await?, before + 1);
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&issued), deadline())
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
        .authenticate_session(f.key.tenant, secret(&first), deadline())
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
            .list_accounts(f.actor().await?, None, 10, deadline())
            .await,
        Err(AuthorityError::RuleRejected(
            AccountRuleError::ReauthenticationRequired
        ))
    ));
    let renewed = f
        .store
        .reauthenticate_local(
            f.store
                .inspect_session(f.key.tenant, secret(&first), deadline())
                .await?,
            password(),
            source(),
            deadline(),
        )
        .await?;
    assert_ne!(first.view().id, renewed.view().id);
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&first), deadline())
            .await
            .is_err()
    );
    *f.policy.recent.write().unwrap() =
        ReauthenticationRequirement::Recent(Duration::from_secs(300));
    assert!(
        !f.store
            .list_accounts(f.actor().await?, None, 10, deadline())
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
        .inspect_session(f.key.tenant, secret(&issued), deadline())
        .await?;
    assert!(
        other
            .store
            .list_accounts(actor, None, 10, deadline())
            .await
            .is_err()
    );
    let wrong = Authority::connect_runtime(
        f.runtime.clone(),
        Arc::new(PasswordKdf::new()),
        config(InstanceId::generate()),
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
                tenant,
                login("admin"),
                password(),
                source(),
                None,
                deadline()
            )
            .await
            .unwrap_err(),
        AuthorityError::Rejected
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
        Arc::new(PasswordKdf::new()),
        f.config(),
        f.policy.clone(),
        deadline(),
    )
    .await?;
    drop(clone);
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&issued), deadline())
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
        f.store.active_tenants()?,
        SessionPolicy::new(60, 600)?,
        rss_transactional_messaging::policy::DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )?,
    )?;
    let changed = Authority::connect_runtime(
        runtime.clone(),
        Arc::new(PasswordKdf::new()),
        config,
        f.policy.clone(),
        deadline(),
    )
    .await?;
    let refreshed = changed
        .refresh_session(f.key.tenant, secret(&old), deadline())
        .await?;
    assert_eq!(
        refreshed.view().absolute_expires_at,
        old.view().absolute_expires_at
    );
    assert_eq!(refreshed.view().auth_time, old.view().auth_time);
    let new = changed
        .login_local(
            f.key.tenant,
            login("admin"),
            password(),
            source(),
            None,
            deadline(),
        )
        .await?;
    assert_eq!(new.view().absolute_expires_at - new.view().auth_time, 600);
    drop(changed);
    runtime.close().await;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn trusted_groups_expire_without_extending_identity_or_snapshot() -> anyhow::Result<()> {
    use federation_support::{RETURN, ScriptedOidc, begin, enabled, finish, issued};
    use rss_identity_core::federation::StateSigner;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let federation = Federation::new(
        GroupFactsMaxAge::new(2)?,
        f.store.clone(),
        ScriptedOidc::new(),
        StateSigner::new([7; 32], &f.instance.to_string())?,
        FederationConfig {
            callback: "https://identity.example.test/api/v2/oidc/callback".into(),
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
        .inspect_session(f.key.tenant, secret(&session), deadline())
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
        fn authorize(
            &self,
            context: &ManagementContext<'_>,
        ) -> Result<ReauthenticationRequirement, ManagementDenied> {
            let VerifiedGroups::Available(groups) =
                context.groups().map_err(|_| ManagementDenied)?
            else {
                return Err(ManagementDenied);
            };
            if groups.values().map_err(|_| ManagementDenied)? != ["staff"] {
                return Err(ManagementDenied);
            }
            Ok(ReauthenticationRequirement::None)
        }
    }
    let managed = Authority::connect_runtime(
        f.runtime.clone(),
        Arc::new(PasswordKdf::new()),
        f.config(),
        Arc::new(StaffPolicy),
        deadline(),
    )
    .await?;
    let fresh = managed
        .inspect_session(f.key.tenant, secret(&session), deadline())
        .await?;
    managed.list_accounts(fresh, None, 10, deadline()).await?;
    let original_expiry = groups.expires_at();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(groups.values(), Err(GroupAccessError::SnapshotExpired));
    assert!(matches!(actor.groups()?, VerifiedGroups::Expired));
    assert!(actor.assurance().is_ok());
    let before = f.events().await?;
    let expired = managed
        .inspect_session(f.key.tenant, secret(&session), deadline())
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

    let refreshed = f
        .store
        .refresh_session(f.key.tenant, secret(&session), deadline())
        .await?;
    let current = f
        .store
        .inspect_session(f.key.tenant, secret(&refreshed), deadline())
        .await?;
    assert!(matches!(current.groups()?, VerifiedGroups::Expired));
    assert_eq!(current.view().auth_time, session.view().auth_time);
    assert!(original_expiry < current.view().absolute_expires_at);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn construction_verifies_every_declared_tenant_fence() -> anyhow::Result<()> {
    use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
    use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgRuntime};
    let f = Fixture::new().await?;
    let runtime = Arc::new(
        PgRuntime::connect_producer(
            PgConfig::new_for_test_plaintext(
                "127.0.0.1",
                f.port,
                &f.database,
                "identity_runtime",
                PgPassword::new("fixture-only"),
            ),
            Timer,
            ExecutionBinding::new(
                StorageIdentity::new([1; 16], [2; 16])?,
                vec![(f.key.tenant, Epoch::new(1)?)],
            )?,
        )
        .await?,
    );
    assert!(matches!(
        Authority::connect_runtime(
            runtime.clone(),
            Arc::new(PasswordKdf::new()),
            f.config(),
            f.policy.clone(),
            deadline()
        )
        .await,
        Err(AuthorityError::Fenced)
    ));
    runtime.close().await;
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid",
    )
    .bind(B)
    .execute(&f.owner)
    .await?;
    assert!(matches!(
        Authority::connect_runtime(
            f.runtime.clone(),
            Arc::new(PasswordKdf::new()),
            f.config(),
            f.policy.clone(),
            deadline()
        )
        .await,
        Err(AuthorityError::Fenced)
    ));
    assert!(matches!(
        Authority::connect_maintenance(
            f.maintenance_runtime.clone(),
            Arc::new(PasswordKdf::new()),
            f.config(),
            deadline()
        )
        .await,
        Err(AuthorityError::Fenced)
    ));
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn group_deadline_includes_session_touch_latency() -> anyhow::Result<()> {
    use federation_support::{RETURN, ScriptedOidc, begin, enabled_department, finish, issued};
    use rss_identity_core::federation::StateSigner;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let federation = Federation::new(
        GroupFactsMaxAge::new(2)?,
        f.store.clone(),
        ScriptedOidc::new(),
        StateSigner::new([7; 32], &f.instance.to_string())?,
        FederationConfig {
            callback: "https://identity.example.test/api/v2/oidc/callback".into(),
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
        .authenticate_session(f.key.tenant, secret(&session), deadline())
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
        sqlx::query("UPDATE identity_authority.sessions SET auth_time=floor(extract(epoch FROM clock_timestamp()))::bigint + 2 - $3, idle_expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint + 2, absolute_expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint + 2, idle_timeout=$2, absolute_timeout=$3 WHERE session_id=$1")
            .bind(session.view().id.as_uuid()).bind(idle).bind(absolute).execute(&f.owner).await?;
        // The idle case keeps ample absolute lifetime, isolating the renewed idle cutoff.
        if idle == 2 {
            sqlx::query("UPDATE identity_authority.sessions SET auth_time=floor(extract(epoch FROM clock_timestamp()))::bigint, absolute_expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint + 120 WHERE session_id=$1")
                .bind(session.view().id.as_uuid()).execute(&f.owner).await?;
        }
        let before: (Vec<u8>, i64) = sqlx::query_as("SELECT token_hash,idle_expires_at FROM identity_authority.sessions WHERE session_id=$1")
            .bind(session.view().id.as_uuid()).fetch_one(&f.owner).await?;
        let events = f.events().await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE FUNCTION identity_authority.delay_refresh() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(3); RETURN NEW; END $$; CREATE TRIGGER delay_refresh BEFORE UPDATE OF {column} ON identity_authority.sessions FOR EACH ROW EXECUTE FUNCTION identity_authority.delay_refresh();")))
            .execute(&f.owner).await?;
        let result = f
            .store
            .refresh_session(f.key.tenant, secret(&session), deadline())
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
