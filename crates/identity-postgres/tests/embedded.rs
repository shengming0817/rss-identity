//! Public embedding contract. These tests cannot access password candidates or session issuance internals.
mod federation_support;
mod support;
use rss_identity_core::{
    InstanceId,
    account::{AccountKey, AccountRuleError, PasswordKdf},
    assurance::{Acr, Amr},
    groups::{GroupFactsMaxAge, UnavailableReason},
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
        VerifiedGroups::Unavailable(UnavailableReason::LocalIdentity)
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
    assert_eq!(groups.values(), ["staff"]);
    assert_eq!(
        groups.source().provider_id.to_string(),
        provider.id.to_string()
    );
    let original_expiry = groups.expires_at();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(matches!(actor.groups()?, VerifiedGroups::Expired));
    assert!(actor.assurance().is_ok());
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
