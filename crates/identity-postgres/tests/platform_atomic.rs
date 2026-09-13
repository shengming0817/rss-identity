mod federation_support;
#[allow(dead_code)]
mod support;
use rss_identity_core::{PrincipalId, account::AccountKey, platform::PlatformError};
use rss_identity_postgres::*;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgTransactionFault;
use support::*;
fn input(tenant: TenantId, id: uuid::Uuid) -> NewTenantAdministrator {
    NewTenantAdministrator {
        operation_id: id,
        tenant,
        principal: PrincipalId::generate(),
        login: login("new-admin"),
        password: password(),
    }
}

#[tokio::test]
#[ignore = "requires real PostgreSQL"]
async fn platform_initialization_roles_and_existing_accounts() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    assert_key_material_and_registrar_privileges(&f).await?;
    let platform = f.platform_actor().await?;
    assert!(platform.identity().platform_administrator);
    assert!(!platform.identity().administrator);
    assert_eq!(
        platform.view().absolute_expires_at - platform.view().auth_time,
        14400
    );
    assert!(
        f.maintenance
            .initialize(f.system_key, login("other"), password(), deadline())
            .await
            .is_err()
    );
    let denied = f
        .store
        .provision_business_tenant(
            f.actor().await?,
            "Forbidden".into(),
            input(TenantId::parse(B)?, uuid::Uuid::new_v4()),
            deadline(),
        )
        .await;
    assert!(matches!(
        denied,
        Err(AuthorityError::Platform(PlatformError::Forbidden))
    ));
    assert_eq!(
        f.store
            .set_platform_role(
                f.platform_actor().await?,
                f.system_key.principal,
                false,
                deadline()
            )
            .await
            .unwrap_err(),
        AuthorityError::Platform(PlatformError::LastAdministrator)
    );
    let second = f
        .store
        .create_local_account(
            f.platform_actor().await?,
            login("second"),
            password(),
            LocalAccountRole::Member,
            deadline(),
        )
        .await?;
    f.store
        .set_platform_role(
            f.platform_actor().await?,
            second.key().principal,
            true,
            deadline(),
        )
        .await?;
    let roles = f
        .store
        .list_accounts(f.platform_actor().await?, None, 100, deadline())
        .await?;
    assert_eq!(
        roles
            .accounts
            .iter()
            .filter(|a| a.platform_administrator)
            .count(),
        2
    );
    assert!(roles.accounts.iter().all(|a| !a.account.administrator));
    let original_epoch=sqlx::query_scalar::<_,i64>("SELECT auth_epoch FROM identity_authority.accounts WHERE tenant_id=$1::uuid AND principal_id=$2").bind(A).bind(f.key.principal.as_uuid()).fetch_one(&f.owner).await?;
    let request = input(f.key.tenant, uuid::Uuid::new_v4());
    let new_principal = request.principal;
    f.store
        .add_business_tenant_administrator(f.platform_actor().await?, request, deadline())
        .await?;
    let created = f
        .store
        .verify_password(
            f.key.tenant,
            login("new-admin"),
            password(),
            source(),
            deadline(),
        )
        .await?;
    assert_eq!(created.account().principal, new_principal);
    let again = input(f.key.tenant, uuid::Uuid::new_v4());
    assert!(matches!(
        f.store
            .add_business_tenant_administrator(f.platform_actor().await?, again, deadline())
            .await,
        Err(AuthorityError::Platform(PlatformError::Conflict))
    ));
    let epoch=sqlx::query_scalar::<_,i64>("SELECT auth_epoch FROM identity_authority.accounts WHERE tenant_id=$1::uuid AND principal_id=$2").bind(A).bind(f.key.principal.as_uuid()).fetch_one(&f.owner).await?;
    assert_eq!(epoch, original_epoch);
    let before = f.platform_actor().await?;
    f.store
        .set_platform_role(
            f.platform_actor().await?,
            f.system_key.principal,
            false,
            deadline(),
        )
        .await?;
    assert!(
        f.store
            .add_business_tenant_administrator(
                before,
                input(f.key.tenant, uuid::Uuid::new_v4()),
                deadline()
            )
            .await
            .is_err()
    );
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PostgreSQL"]
async fn platform_provisioning_concurrency_and_settlement() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let tenant = TenantId::parse("cccccccc-cccc-4ccc-8ccc-cccccccccccc")?;
    let operation = uuid::Uuid::new_v4();
    let first = f.platform_actor().await?;
    let second = f.platform_actor().await?;
    let (a, b) = tokio::join!(
        f.store
            .provision_business_tenant(first, "C".into(), input(tenant, operation), deadline()),
        f.store
            .provision_business_tenant(second, "C".into(), input(tenant, operation), deadline())
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let receipt = f
        .store
        .platform_operation(f.platform_actor().await?, operation, deadline())
        .await?;
    assert_eq!(receipt.tenant_id, tenant.to_string());
    let another = TenantId::parse("dddddddd-dddd-4ddd-8ddd-dddddddddddd")?;
    sqlx::raw_sql("CREATE FUNCTION public.reject_platform_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic private'; END $$; CREATE TRIGGER reject_platform_event BEFORE INSERT ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.reject_platform_event()").execute(&f.owner).await?;
    let actor = f.platform_actor().await?;
    let result = f
        .store
        .provision_business_tenant(
            actor,
            "D".into(),
            input(another, uuid::Uuid::new_v4()),
            deadline(),
        )
        .await;
    assert!(matches!(result, Err(AuthorityError::RolledBack(_))));
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.tenant_registry WHERE business_tenant=$1::uuid",
    )
    .bind(another.to_string())
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(n, 0);
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.tenant_epoch WHERE tenant_id=$1::uuid",
    )
    .bind(another.to_string())
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(n, 0);
    for table in ["accounts", "memberships", "local_credentials"] {
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM identity_authority.{table} WHERE tenant_id=$1::uuid"
        )))
        .bind(another.to_string())
        .fetch_one(&f.owner)
        .await?;
        assert_eq!(count, 0, "failed event must roll back every target record");
    }
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM identity_authority.platform_operations WHERE business_tenant=$1::uuid").bind(another.to_string()).fetch_one(&f.owner).await?;
    assert_eq!(count, 0);
    sqlx::raw_sql("DROP TRIGGER reject_platform_event ON rss_transactional_messaging.outbox; DROP FUNCTION public.reject_platform_event()").execute(&f.owner).await?;
    let actor = f.platform_actor().await?;
    let operation = uuid::Uuid::new_v4();
    f.store
        .runtime()?
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        f.store
            .provision_business_tenant(actor, "D".into(), input(another, operation), deadline())
            .await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    assert_eq!(
        f.store
            .platform_operation(f.platform_actor().await?, operation, deadline())
            .await?
            .tenant_id,
        another.to_string()
    );
    let first = f.platform_actor().await?;
    let second = f.platform_actor().await?;
    let (a, b) = tokio::join!(
        f.store.add_business_tenant_administrator(
            first,
            input(f.key.tenant, uuid::Uuid::new_v4()),
            deadline()
        ),
        f.store.add_business_tenant_administrator(
            second,
            input(f.key.tenant, uuid::Uuid::new_v4()),
            deadline()
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let rejected = if let Err(e) = a { e } else { b.unwrap_err() };
    assert!(matches!(
        rejected,
        AuthorityError::Platform(PlatformError::Conflict)
    ));
    assert_add_only_settlement(&f).await?;
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PostgreSQL"]
async fn platform_dynamic_admission_and_restart() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let target = TenantId::parse("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")?;
    let request = input(target, uuid::Uuid::new_v4());
    let key = AccountKey {
        tenant: target,
        principal: request.principal,
    };
    f.store
        .provision_business_tenant(
            f.platform_actor().await?,
            "Dynamic".into(),
            request,
            deadline(),
        )
        .await?;
    assert!(!f.store.tenant_active(target));
    f.store.activate_registered_tenants(deadline()).await?;
    assert!(f.store.tenant_active(target));
    let candidate = f
        .store
        .verify_password(target, login("new-admin"), password(), source(), deadline())
        .await?;
    assert_eq!(candidate.account(), key);
    let session = f.store.create_session(candidate, None, deadline()).await?;
    assert!(session.identity().administrator);
    assert!(!session.identity().platform_administrator);
    let old = f.store.runtime()?;
    f.store.activate_registered_tenants(deadline()).await?;
    assert!(std::sync::Arc::ptr_eq(&old, &f.store.runtime()?));
    // A real request pins the old runtime while a new complete binding is installed.
    let mut blocker = f.owner.begin().await?;
    sqlx::query(
        "SELECT tenant_id FROM identity_authority.guard WHERE tenant_id=$1::uuid FOR UPDATE",
    )
    .bind(target.to_string())
    .execute(&mut *blocker)
    .await?;
    let store = f.store.clone();
    let secret =
        rss_identity_core::session::SessionSecret::parse(session.secret().expose().to_string())?;
    let inflight =
        tokio::spawn(async move { store.inspect_session(target, secret, deadline()).await });
    let cutoff = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let waiting:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename='identity_runtime' AND wait_event_type='Lock' AND query LIKE '%identity_authority.guard%'").fetch_one(&f.owner).await?;
        if waiting > 0 {
            break;
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < cutoff,
            "request never acquired the old runtime"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let second = TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    f.store
        .provision_business_tenant(
            f.platform_actor().await?,
            "Second".into(),
            input(second, uuid::Uuid::new_v4()),
            deadline(),
        )
        .await?;
    f.store.activate_registered_tenants(deadline()).await?;
    assert!(f.store.tenant_active(target) && f.store.tenant_active(second));
    let third = TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    f.store
        .provision_business_tenant(
            f.platform_actor().await?,
            "Third".into(),
            input(third, uuid::Uuid::new_v4()),
            deadline(),
        )
        .await?;
    assert_eq!(
        f.store
            .activate_registered_tenants(deadline())
            .await
            .unwrap_err(),
        AuthorityError::Busy
    );
    assert!(!f.store.tenant_active(third));
    blocker.commit().await?;
    assert_eq!(inflight.await??.account(), key);
    f.store.activate_registered_tenants(deadline()).await?;
    for t in [f.key.tenant, target, second, third] {
        assert!(f.store.tenant_active(t));
    }

    // Reconstruct from only the external system-domain binding, never a static business list.
    use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
    use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgRuntime};
    let config = PgConfig::new_for_test_plaintext(
        "127.0.0.1",
        f.port,
        &f.database,
        "identity_runtime",
        PgPassword::new("fixture-only"),
    );
    let storage = StorageIdentity::new([1; 16], [2; 16])?;
    let runtime = std::sync::Arc::new(
        PgRuntime::connect_producer(
            config.clone(),
            Timer,
            ExecutionBinding::new(storage, vec![(f.system_key.tenant, Epoch::new(1)?)])?,
        )
        .await?,
    );
    let kdf = std::sync::Arc::new(rss_identity_core::account::PasswordKdf::new());
    let restarted = Authority::connect_runtime(
        runtime,
        kdf.clone(),
        f.deployment.clone(),
        rss_transactional_messaging::policy::DeliveryBudget::new(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        )?,
        f.system_key.tenant,
        support::runtime_configuration(f.port, &f.database),
        deadline(),
    )
    .await?;
    restarted.activate_registered_tenants(deadline()).await?;
    for t in [f.key.tenant, target, second, third] {
        assert!(restarted.tenant_active(t));
    }
    assert_eq!(
        restarted
            .verify_password(target, login("new-admin"), password(), source(), deadline())
            .await?
            .account(),
        key
    );
    restarted.close().await;
    kdf.close();
    kdf.wait_closed().await;
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid",
    )
    .bind(target.to_string())
    .execute(&f.owner)
    .await?;
    assert!(matches!(
        f.store
            .verify_password(target, login("new-admin"), password(), source(), deadline())
            .await,
        Err(AuthorityError::Fenced)
    ));
    f.close().await;
    Ok(())
}

async fn assert_key_material_and_registrar_privileges(f: &Fixture) -> anyhow::Result<()> {
    for (grant, revoke) in [
        (
            "GRANT CREATE ON SCHEMA identity_authority TO identity_tenant_registrar",
            "REVOKE CREATE ON SCHEMA identity_authority FROM identity_tenant_registrar",
        ),
        (
            "GRANT UPDATE ON rss_transactional_messaging.tenant_epoch TO identity_tenant_registrar",
            "REVOKE UPDATE ON rss_transactional_messaging.tenant_epoch FROM identity_tenant_registrar",
        ),
        (
            "GRANT SELECT(auth_epoch) ON identity_authority.accounts TO identity_tenant_registrar",
            "REVOKE SELECT(auth_epoch) ON identity_authority.accounts FROM identity_tenant_registrar",
        ),
        (
            "GRANT EXECUTE ON FUNCTION identity_authority.protect_deployment() TO identity_tenant_registrar",
            "REVOKE EXECUTE ON FUNCTION identity_authority.protect_deployment() FROM identity_tenant_registrar",
        ),
        (
            "GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution() TO identity_tenant_registrar WITH GRANT OPTION",
            "REVOKE GRANT OPTION FOR EXECUTE ON FUNCTION rss_transactional_messaging.check_execution() FROM identity_tenant_registrar",
        ),
    ] {
        sqlx::raw_sql(grant).execute(&f.owner).await?;
        assert!(matches!(
            f.probe(AuthorityProfile::Runtime).await,
            Err(AuthorityError::StorageIncompatible(
                StorageMismatch::Privileges
            ))
        ));
        sqlx::raw_sql(revoke).execute(&f.owner).await?;
        assert!(f.probe(AuthorityProfile::Runtime).await.is_ok());
    }
    let service = federation_support::service(f, federation_support::ScriptedOidc::new());
    let mut settings = federation_support::settings().input();
    settings.jit = false;
    let p = service
        .create_provider(
            f.platform_actor().await?,
            settings.try_into()?,
            rss_identity_core::federation::ProviderCredentials::new(
                "startup-credential".into(),
                None,
            )?,
            deadline(),
        )
        .await?;
    f.store.check_credential_keys(deadline()).await?;
    use rss_transactional_messaging::fence::{Epoch, StorageIdentity};
    use rss_transactional_messaging_postgres::{PgConfig, PgPassword};
    let kdf = std::sync::Arc::new(rss_identity_core::account::PasswordKdf::new());
    let wrong = Authority::connect_runtime(
        f.runtime.clone(),
        kdf.clone(),
        f.deployment.clone(),
        rss_transactional_messaging::policy::DeliveryBudget::new(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        )?,
        f.system_key.tenant,
        RuntimeConfiguration::new(
            RuntimeSource::new(
                PgConfig::new_for_test_plaintext(
                    "127.0.0.1",
                    f.port,
                    &f.database,
                    "identity_runtime",
                    PgPassword::new("fixture-only"),
                ),
                StorageIdentity::new([1; 16], [2; 16])?,
                Epoch::new(1)?,
            ),
            std::sync::Arc::new(CredentialKeys::new(
                "fixture".into(),
                vec![("fixture".into(), [9; 32])],
            )?),
        ),
        deadline(),
    )
    .await?;
    assert!(
        wrong.check_credential_keys(deadline()).await.is_err(),
        "same key ID must authenticate actual key bytes"
    );
    drop(wrong);
    kdf.close();
    kdf.wait_closed().await;
    let sealed:serde_json::Value=sqlx::query_scalar("SELECT sealed FROM identity_authority.provider_credentials WHERE tenant_id=$1::uuid AND provider_id=$2::uuid").bind(SYSTEM).bind(p.id.to_string()).fetch_one(&f.owner).await?;
    let mut corrupt = sealed.clone();
    corrupt["ciphertext"][0] = serde_json::json!(corrupt["ciphertext"][0].as_u64().unwrap() ^ 1);
    sqlx::query("UPDATE identity_authority.provider_credentials SET sealed=$3 WHERE tenant_id=$1::uuid AND provider_id=$2::uuid").bind(SYSTEM).bind(p.id.to_string()).bind(corrupt).execute(&f.owner).await?;
    assert!(f.store.check_credential_keys(deadline()).await.is_err());
    sqlx::query("UPDATE identity_authority.provider_credentials SET sealed=$3 WHERE tenant_id=$1::uuid AND provider_id=$2::uuid").bind(SYSTEM).bind(p.id.to_string()).bind(sealed).execute(&f.owner).await?;
    Ok(())
}
async fn target_records(
    f: &Fixture,
    principal: PrincipalId,
    operation: uuid::Uuid,
    expected: i64,
) -> anyhow::Result<()> {
    for table in ["accounts", "memberships", "local_credentials"] {
        let n:i64=sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM identity_authority.{table} WHERE tenant_id=$1::uuid AND principal_id=$2"))).bind(A).bind(principal.as_uuid()).fetch_one(&f.owner).await?;
        assert_eq!(n, expected);
    }
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.platform_operations WHERE operation_id=$1",
    )
    .bind(operation)
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(n, expected);
    Ok(())
}
async fn assert_add_only_settlement(f: &Fixture) -> anyhow::Result<()> {
    for conflict in ["operation", "principal", "login"] {
        let mut first = input(f.key.tenant, uuid::Uuid::new_v4());
        let mut second = input(f.key.tenant, uuid::Uuid::new_v4());
        first.login = login(&format!("{conflict}-first"));
        second.login = login(&format!("{conflict}-second"));
        match conflict {
            "operation" => second.operation_id = first.operation_id,
            "principal" => second.principal = first.principal,
            _ => second.login = first.login.clone(),
        }
        let one = f.platform_actor().await?;
        let two = f.platform_actor().await?;
        let (a, b) = tokio::join!(
            f.store
                .add_business_tenant_administrator(one, first, deadline()),
            f.store
                .add_business_tenant_administrator(two, second, deadline())
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        let error = if let Err(e) = a { e } else { b.unwrap_err() };
        assert_eq!(error, AuthorityError::Platform(PlatformError::Conflict));
    }
    let mut request = input(f.key.tenant, uuid::Uuid::new_v4());
    request.login = login("rollback-added");
    let principal = request.principal;
    let operation = request.operation_id;
    let actor = f.platform_actor().await?;
    let before = f.events().await?;
    sqlx::raw_sql("CREATE FUNCTION public.reject_added_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE TRIGGER reject_added_event BEFORE INSERT ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.reject_added_event()").execute(&f.owner).await?;
    assert!(matches!(
        f.store
            .add_business_tenant_administrator(actor, request, deadline())
            .await,
        Err(AuthorityError::RolledBack(_))
    ));
    target_records(f, principal, operation, 0).await?;
    assert_eq!(f.events().await?, before);
    sqlx::raw_sql("DROP TRIGGER reject_added_event ON rss_transactional_messaging.outbox; DROP FUNCTION public.reject_added_event()").execute(&f.owner).await?;
    let mut request = input(f.key.tenant, uuid::Uuid::new_v4());
    request.login = login("unknown-added");
    let principal = request.principal;
    let operation = request.operation_id;
    let actor = f.platform_actor().await?;
    f.store
        .runtime()?
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        f.store
            .add_business_tenant_administrator(actor, request, deadline())
            .await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    target_records(f, principal, operation, 1).await?;
    assert_eq!(
        f.store
            .platform_operation(f.platform_actor().await?, operation, deadline())
            .await?
            .principal_id,
        principal.as_uuid()
    );
    assert_eq!(
        f.store
            .verify_password(
                f.key.tenant,
                login("admin"),
                password(),
                source(),
                deadline()
            )
            .await?
            .account(),
        f.key
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL"]
async fn platform_last_administrator_changes_serialize() -> anyhow::Result<()> {
    for (one, two) in [(0, 1), (0, 2), (1, 2)] {
        let f = Fixture::new().await?;
        f.bootstrap().await?;
        let second = f
            .store
            .create_local_account(
                f.platform_actor().await?,
                login("second-platform"),
                password(),
                LocalAccountRole::Member,
                deadline(),
            )
            .await?;
        f.store
            .set_platform_role(
                f.platform_actor().await?,
                second.key().principal,
                true,
                deadline(),
            )
            .await?;
        let first_candidate = f
            .store
            .verify_password(
                f.system_key.tenant,
                login("platform"),
                password(),
                source(),
                deadline(),
            )
            .await?;
        let first = f
            .store
            .create_session(first_candidate, None, deadline())
            .await?;
        let second_candidate = f
            .store
            .verify_password(
                f.system_key.tenant,
                login("second-platform"),
                password(),
                source(),
                deadline(),
            )
            .await?;
        let second_session = f
            .store
            .create_session(second_candidate, None, deadline())
            .await?;
        let a = f
            .store
            .inspect_session(
                f.system_key.tenant,
                rss_identity_core::session::SessionSecret::parse(first.secret().expose().into())?,
                deadline(),
            )
            .await?;
        let b = f
            .store
            .inspect_session(
                f.system_key.tenant,
                rss_identity_core::session::SessionSecret::parse(
                    second_session.secret().expose().into(),
                )?,
                deadline(),
            )
            .await?;
        let before = f.events().await?;
        let (a, b) = tokio::join!(
            platform_change(&f.store, a, f.system_key, one),
            platform_change(&f.store, b, second.key(), two)
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        let (stale, retained, survivor) = if a.is_ok() {
            (&first, &second_session, "second-platform")
        } else {
            (&second_session, &first, "platform")
        };
        let failed = if let Err(e) = a { e } else { b.unwrap_err() };
        assert_eq!(
            failed,
            AuthorityError::Platform(PlatformError::LastAdministrator)
        );
        assert_eq!(f.events().await?, before + 1);
        assert!(
            f.store
                .inspect_session(
                    f.system_key.tenant,
                    rss_identity_core::session::SessionSecret::parse(
                        stale.secret().expose().into()
                    )?,
                    deadline()
                )
                .await
                .is_err()
        );
        assert!(
            f.store
                .inspect_session(
                    f.system_key.tenant,
                    rss_identity_core::session::SessionSecret::parse(
                        retained.secret().expose().into()
                    )?,
                    deadline()
                )
                .await?
                .identity()
                .platform_administrator
        );
        let candidate = f
            .store
            .verify_password(
                f.system_key.tenant,
                login(survivor),
                password(),
                source(),
                deadline(),
            )
            .await?;
        assert!(
            f.store
                .create_session(candidate, None, deadline())
                .await?
                .identity()
                .platform_administrator
        );
        f.close().await;
    }
    Ok(())
}
async fn platform_change(
    store: &Authority,
    actor: AuthenticatedSession,
    key: AccountKey,
    change: u8,
) -> Result<rss_identity_core::account::AccountState, AuthorityError> {
    match change {
        0 => {
            store
                .set_platform_role(actor, key.principal, false, deadline())
                .await
        }
        1 => {
            store
                .set_account_enabled(actor, key, false, deadline())
                .await
        }
        _ => {
            store
                .set_account_membership(actor, key, false, deadline())
                .await
        }
    }
}
