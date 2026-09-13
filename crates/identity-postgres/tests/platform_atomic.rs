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
