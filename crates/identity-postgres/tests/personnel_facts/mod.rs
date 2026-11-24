use super::*;
use federation_support::*;
use rss_identity_postgres::personnel_facts::*;
use sqlx::Connection;

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn bounded_source_observations_under_reader_role() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let adapter = ScriptedOidc::new();
    adapter.groups.lock().unwrap().clear();
    let federation = service(&f, adapter);
    let provider = enabled_department(&f, &federation, 300).await?;
    let login = issued(
        finish(
            &federation,
            begin(&f, &federation, &provider).await?,
            "employee",
        )
        .await?,
    );
    let account = proof(&f.store, &f, &login).await?.account();
    let mut owner = f.owner.acquire().await?;
    let mut tx = owner.begin().await?;
    let role = format!("personnel_reader_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE ROLE {role} NOLOGIN")))
        .execute(&mut *tx)
        .await?;
    grant_personnel_fact_read(&mut tx, &role).await?;
    sqlx::query("SELECT set_config('role',$1,true),set_config('rss.tenant_id',$2,true)")
        .bind(&role)
        .bind(account.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    verify_personnel_fact_read(&mut tx).await?;
    let field = || PersonnelField::Groups(provider.id);
    let limits = ProfileLimits::default();
    let groups = read_personnel_facts_on(
        &mut tx,
        f.instance,
        account.tenant,
        &[account.principal],
        field(),
        limits,
    )
    .await?;
    let item = &groups.items[0];
    assert_eq!(item.value, Some(json!([])));
    assert_eq!(item.status, ProfileStatus::Available);
    assert_eq!(item.provider_version, Some(provider.version));
    assert!(item.expires_at.unwrap() > groups.sampled_at);
    assert!(item.snapshot_id.is_some() && item.source_revision.is_some());
    let departments = read_personnel_facts_on(
        &mut tx,
        f.instance,
        account.tenant,
        &[account.principal],
        PersonnelField::Departments(provider.id),
        limits,
    )
    .await?;
    assert_eq!(
        departments.items[0].value.as_ref().unwrap()["memberships"],
        json!(["dept-01"])
    );
    let path = ["emailVerified".to_owned()];
    let source = ProfileSource::Idp {
        provider: provider.id,
    };
    let email = read_personnel_facts_on(
        &mut tx,
        f.instance,
        account.tenant,
        &[account.principal],
        PersonnelField::Profile {
            source,
            path: &path,
        },
        limits,
    )
    .await?;
    assert_eq!(email.items[0].value, Some(json!(true)));
    let missing = read_personnel_facts_on(
        &mut tx,
        f.instance,
        account.tenant,
        &[account.principal],
        PersonnelField::Profile {
            source: ProfileSource::IdentityLocal,
            path: &path,
        },
        limits,
    )
    .await?;
    assert_eq!(missing.items[0].status, ProfileStatus::Missing);
    assert!(
        read_personnel_facts_on(&mut tx, f.instance, account.tenant, &[], field(), limits)
            .await?
            .items
            .is_empty()
    );
    for (instance, tenant, ids) in [
        (
            rss_identity_core::InstanceId::generate(),
            account.tenant,
            vec![account.principal],
        ),
        (
            f.instance,
            rss_request_context::TenantId::parse(B)?,
            vec![account.principal],
        ),
        (f.instance, account.tenant, vec![account.principal; 2]),
        (
            f.instance,
            account.tenant,
            vec![account.principal; MAX_PERSONNEL_SUBJECTS + 1],
        ),
    ] {
        assert!(
            read_personnel_facts_on(&mut tx, instance, tenant, &ids, field(), limits)
                .await
                .is_err()
        );
    }
    sqlx::query("UPDATE identity_authority.sessions SET auth_facts=jsonb_set(jsonb_set(auth_facts,'{groups,observed_at}',to_jsonb($1::bigint-10)),'{groups,expires_at}',to_jsonb($1::bigint)) WHERE principal_id=$2 AND facts_sequence IS NOT NULL")
        .bind(groups.sampled_at).bind(account.principal.as_uuid()).execute(&f.owner).await?;
    let expired = read_personnel_facts_on(
        &mut tx,
        f.instance,
        account.tenant,
        &[account.principal],
        field(),
        limits,
    )
    .await?;
    assert_eq!(expired.items[0].status, ProfileStatus::Expired);
    assert!(expired.items[0].value.is_none() && expired.generation > groups.generation);
    sqlx::query("UPDATE identity_authority.providers SET config_version=config_version+1 WHERE provider_id=$1::uuid")
        .bind(provider.id.to_string()).execute(&f.owner).await?;
    let invalid = read_personnel_facts_on(
        &mut tx,
        f.instance,
        account.tenant,
        &[account.principal],
        field(),
        limits,
    )
    .await?;
    assert_eq!(invalid.items[0].status, ProfileStatus::Unavailable);
    assert!(invalid.items[0].value.is_none() && invalid.generation > expired.generation);
    tx.rollback().await?;
    drop(owner);
    f.close().await;
    Ok(())
}
