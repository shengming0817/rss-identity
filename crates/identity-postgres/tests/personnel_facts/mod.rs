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
    let mut profile = local("emp").observation()?;
    profile.email_verified = rss_identity_core::profile::Attribute::Available { value: true };
    profile.extensions = rss_identity_core::profile::Attribute::Available {
        value: Extensions::try_from(json!({"jobs":["sales","dev"],"object":{"-1":"literal"}}))?,
    };
    *adapter.profile.lock().unwrap() = Some(profile);
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
    let max_age_seconds = std::num::NonZeroU32::new(86400).unwrap();
    let groups = read_personnel_facts_on(
        &mut tx,
        f.instance,
        account.tenant,
        &[account.principal],
        field(),
    )
    .await?;
    let item = &groups.items[0];
    assert_eq!(item.value, Some(json!([])));
    assert_eq!(item.status, ProfileStatus::Available);
    assert_eq!(item.provider_version, Some(provider.version));
    assert!(item.expires_at.unwrap() > groups.sampled_at);
    assert!(item.snapshot_id.is_some() && item.observation_sequence.is_some());
    let departments = read_personnel_facts_on(
        &mut tx,
        f.instance,
        account.tenant,
        &[account.principal],
        PersonnelField::Departments(provider.id),
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
            max_age_seconds,
        },
    )
    .await?;
    assert_eq!(email.items[0].value, Some(json!(true)));
    assert!(email.items[0].observation_sequence.is_some());
    for (segments, expected) in [
        (["extensions", "jobs", "1"], Some(json!("dev"))),
        (["extensions", "jobs", "-1"], None),
        (["extensions", "jobs", "01"], None),
        (["extensions", "object", "-1"], Some(json!("literal"))),
    ] {
        let segments = segments.map(str::to_owned);
        let profile = read_personnel_facts_on(
            &mut tx,
            f.instance,
            account.tenant,
            &[account.principal],
            PersonnelField::Profile {
                source,
                path: &segments,
                max_age_seconds,
            },
        )
        .await?;
        assert_eq!(profile.items[0].value, expected);
    }
    let missing = read_personnel_facts_on(
        &mut tx,
        f.instance,
        account.tenant,
        &[account.principal],
        PersonnelField::Profile {
            source: ProfileSource::IdentityLocal,
            path: &path,
            max_age_seconds,
        },
    )
    .await?;
    assert_eq!(missing.items[0].status, ProfileStatus::Missing);
    assert!(
        read_personnel_facts_on(&mut tx, f.instance, account.tenant, &[], field())
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
            read_personnel_facts_on(&mut tx, instance, tenant, &ids, field())
                .await
                .is_err()
        );
    }
    let future = groups.sampled_at + 20;
    sqlx::query("UPDATE identity_authority.sessions SET auth_facts=jsonb_set(auth_facts,'{groups,observed_at}',to_jsonb($1::bigint)) WHERE principal_id=$2 AND facts_sequence IS NOT NULL")
        .bind(future).bind(account.principal.as_uuid()).execute(&f.owner).await?;
    let pending = read_personnel_facts_on(
        &mut tx,
        f.instance,
        account.tenant,
        &[account.principal],
        field(),
    )
    .await?;
    assert_eq!(pending.items[0].status, ProfileStatus::Unavailable);
    assert_eq!(pending.next_transition_at(), Some(future));
    sqlx::query("UPDATE identity_authority.sessions SET auth_facts=auth_facts #- '{groups,expires_at}' WHERE principal_id=$1 AND facts_sequence IS NOT NULL")
        .bind(account.principal.as_uuid()).execute(&f.owner).await?;
    let malformed = read_personnel_facts_on(
        &mut tx,
        f.instance,
        account.tenant,
        &[account.principal],
        field(),
    )
    .await?;
    assert_eq!(malformed.items[0].status, ProfileStatus::Unavailable);
    assert!(malformed.items[0].value.is_none());
    sqlx::query("UPDATE identity_authority.sessions SET auth_facts=jsonb_set(jsonb_set(auth_facts,'{groups,observed_at}',to_jsonb($1::bigint-10)),'{groups,expires_at}',to_jsonb($1::bigint)) WHERE principal_id=$2 AND facts_sequence IS NOT NULL")
        .bind(groups.sampled_at).bind(account.principal.as_uuid()).execute(&f.owner).await?;
    let expired = read_personnel_facts_on(
        &mut tx,
        f.instance,
        account.tenant,
        &[account.principal],
        field(),
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
    )
    .await?;
    assert_eq!(invalid.items[0].status, ProfileStatus::Unavailable);
    assert!(invalid.items[0].value.is_none() && invalid.generation > expired.generation);
    assert_eq!(invalid.items[0].provider_version, item.provider_version);
    sqlx::query("RESET ROLE").execute(&mut *tx).await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("GRANT EXECUTE ON FUNCTION identity_authority.personnel_facts(uuid,uuid,uuid[],text,text,text[],bigint) TO {role} WITH GRANT OPTION")))
        .execute(&mut *tx).await?;
    sqlx::query("SELECT set_config('role',$1,true)")
        .bind(&role)
        .execute(&mut *tx)
        .await?;
    assert!(matches!(
        verify_personnel_fact_read(&mut tx).await,
        Err(AuthorityError::StorageIncompatible(
            StorageMismatch::Privileges
        ))
    ));
    tx.rollback().await?;
    drop(owner);
    f.close().await;
    Ok(())
}
