use super::*;
use rss_identity_core::directory::AccountQuery;

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn department_link_preserves_source_observation_acceptance_order() -> anyhow::Result<()> {
    use federation_support::{
        BROWSER, ScriptedOidc, begin, department_snapshot, enabled_department, finish, issued,
        service, state,
    };
    use rss_identity_core::department::UpstreamDepartmentSnapshot;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let federation = service(&f, upstream.clone());
    let source_provider = enabled_department(&f, &federation, 120).await?;
    let target_provider = enabled_department(&f, &federation, 120).await?;
    let old = issued(
        finish(
            &federation,
            begin(&f, &federation, &source_provider).await?,
            "alice",
        )
        .await?,
    );
    let actor = f
        .store
        .inspect_session(f.key.tenant, secret(&old), deadline())
        .await?;
    let principal = actor.account().principal.as_uuid().to_string();
    let first = state(
        federation
            .begin_link(
                LinkRequest {
                    actor,
                    target_provider: target_provider.id,
                    password: None,
                    browser: BROWSER.into(),
                    target: "home".into(),
                    source: source(),
                },
                deadline(),
            )
            .await?,
    );
    let second = match federation
        .complete(
            first,
            BROWSER.into(),
            zeroize::Zeroizing::new("alice".into()),
            "https://idp.example.test".into(),
            Some(secret(&old)),
            deadline(),
        )
        .await?
    {
        FederatedOutcome::Redirect(redirect) => state(redirect),
        _ => anyhow::bail!("expected target authentication"),
    };
    // A distinct login accepts a newer missing source observation between the two link stages.
    *upstream.department_snapshot.lock().unwrap() = UpstreamDepartmentSnapshot::Missing;
    let newer = issued(
        finish(
            &federation,
            begin(&f, &federation, &source_provider).await?,
            "alice",
        )
        .await?,
    );
    *upstream.department_snapshot.lock().unwrap() =
        UpstreamDepartmentSnapshot::Present(department_snapshot(Some("target-only")));
    let linked = issued(
        federation
            .complete(
                second,
                BROWSER.into(),
                zeroize::Zeroizing::new("another-subject".into()),
                "https://idp.example.test".into(),
                Some(secret(&old)),
                deadline(),
            )
            .await?,
    );
    let (retained,latest):(i64,i64)=sqlx::query_as("SELECT (SELECT facts_sequence FROM identity_authority.sessions WHERE session_id=$1),(SELECT facts_sequence FROM identity_authority.sessions WHERE session_id=$2)")
        .bind(linked.view().id.as_uuid()).bind(newer.view().id.as_uuid()).fetch_one(&f.owner).await?;
    assert!(
        retained < latest,
        "copying a source fact must preserve its acceptance order"
    );
    let source_id = source_provider.id.to_string();
    let query = AccountQuery::parse(
        Some(&format!("principalId=='{principal}'")),
        None,
        Some("principalId,departmentStatus,departmentSnapshot"),
        Some(&source_id),
        50,
    )?;
    let rows = f
        .store
        .list_accounts(f.actor().await?, query, None, deadline())
        .await?
        .accounts;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].department_snapshot.is_none());
    assert_eq!(rows[0].department_status, "unavailable");
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn account_directory_null_and_equal_values_keep_total_order() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let mut ids = Vec::new();
    for name in ["alpha", "beta", "gamma", "omega"] {
        let state = f
            .store
            .create_local_account(f.actor().await?, login(name), password(), deadline())
            .await?;
        ids.push((name, state.key().principal.as_uuid().to_string()));
        if ["alpha", "beta"].contains(&name) {
            let profile = rss_identity_core::profile::LocalProfile {
                display_name: Some("Same".into()),
                username: None,
                email: None,
                extensions: serde_json::json!({}).try_into()?,
                max_age_seconds: 3600,
            };
            f.store
                .update_local_profile(
                    f.actor().await?,
                    state.key(),
                    ProfileChange {
                        operation_id: uuid::Uuid::new_v4(),
                        expected_revision: 0,
                        value: Some(profile),
                    },
                    deadline(),
                )
                .await?;
            f.store
                .login_local(
                    f.key.tenant,
                    login(name),
                    password(),
                    source(),
                    None,
                    deadline(),
                )
                .await?;
        }
    }
    for sort in ["displayName,enabled", "-displayName,-enabled"] {
        let query = AccountQuery::parse(
            Some("login=in=('alpha','beta','gamma','omega')"),
            Some(sort),
            Some("principalId"),
            Some("local"),
            1,
        )?;
        let mut expected = ids.clone();
        expected.sort_by(|(a, aid), (b, bid)| {
            let missing = |name: &&str| !["alpha", "beta"].contains(name);
            missing(a).cmp(&missing(b)).then_with(|| aid.cmp(bid))
        });
        let mut cursor = None;
        let mut actual = Vec::new();
        loop {
            let page = f
                .store
                .list_accounts(f.actor().await?, query.clone(), cursor, deadline())
                .await?;
            actual.extend(page.accounts.into_iter().map(|row| row.principal_id));
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(
            actual,
            expected.into_iter().map(|(_, id)| id).collect::<Vec<_>>()
        );
    }
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn account_detail_rejects_expiry_during_target_read() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let target = f
        .store
        .create_local_account(f.actor().await?, login("target"), password(), deadline())
        .await?
        .key();
    let session = f.login().await?;
    sqlx::query("UPDATE identity_authority.sessions SET issued_at=floor(extract(epoch FROM clock_timestamp()))::bigint-118,local_authenticated_at=floor(extract(epoch FROM clock_timestamp()))::bigint-118,idle_expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint+2,absolute_expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint+2,idle_timeout=120,absolute_timeout=120 WHERE session_id=$1")
        .bind(session.view().id.as_uuid()).execute(&f.owner).await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE FUNCTION identity_authority.delay_directory_detail() RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(3); RETURN true; END $$; GRANT EXECUTE ON FUNCTION identity_authority.delay_directory_detail() TO identity_runtime; CREATE POLICY delay_directory_detail ON identity_authority.local_credentials AS RESTRICTIVE FOR SELECT USING (CASE WHEN principal_id='{}'::uuid THEN identity_authority.delay_directory_detail() ELSE true END)",target.principal.as_uuid())))
        .execute(&f.owner).await?;
    let actor = f
        .store
        .inspect_session(f.key.tenant, secret(&session), deadline())
        .await?;
    assert!(matches!(
        f.store.read_account(actor, target, deadline()).await,
        Err(AuthorityError::Rejected)
    ));
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn account_directory_filters_before_stable_pagination_and_invalidates_changes()
-> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    for name in ["alpha", "beta", "gamma"] {
        f.store
            .create_local_account(f.actor().await?, login(name), password(), deadline())
            .await?;
    }
    let q = AccountQuery::parse(
        Some("login=in=('alpha','beta','gamma')"),
        Some("-login"),
        Some("principalId,login"),
        None,
        1,
    )?;
    let mut cursor = None;
    let mut names = Vec::new();
    loop {
        let page = f
            .store
            .list_accounts(f.actor().await?, q.clone(), cursor, deadline())
            .await?;
        assert_eq!(page.fields, q.fields());
        names.extend(page.accounts.iter().map(|r| r.login.clone().unwrap()));
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(names, ["gamma", "beta", "alpha"]);
    let page = f
        .store
        .list_accounts(f.actor().await?, q.clone(), None, deadline())
        .await?;
    let changed = AccountQuery::parse(
        Some("login=='alpha'"),
        Some("-login"),
        Some("principalId,login"),
        None,
        1,
    )?;
    assert!(matches!(
        f.store
            .list_accounts(
                f.actor().await?,
                changed,
                page.next_cursor.clone(),
                deadline()
            )
            .await,
        Err(AuthorityError::CursorInvalidated)
    ));
    let target = AccountKey {
        tenant: f.key.tenant,
        principal: rss_identity_core::PrincipalId::parse(&page.accounts[0].principal_id)?,
    };
    let detail = f
        .store
        .read_account(f.actor().await?, target, deadline())
        .await?;
    assert_eq!(detail.login.as_deref(), Some("gamma"));
    f.store
        .set_account_enabled(f.actor().await?, target, false, deadline())
        .await?;
    assert!(matches!(
        f.store
            .list_accounts(f.actor().await?, q, page.next_cursor, deadline())
            .await,
        Err(AuthorityError::CursorInvalidated)
    ));
    let disabled = f
        .store
        .list_accounts(
            f.actor().await?,
            AccountQuery::parse(Some("enabled==false"), None, None, None, 50)?,
            None,
            deadline(),
        )
        .await?;
    assert_eq!(disabled.accounts.len(), 1);
    assert_eq!(disabled.accounts[0].login.as_deref(), Some("gamma"));
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn account_directory_profiles_are_source_selected_and_authorized_for_predicates()
-> anyhow::Result<()> {
    use rss_identity_core::profile::{Extensions, LocalProfile};
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    f.store
        .update_local_profile(
            f.actor().await?,
            f.key,
            ProfileChange {
                operation_id: uuid::Uuid::new_v4(),
                expected_revision: 0,
                value: Some(LocalProfile {
                    display_name: Some("Local Alice".into()),
                    username: None,
                    email: Some("alice@example.test".into()),
                    extensions: Extensions::try_from(serde_json::json!({}))?,
                    max_age_seconds: 3600,
                }),
            },
            deadline(),
        )
        .await?;
    f.login().await?;
    let q = AccountQuery::parse(
        Some("email=icontains='EXAMPLE.TEST'"),
        Some("displayName"),
        Some("principalId,displayName,email,profileStatus"),
        Some("local"),
        1,
    )?;
    let page = f
        .store
        .list_accounts(f.actor().await?, q.clone(), None, deadline())
        .await?;
    assert_eq!(page.accounts.len(), 1);
    assert_eq!(
        page.accounts[0].display_name.as_deref(),
        Some("Local Alice")
    );
    assert_eq!(page.accounts[0].profile_status, "available");
    struct NoProfiles;
    impl ManagementPolicy for NoProfiles {
        fn authorize<'a>(
            &'a self,
            c: &'a ManagementContext<'a>,
            _: &'a mut sqlx::PgConnection,
        ) -> futures::future::BoxFuture<'a, Result<ReauthenticationRequirement, ManagementDenied>>
        {
            Box::pin(async move {
                if c.operation() == ManagementOperation::ReadLatestProfile {
                    Err(ManagementDenied)
                } else {
                    Ok(ReauthenticationRequirement::None)
                }
            })
        }
    }
    let restricted = Authority::connect_runtime(
        f.runtime.clone(),
        Arc::new(rss_identity_core::account::PasswordKdf::new()),
        f.config(),
        Arc::new(NoProfiles),
        deadline(),
    )
    .await?;
    assert!(
        restricted
            .list_accounts(f.actor().await?, q, None, deadline())
            .await
            .is_err()
    );
    assert!(
        !restricted
            .list_accounts(f.actor().await?, AccountQuery::default(), None, deadline())
            .await?
            .accounts
            .is_empty()
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn department_directory_uses_latest_accepted_fact_without_resurrecting_older_memberships()
-> anyhow::Result<()> {
    use federation_support::{
        ScriptedOidc, begin, department_snapshot, enabled_department, finish, issued, service,
    };
    use rss_identity_core::department::UpstreamDepartmentSnapshot;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let federation = service(&f, upstream.clone());
    let provider = enabled_department(&f, &federation, 120).await?;
    let provider_id = provider.id.to_string();
    let old = issued(
        finish(
            &federation,
            begin(&f, &federation, &provider).await?,
            "alice",
        )
        .await?,
    );
    let query = || {
        AccountQuery::parse(
            Some("departmentSubtree=='root'"),
            None,
            Some("principalId,departmentStatus,departmentSnapshot"),
            Some(&provider_id),
            50,
        )
    };
    let page = f
        .store
        .list_accounts(f.actor().await?, query()?, None, deadline())
        .await?;
    assert_eq!(page.accounts.len(), 1);
    let principal = page.accounts[0].principal_id.clone();
    // Logging out does not rewrite the accepted directory observation or extend its TTL.
    let actor = f
        .store
        .inspect_session(f.key.tenant, secret(&old), deadline())
        .await?;
    f.store.revoke_current_session(actor, deadline()).await?;
    assert_eq!(
        f.store
            .list_accounts(f.actor().await?, query()?, None, deadline())
            .await?
            .accounts
            .len(),
        1
    );
    *upstream.department_snapshot.lock().unwrap() = UpstreamDepartmentSnapshot::Missing;
    upstream
        .issued_at_offset
        .store(-1, std::sync::atomic::Ordering::SeqCst);
    let newer = issued(
        finish(
            &federation,
            begin(&f, &federation, &provider).await?,
            "alice",
        )
        .await?,
    );
    assert!(
        f.store
            .list_accounts(f.actor().await?, query()?, None, deadline())
            .await?
            .accounts
            .is_empty()
    );
    let all = || {
        AccountQuery::parse(
            Some(&format!("principalId=='{principal}'")),
            None,
            Some("principalId,departmentStatus,departmentSnapshot"),
            Some(&provider_id),
            50,
        )
    };
    let page = f
        .store
        .list_accounts(f.actor().await?, all()?, None, deadline())
        .await?;
    assert_eq!(page.accounts[0].department_status, "claim_missing");
    assert!(page.accounts[0].department_snapshot.is_none());
    let (old_seq,new_seq):(i64,i64)=sqlx::query_as("SELECT (SELECT facts_sequence FROM identity_authority.sessions WHERE session_id=$1),(SELECT facts_sequence FROM identity_authority.sessions WHERE session_id=$2)").bind(old.view().id.as_uuid()).bind(newer.view().id.as_uuid()).fetch_one(&f.owner).await?;
    assert!(new_seq > old_seq);
    upstream
        .issued_at_offset
        .store(0, std::sync::atomic::Ordering::SeqCst);
    *upstream.department_snapshot.lock().unwrap() =
        UpstreamDepartmentSnapshot::Present(department_snapshot(None));
    issued(
        finish(
            &federation,
            begin(&f, &federation, &provider).await?,
            "alice",
        )
        .await?,
    );
    let page = f
        .store
        .list_accounts(f.actor().await?, all()?, None, deadline())
        .await?;
    assert_eq!(page.accounts[0].department_status, "available");
    assert!(
        page.accounts[0]
            .department_snapshot
            .as_ref()
            .unwrap()
            .memberships()
            .is_empty()
    );
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.owner)
            .await?;
    sqlx::query("UPDATE identity_authority.sessions SET auth_facts=jsonb_set(jsonb_set(auth_facts,'{department_snapshot,observed_at}',to_jsonb($2::bigint)),'{department_snapshot,expires_at}',to_jsonb($3::bigint)) WHERE facts_sequence=(SELECT max(facts_sequence) FROM identity_authority.sessions WHERE principal_id=$1::uuid AND external_identity_id IS NOT NULL)")
        .bind(&principal).bind(now-1000).bind(now-900).execute(&f.owner).await?;
    let page = f
        .store
        .list_accounts(f.actor().await?, all()?, None, deadline())
        .await?;
    assert_eq!(page.accounts[0].department_status, "expired");
    assert!(page.accounts[0].department_snapshot.is_none());
    federation
        .enable_provider(
            f.actor().await?,
            provider.id,
            provider.version,
            false,
            deadline(),
        )
        .await?;
    let page = f
        .store
        .list_accounts(f.actor().await?, all()?, None, deadline())
        .await?;
    assert_eq!(page.accounts[0].department_status, "unavailable");
    f.close().await;
    Ok(())
}
