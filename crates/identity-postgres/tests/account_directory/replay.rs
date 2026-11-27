use super::*;
use federation_support::{ScriptedOidc, begin, enabled_department, finish, issued, service};

// Replay the same normal pagination requests on each revision; each version signs its own cursors.
pub(super) async fn replay_writes() -> anyhow::Result<Vec<Vec<bool>>> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let other = f
        .store
        .create_local_account(f.actor().await?, login("reader"), password(), deadline())
        .await?
        .key();
    let spare = f.login().await?;
    let federation = service(&f, ScriptedOidc::new());
    let selected = enabled_department(&f, &federation, 300).await?;
    let unrelated = enabled_department(&f, &federation, 300).await?;
    let _observation = issued(
        finish(
            &federation,
            begin(&f, &federation, &selected).await?,
            "alice",
        )
        .await?,
    );
    let source = selected.id.to_string();
    let queries = [
        AccountQuery::parse(None, Some("login"), Some("principalId,login"), None, 1)?,
        AccountQuery::parse(
            Some("enabled==true"),
            Some("login"),
            Some("principalId"),
            None,
            1,
        )?,
        AccountQuery::parse(
            None,
            Some("displayName"),
            Some("principalId"),
            Some("local"),
            1,
        )?,
        AccountQuery::parse(
            None,
            Some("profileStatus"),
            Some("principalId"),
            Some(&source),
            1,
        )?,
        AccountQuery::parse(None, None, Some("departmentStatus"), Some(&source), 1)?,
        AccountQuery::parse(
            None,
            Some("departmentStatus"),
            Some("email"),
            Some(&source),
            1,
        )?,
    ];
    let mut results = Vec::new();
    for event in [
        "session revocation",
        "other provider",
        "local observation",
        "selected provider",
        "account disabled",
    ] {
        let mut pages = Vec::new();
        for q in &queries {
            let cursor = f
                .store
                .list_accounts(f.actor().await?, q.clone(), None, deadline())
                .await?
                .next_cursor
                .ok_or_else(|| anyhow::anyhow!("missing first page"))?;
            let before = f
                .store
                .list_accounts(
                    f.actor().await?,
                    q.clone(),
                    Some(cursor.clone()),
                    deadline(),
                )
                .await?;
            pages.push((cursor, before.accounts[0].principal_id.clone()));
        }
        match event {
            "session revocation" => {
                sqlx::query("UPDATE identity_authority.sessions SET revoked_at=issued_at WHERE session_id=$1")
                .bind(spare.view().id.as_uuid()).execute(&f.owner).await?;
            }
            "other provider" | "selected provider" => {
                let provider = if event == "other provider" {
                    &unrelated
                } else {
                    &selected
                };
                federation
                    .enable_provider(
                        f.actor().await?,
                        provider.id,
                        provider.version,
                        false,
                        deadline(),
                    )
                    .await?;
            }
            "local observation" => {
                let affected=sqlx::query("UPDATE identity_authority.profile_observations SET value=jsonb_set(value,'{displayName}',jsonb_build_object('status','available','value','Updated')) WHERE tenant_id=$1::uuid AND source='local'")
                    .bind(A).execute(&f.owner).await?;
                assert!(affected.rows_affected() > 0);
            }
            "account disabled" => {
                f.store
                    .set_account_enabled(f.actor().await?, other, false, deadline())
                    .await?;
            }
            _ => unreachable!(),
        }
        let mut invalid = Vec::new();
        for (q, (cursor, expected)) in queries.iter().zip(pages) {
            match f
                .store
                .list_accounts(f.actor().await?, q.clone(), Some(cursor), deadline())
                .await
            {
                Ok(page) => {
                    assert_eq!(page.accounts[0].principal_id, expected, "{event}");
                    invalid.push(false);
                }
                Err(AuthorityError::CursorInvalidated) => invalid.push(true),
                Err(e) => return Err(e.into()),
            }
        }
        eprintln!("directory replay {event}: {invalid:?}");
        results.push(invalid);
    }
    f.close().await;
    Ok(results)
}
