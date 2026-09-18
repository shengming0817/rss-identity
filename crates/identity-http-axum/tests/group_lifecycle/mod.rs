//! Embedded reconstruction of #2433's real directory lifecycle; no central/client APIs.
use super::*;
use rss_identity_core::groups::{GroupFactsMaxAge, UnavailableReason};

fn available(actor: &AuthenticatedSession, provider: ProviderId) -> uuid::Uuid {
    let VerifiedGroups::Available(groups) = actor.groups().unwrap() else {
        panic!("fresh groups absent")
    };
    assert_eq!(groups.values().unwrap(), ["/staff"]);
    assert_eq!(
        groups.source().provider_id.to_string(),
        provider.to_string()
    );
    assert_eq!(
        groups.source().issuer,
        std::env::var("IDENTITY_TEST_FEDERATED_ISSUER").unwrap()
    );
    groups.snapshot_id()
}
async fn inspect(f: &Fixture, cookie: &str) -> anyhow::Result<AuthenticatedSession> {
    Ok(f.store
        .inspect_session(tenant(), secret(cookie), deadline())
        .await?)
}
// Each independent browser gets its own binding and the normal per-browser attempt budget.
async fn login_browser(
    app: &Router,
    provider: &ProviderView,
    binding: char,
) -> anyhow::Result<String> {
    let browser = format!(
        "__Host-identity-oidc-browser={}A",
        binding.to_string().repeat(42)
    );
    let url = begin(app, provider, &browser, None, None, false).await?;
    let cb = authorize(&url, "alice").await?;
    let response = callback(app, &cb, &browser).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    Ok(cookie(&response))
}
struct Paused(String);
impl Paused {
    fn new() -> anyhow::Result<Self> {
        let id = std::env::var("IDENTITY_TEST_KEYCLOAK_CONTAINER")?;
        anyhow::ensure!(
            std::process::Command::new("docker")
                .args(["pause", &id])
                .output()?
                .status
                .success(),
            "fixture pause failed"
        );
        Ok(Self(id))
    }
}
impl Drop for Paused {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker")
            .args(["unpause", &self.0])
            .output();
    }
}

#[tokio::test]
#[ignore = "requires make test-federated"]
async fn real_group_snapshot_lifecycle() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let s = Federation::new(
        GroupFactsMaxAge::new(30)?,
        f.store.clone(),
        Arc::new(fixture_transport(true)?),
        StateSigner::new([7; 32], ORIGIN)?,
        FederationConfig {
            callback: CALLBACK.into(),
            credential_keys: credential_keys(),
            targets: BTreeMap::from([("home".into(), format!("{ORIGIN}/done"))]),
        },
    )?;
    let p = provider(&f, &s).await?;
    let app = app(&s);
    let first = login_browser(&app, &p, 'A').await?;
    let second = login_browser(&app, &p, 'B').await?;
    let actor = inspect(&f, &first).await?;
    let snapshot = available(&actor, p.id);
    assert_ne!(available(&inspect(&f, &second).await?, p.id), snapshot);
    keycloak_support::staff_membership(false).await?;
    let removed = async {
        assert_eq!(available(&inspect(&f, &first).await?, p.id), snapshot);
        available(&inspect(&f, &second).await?, p.id);
        let cookie = login_browser(&app, &p, 'C').await?;
        assert!(
            matches!(
                inspect(&f, &cookie).await?.groups()?,
                VerifiedGroups::Unavailable(UnavailableReason::ClaimMissing)
            ),
            "Keycloak omits groups for zero memberships"
        );
        Ok::<_, anyhow::Error>(cookie)
    }
    .await;
    keycloak_support::staff_membership(true).await?;
    let removed = removed?;
    // Fresh request proof outlives the group snapshot while retaining the same signed deadline.
    let expiry: i64 = sqlx::query_scalar("SELECT max((auth_facts->'groups'->>'expires_at')::bigint) FROM identity_authority.sessions WHERE auth_facts IS NOT NULL")
        .fetch_one(&f.owner).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.owner)
            .await?;
    tokio::time::sleep(Duration::from_secs(
        (expiry - now).saturating_sub(1).max(0) as u64
    ))
    .await;
    let near = inspect(&f, &first).await?;
    let retained = match near.groups()? {
        VerifiedGroups::Available(g) => Some(g),
        VerifiedGroups::Expired => None,
        _ => panic!("unexpected groups"),
    };
    tokio::time::sleep(Duration::from_secs(2)).await;
    if let Some(groups) = retained {
        assert_eq!(groups.values(), Err(GroupAccessError::SnapshotExpired));
    }
    assert!(near.assurance().is_ok());
    for cookie in [&first, &second] {
        let old = inspect(&f, cookie).await?;
        assert_eq!(old.account(), actor.account());
        assert!(matches!(old.groups()?, VerifiedGroups::Expired));
    }
    let before: Value = sqlx::query_scalar(
        "SELECT auth_facts FROM identity_authority.sessions WHERE session_id=$1",
    )
    .bind(actor.view().id.as_uuid())
    .fetch_one(&f.owner)
    .await?;
    let refreshed = f
        .store
        .refresh_session(tenant(), secret(&first), deadline())
        .await?;
    let after: Value = sqlx::query_scalar(
        "SELECT auth_facts FROM identity_authority.sessions WHERE session_id=$1",
    )
    .bind(actor.view().id.as_uuid())
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(before, after);
    let refreshed = format!("session={}", refreshed.secret().expose());
    assert!(matches!(
        inspect(&f, &refreshed).await?.groups()?,
        VerifiedGroups::Expired
    ));
    let fresh = login_browser(&app, &p, 'D').await?;
    assert_ne!(available(&inspect(&f, &fresh).await?, p.id), snapshot);
    {
        let _paused = Paused::new()?;
        available(&inspect(&f, &fresh).await?, p.id);
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                &format!("/api/v2/tenants/{A}/oidc/{}/login", p.id),
                BROWSER,
                None,
                json!({"returnTarget":"home"}),
            ))
            .await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    available(&inspect(&f, &fresh).await?, p.id);
    let mut settings = p.settings.input();
    settings.claims.groups = Some("absent_groups".into());
    let changed = s
        .update_provider(
            f.actor().await?,
            p.id,
            p.version,
            settings.try_into()?,
            credentials(true)?,
            deadline(),
        )
        .await?;
    for cookie in [&refreshed, &second, &removed, &fresh] {
        assert!(inspect(&f, cookie).await.is_err());
    }
    let missing = login_browser(&app, &changed, 'E').await?;
    assert!(matches!(
        inspect(&f, &missing).await?.groups()?,
        VerifiedGroups::Unavailable(UnavailableReason::ClaimMissing)
    ));
    let disabled = s
        .enable_provider(f.actor().await?, p.id, changed.version, false, deadline())
        .await?;
    assert!(inspect(&f, &missing).await.is_err());
    s.enable_provider(f.actor().await?, p.id, disabled.version, true, deadline())
        .await?;
    assert!(inspect(&f, &missing).await.is_err());
    f.close().await;
    Ok(())
}
