//! Embedded reconstruction of #2433's real directory lifecycle; no central/client APIs.
use super::*;
use futures::FutureExt;
use rss_identity_core::groups::{GroupFactsMaxAge, UnavailableReason};
use std::{future::Future, panic::AssertUnwindSafe};

async fn without_staff<T>(body: impl Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
    let membership = keycloak_support::StaffMembership::load().await?;
    // Capture unwinding assertions as well as ordinary errors, then await restoration
    // before propagating either. Include removal in the scope: a lost response may
    // still have changed the provider.
    let result = AssertUnwindSafe(async {
        membership.set(false).await?;
        body.await
    })
    .catch_unwind()
    .await;
    let restored = membership.restore().await;
    if restored.is_err() {
        eprintln!("fixture staff membership restoration failed");
    }
    match result {
        Ok(result) => match (result, restored) {
            (result, Ok(())) => result,
            (Ok(_), Err(_)) => anyhow::bail!("fixture staff membership restoration failed"),
            (Err(error), Err(_)) => {
                Err(error.context("fixture staff membership restoration also failed"))
            }
        },
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

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
struct Paused {
    id: String,
    active: bool,
}
fn docker(action: &str, id: &str) -> anyhow::Result<()> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("docker")
        .args([action, id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                anyhow::ensure!(status.success(), "fixture docker {action} failed: {status}");
                return Ok(());
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            result => {
                let _ = child.kill();
                let _ = child.wait();
                result?;
                anyhow::bail!("fixture docker {action} timed out");
            }
        }
    }
}
impl Paused {
    fn new() -> anyhow::Result<Self> {
        // Own cleanup before invoking pause, including an uncertain command result.
        let guard = Self {
            id: std::env::var("IDENTITY_TEST_KEYCLOAK_CONTAINER")?,
            active: true,
        };
        docker("pause", &guard.id)?;
        Ok(guard)
    }
    fn restore(&mut self) -> anyhow::Result<()> {
        if self.active {
            docker("unpause", &self.id)?;
            self.active = false;
        }
        Ok(())
    }
}
impl Drop for Paused {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("fixture unpause fallback failed: {error}");
        }
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
    let panic = AssertUnwindSafe(without_staff(async {
        panic!("injected membership assertion failure");
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    }))
    .catch_unwind()
    .await;
    assert!(panic.is_err());
    let membership = keycloak_support::StaffMembership::load().await?;
    assert!(membership.current().await?);
    let error: anyhow::Result<()> =
        without_staff(async { anyhow::bail!("injected body error") }).await;
    assert!(error.is_err());
    assert!(membership.current().await?);
    without_staff(async {
        assert!(!membership.current().await?);
        without_staff(async { Ok(()) }).await?;
        assert!(!membership.current().await?);
        Ok(())
    })
    .await?;
    assert!(membership.current().await?);
    // A failed explicit restore must be surfaced and leave the fallback armed.
    let mut missing = Paused {
        id: format!("identity-missing-{}", uuid::Uuid::new_v4()),
        active: true,
    };
    assert!(missing.restore().is_err());
    assert!(missing.active);
    drop(missing);
    // Unwinding an assertion also releases a real paused fixture.
    let panic = std::panic::catch_unwind(|| {
        let _paused = Paused::new().unwrap();
        panic!("injected pause assertion failure");
    });
    assert!(panic.is_err());
    assert!(membership.current().await?);
    let first = login_browser(&app, &p, 'A').await?;
    let second = login_browser(&app, &p, 'B').await?;
    let actor = inspect(&f, &first).await?;
    let snapshot = available(&actor, p.id);
    assert_ne!(available(&inspect(&f, &second).await?, p.id), snapshot);
    let removed = without_staff(async {
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
    })
    .await?;
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
        let mut paused = Paused::new()?;
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
        paused.restore()?;
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
