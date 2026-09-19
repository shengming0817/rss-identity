use super::*;
use federation_support::{
    ScriptedOidc, begin, enabled, enabled_department, finish, issued, service,
};
use rss_identity_core::department::{DepartmentClaim, DepartmentId, UpstreamDepartment};
use rss_identity_core::federation::ProviderCredentials;

async fn facts(f: &Fixture, session: &IssuedSession) -> anyhow::Result<serde_json::Value> {
    Ok(
        sqlx::query_scalar(
            "SELECT auth_facts FROM identity_authority.sessions WHERE session_id=$1",
        )
        .bind(session.view().id.as_uuid())
        .fetch_one(&f.owner)
        .await?,
    )
}
struct DepartmentPolicy {
    expected: Option<String>,
}
impl ManagementPolicy for DepartmentPolicy {
    fn authorize(
        &self,
        c: &ManagementContext<'_>,
    ) -> Result<ReauthenticationRequirement, ManagementDenied> {
        let VerifiedDepartment::Available(d) = c.department().map_err(|_| ManagementDenied)? else {
            return Err(ManagementDenied);
        };
        if d.account() != c.actor()
            || d.instance() != c.instance()
            || d.value()
                .map_err(|_| ManagementDenied)?
                .map(DepartmentId::as_str)
                != self.expected.as_deref()
        {
            return Err(ManagementDenied);
        }
        Ok(ReauthenticationRequirement::None)
    }
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn department_values_absence_expiry_refresh_and_management() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    let federation = service(&f, upstream.clone());
    let provider = enabled_department(&f, &federation, 2).await?;
    for expected in [Some("dept-01"), None] {
        *upstream.department.lock().unwrap() = match expected {
            Some(id) => UpstreamDepartment::Present(DepartmentId::new(id.into())?),
            None => UpstreamDepartment::NoDepartment,
        };
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
        let VerifiedDepartment::Available(department) = actor.department()? else {
            anyhow::bail!("department unavailable");
        };
        assert_eq!(department.value()?.map(DepartmentId::as_str), expected);
        assert_eq!(department.instance(), f.instance);
        assert_eq!(department.account(), actor.account());
        assert_eq!(
            department.provider_id().to_string(),
            provider.id.to_string()
        );
        assert_eq!(department.issuer(), provider.settings.issuer().as_str());
        assert_eq!(department.provider_config_version(), provider.version);
        assert_eq!(department.expires_at() - department.observed_at(), 2);
        let before = facts(&f, &session).await?;
        let managed = Authority::connect_runtime(
            f.runtime.clone(),
            Arc::new(PasswordKdf::new()),
            f.config(),
            Arc::new(DepartmentPolicy {
                expected: expected.map(str::to_owned),
            }),
            deadline(),
        )
        .await?;
        managed
            .list_accounts(
                managed
                    .inspect_session(f.key.tenant, secret(&session), deadline())
                    .await?,
                None,
                10,
                deadline(),
            )
            .await?;
        let refreshed = f
            .store
            .refresh_session(f.key.tenant, secret(&session), deadline())
            .await?;
        assert_eq!(facts(&f, &refreshed).await?, before);
        let reloaded = managed
            .inspect_session(f.key.tenant, secret(&refreshed), deadline())
            .await?;
        let VerifiedDepartment::Available(reloaded_department) = reloaded.department()? else {
            anyhow::bail!("reloaded department unavailable");
        };
        assert_eq!(reloaded_department.snapshot_id(), department.snapshot_id());
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(
            department.value(),
            Err(DepartmentAccessError::SnapshotExpired)
        );
        assert!(matches!(actor.department()?, VerifiedDepartment::Expired));
        assert!(actor.assurance().is_ok());
        assert!(matches!(actor.groups()?, VerifiedGroups::Available(_)));
        assert!(
            managed
                .list_accounts(
                    managed
                        .inspect_session(f.key.tenant, secret(&refreshed), deadline())
                        .await?,
                    None,
                    10,
                    deadline()
                )
                .await
                .is_err()
        );
        let again = f
            .store
            .refresh_session(f.key.tenant, secret(&refreshed), deadline())
            .await?;
        assert!(matches!(
            f.store
                .inspect_session(f.key.tenant, secret(&again), deadline())
                .await?
                .department()?,
            VerifiedDepartment::Expired
        ));
        assert_eq!(facts(&f, &again).await?, before);
    }
    *upstream.department.lock().unwrap() = UpstreamDepartment::Missing;
    let missing = issued(
        finish(
            &federation,
            begin(&f, &federation, &provider).await?,
            "missing",
        )
        .await?,
    );
    assert!(matches!(
        f.store
            .inspect_session(f.key.tenant, secret(&missing), deadline())
            .await?
            .department()?,
        VerifiedDepartment::Unavailable(UnavailableReason::ClaimMissing)
    ));
    let groups_only = enabled(&f, &federation).await?;
    let session = issued(
        finish(
            &federation,
            begin(&f, &federation, &groups_only).await?,
            "groups-only",
        )
        .await?,
    );
    let actor = f
        .store
        .inspect_session(f.key.tenant, secret(&session), deadline())
        .await?;
    assert!(matches!(
        actor.department()?,
        VerifiedDepartment::Unavailable(UnavailableReason::NotConfigured)
    ));
    assert!(matches!(actor.groups()?, VerifiedGroups::Available(_)));
    assert!(matches!(
        f.actor().await?.department()?,
        VerifiedDepartment::Unavailable(UnavailableReason::LocalIdentity)
    ));
    f.close().await;
    Ok(())
}

async fn login_department(
    f: &Fixture,
    federation: &Federation,
    provider: &rss_identity_core::federation::ProviderView,
) -> anyhow::Result<IssuedSession> {
    Ok(issued(
        finish(federation, begin(f, federation, provider).await?, "alice").await?,
    ))
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn department_configuration_revokes_sessions_and_pending_attempts() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let federation = service(&f, ScriptedOidc::new());
    let provider = enabled_department(&f, &federation, 60).await?;
    let old = login_department(&f, &federation, &provider).await?;
    let pending = begin(&f, &federation, &provider).await?;
    let mut settings = provider.settings.input();
    settings.claims.department = Some(DepartmentClaim::new("department_id".into(), 30)?);
    let next = federation
        .update_provider(
            f.actor().await?,
            provider.id,
            provider.version,
            settings.try_into()?,
            ProviderCredentials::new("fixture-secret".into(), None)?,
            deadline(),
        )
        .await?;
    assert!(
        next.version > provider.version
            && next.revocation_epoch > provider.revocation_epoch
            && next.credential_version > provider.credential_version
    );
    assert!(finish(&federation, pending, "alice").await.is_err());
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&old), deadline())
            .await
            .is_err()
    );
    let session = login_department(&f, &federation, &next).await?;
    let actor = f
        .store
        .inspect_session(f.key.tenant, secret(&session), deadline())
        .await?;
    let VerifiedDepartment::Available(d) = actor.department()? else {
        anyhow::bail!("department missing");
    };
    assert_eq!(d.expires_at() - d.observed_at(), 30);
    assert_eq!(d.provider_config_version(), next.version);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn department_source_is_instance_tenant_principal_and_provider_bound() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let federation = service(&f, ScriptedOidc::new());
    let provider = enabled_department(&f, &federation, 60).await?;
    let session = login_department(&f, &federation, &provider).await?;
    let actor = f
        .store
        .inspect_session(f.key.tenant, secret(&session), deadline())
        .await?;
    let key = actor.account();
    assert!(
        f.store
            .inspect_session(
                rss_request_context::TenantId::parse(B)?,
                secret(&session),
                deadline()
            )
            .await
            .is_err()
    );
    let other = Fixture::new().await?;
    other.bootstrap().await?;
    assert!(
        other
            .store
            .list_accounts(actor, None, 10, deadline())
            .await
            .is_err()
    );
    other.close().await;
    let other_provider = enabled_department(&f, &federation, 60).await?;
    let other_session = login_department(&f, &federation, &other_provider).await?;
    let other_actor = f
        .store
        .inspect_session(f.key.tenant, secret(&other_session), deadline())
        .await?;
    assert_ne!(other_actor.account(), key);
    let VerifiedDepartment::Available(d) = other_actor.department()? else {
        anyhow::bail!("department missing");
    };
    assert_eq!(d.account(), other_actor.account());
    assert_eq!(d.provider_id().to_string(), other_provider.id.to_string());
    let mismatch = sqlx::query("UPDATE identity_authority.sessions SET external_identity_id=(SELECT external_identity_id FROM identity_authority.sessions WHERE session_id=$1) WHERE session_id=$2")
        .bind(session.view().id.as_uuid()).bind(other_session.view().id.as_uuid()).execute(&f.owner).await.unwrap_err();
    assert_eq!(
        mismatch
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref(),
        Some("23503")
    );
    f.close().await;
    Ok(())
}

async fn revoke_case(kind: u8) -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let federation = service(&f, ScriptedOidc::new());
    let provider = enabled_department(&f, &federation, 60).await?;
    let session = login_department(&f, &federation, &provider).await?;
    let actor = f
        .store
        .inspect_session(f.key.tenant, secret(&session), deadline())
        .await?;
    match kind {
        0 => {
            f.store
                .set_account_enabled(f.actor().await?, actor.account(), false, deadline())
                .await?;
        }
        1 => {
            f.store
                .set_account_membership(f.actor().await?, actor.account(), false, deadline())
                .await?;
        }
        2 => {
            f.store.revoke_current_session(actor, deadline()).await?;
        }
        3 => {
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
        _ => unreachable!(),
    }
    assert!(
        f.store
            .inspect_session(f.key.tenant, secret(&session), deadline())
            .await
            .is_err()
    );
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn department_subject_and_provider_revocations_are_current() -> anyhow::Result<()> {
    for kind in 0..4 {
        revoke_case(kind).await?;
    }
    Ok(())
}
