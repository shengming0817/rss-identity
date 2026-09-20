//! Real administrator-owned signed JSON assertions, including independent old sessions.
use super::*;
use futures::FutureExt;
use rss_identity_core::department::DepartmentUnavailableReason;
use std::panic::AssertUnwindSafe;

async fn inspect(
    f: &Fixture,
    app: &Router,
    provider: &ProviderView,
    binding: char,
) -> anyhow::Result<AuthenticatedSession> {
    let browser = format!(
        "__Host-identity-oidc-browser={}A",
        binding.to_string().repeat(42)
    );
    let url = begin(app, provider, &browser, None, None, false).await?;
    let cb = authorize(&url, "alice").await?;
    let response = callback(app, &cb, &browser).await?;
    Ok(f.store
        .inspect_session(tenant(), secret(&cookie(&response)), deadline())
        .await?)
}

#[tokio::test]
#[ignore = "requires make test-federated"]
async fn administrator_snapshot_moves_members_and_keeps_old_observations() -> anyhow::Result<()> {
    let admin = keycloak_support::StaffMembership::load().await?;
    let original = admin.organization().await?;
    let result = AssertUnwindSafe(async {
        admin.reject_user_organization_edit().await?;
        let f = Fixture::new().await?;
        f.bootstrap().await?;
        let s = service(&f, Arc::new(fixture_transport(true)?));
        let p = provider(&f, &s).await?;
        let app = app(&s);
        let old = inspect(&f, &app, &p, 'j').await?;
        let VerifiedDepartmentSnapshot::Available(old_fact) = old.department_snapshot()? else {
            anyhow::bail!("initial snapshot missing")
        };
        assert_eq!(old_fact.snapshot()?.source_revision(), "fixture-r1");
        assert_eq!(old_fact.snapshot()?.memberships()[0].as_str(), "dept-01");
        assert_eq!(old_fact.snapshot()?.nodes().len(), 3);

        let mut moved = original.clone();
        moved["sourceRevision"] = json!("fixture-r2");
        moved["nodes"][1]["parentId"] = json!("dept-02");
        moved["memberships"] = json!(["dept-02"]);
        admin.set_organization(&moved).await?;
        let next = inspect(&f, &app, &p, 'k').await?;
        let VerifiedDepartmentSnapshot::Available(next_fact) = next.department_snapshot()? else {
            anyhow::bail!("moved snapshot missing")
        };
        assert_eq!(next_fact.snapshot()?.source_revision(), "fixture-r2");
        assert_eq!(next_fact.snapshot()?.memberships()[0].as_str(), "dept-02");
        assert_eq!(
            next_fact.snapshot()?.nodes()[1]
                .parent_id()
                .unwrap()
                .as_str(),
            "dept-02"
        );
        assert_eq!(old_fact.snapshot()?.source_revision(), "fixture-r1");
        assert_eq!(
            old_fact.snapshot()?.nodes()[1]
                .parent_id()
                .unwrap()
                .as_str(),
            "root"
        );
        assert_eq!(old_fact.account(), next_fact.account());
        assert_ne!(old_fact.snapshot_id(), next_fact.snapshot_id());

        moved["nodes"][1]["parentId"] = json!("missing");
        admin.set_organization(&moved).await?;
        let invalid = inspect(&f, &app, &p, 'l').await?;
        assert!(invalid.assurance().is_ok());
        assert!(matches!(invalid.groups()?, VerifiedGroups::Available(_)));
        assert!(matches!(
            invalid.department_snapshot()?,
            VerifiedDepartmentSnapshot::Unavailable(DepartmentUnavailableReason::InvalidClaim)
        ));

        moved["nodes"] = json!([{"id":"root","displayName":"Company","parentId":null}]);
        moved["memberships"] = json!([]);
        moved["sourceRevision"] = json!("fixture-r3");
        admin.set_organization(&moved).await?;
        let unassigned = inspect(&f, &app, &p, 'm').await?;
        let VerifiedDepartmentSnapshot::Available(fact) = unassigned.department_snapshot()? else {
            anyhow::bail!("unassigned snapshot missing")
        };
        assert!(fact.snapshot()?.memberships().is_empty());
        assert_eq!(fact.snapshot()?.nodes().len(), 1);
        assert_eq!(fact.snapshot()?.source_revision(), "fixture-r3");
        f.close().await;
        Ok(())
    })
    .catch_unwind()
    .await;
    let restored = admin.set_organization(&original).await;
    match result {
        Ok(result) => {
            restored?;
            result
        }
        Err(panic) => {
            if restored.is_err() {
                eprintln!("organization fixture restoration failed");
            }
            std::panic::resume_unwind(panic)
        }
    }
}
