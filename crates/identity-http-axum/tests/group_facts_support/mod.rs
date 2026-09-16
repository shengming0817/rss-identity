//! Real provider group removal and bounded expiry through the production online seam.
use super::{downstream_support::*, keycloak_support, support::*};
use reqwest::Client;
use rss_identity_client::{IdentityClient, VerifiedGroups, VerifiedIdentity};
use rss_identity_core::federation::{ProviderId, ProviderView};
use rss_identity_postgres::Federation;
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";

#[track_caller]
pub fn available(proof: &VerifiedIdentity, provider: ProviderId, values: &[&str]) -> uuid::Uuid {
    let VerifiedGroups::Available(groups) = proof.groups().unwrap() else {
        panic!("expected available groups");
    };
    assert_eq!(groups.values(), values);
    assert_eq!(
        groups.source().provider_id.to_string(),
        provider.to_string()
    );
    assert!(groups.expires_at() <= groups.observed_at() + 30);
    groups.snapshot_id()
}
async fn browser() -> anyhow::Result<Client> {
    Ok(Client::builder()
        .no_proxy()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            std::env::var("IDENTITY_TEST_DOWNSTREAM_CA")?,
        )?)?)
        .timeout(Duration::from_secs(10))
        .build()?)
}
async fn login(c: &Client, origin: &str, provider: ProviderId) -> anyhow::Result<Value> {
    let started = post(
        c,
        origin,
        &format!("/api/v1/tenants/{A}/oidc/{provider}/login"),
        json!({"client_id":"identity","return_target":"home"}),
        None,
    )
    .await?;
    let callback = keycloak_support::authorize(
        started["authorization_url"].as_str().unwrap(),
        "alice",
        false,
    )
    .await?;
    anyhow::ensure!(
        c.get(callback).send().await?.status() == reqwest::StatusCode::SEE_OTHER,
        "group login failed"
    );
    Ok(c.get(format!("{origin}/api/v1/tenants/{A}/session"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}
async fn consumer(token: &str, status: &str) -> anyhow::Result<()> {
    let token = Zeroizing::new(token.to_owned());
    let status = status.to_owned();
    let output = tokio::task::spawn_blocking(move || {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        std::process::Command::new("python3")
            .arg(root.join("hack/consumer.py"))
            .current_dir(root)
            .env("IDENTITY_TEST_GROUP_CREDENTIAL", token.as_str())
            .env("IDENTITY_TEST_GROUP_STATUS", status)
            .output()
    })
    .await??;
    anyhow::ensure!(
        output.status.success(),
        "independent group consumer failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(())
}
#[allow(clippy::too_many_arguments)] // One existing running PG/Keycloak/Hydra fixture, not another server.
pub async fn lifecycle(
    f: &Fixture,
    federation: &Federation,
    p: &ProviderView,
    sdk: &IdentityClient,
    c: &Client,
    origin: &str,
    issuer: &str,
    token: &str,
    csrf: &str,
) -> anyhow::Result<()> {
    let first = sdk.validate(token).await?;
    let snapshot = available(&first, p.id, &["/staff"]);
    consumer(token, "available").await?;
    let c2 = browser().await?;
    let session2 = login(&c2, origin, p.id).await?;
    let (token2, _, _) = flow(
        &c2,
        origin,
        issuer,
        session2["csrf_token"].as_str().unwrap(),
        VERIFIER,
        false,
    )
    .await?;
    let second = sdk.validate(&token2).await?;
    assert_ne!(available(&second, p.id, &["/staff"]), snapshot);
    // Every legal same-tenant client can receive the same session's groups.
    let (other_token, _, _) = flow_for_client(
        &c2,
        origin,
        issuer,
        session2["csrf_token"].as_str().unwrap(),
        VERIFIER,
        false,
        "other",
    )
    .await?;
    let other = IdentityClient::new(
        rss_identity_client::ClientConfig {
            identity_origin: origin.into(),
            issuer: issuer.into(),
            client_id: "other".into(),
            audience: "other-api".into(),
            tenant_id: A.into(),
            validation_secret: Zeroizing::new("fixture-validation-other-secret-32bytes".into()),
            timeout: Duration::from_secs(10),
            ca_pem: Some(std::fs::read(std::env::var(
                "IDENTITY_TEST_DOWNSTREAM_CA",
            )?)?),
        },
        Arc::new(rss_identity_client::SystemClock),
    )?;
    assert_eq!(
        available(&other.validate(&other_token).await?, p.id, &["/staff"]),
        available(&second, p.id, &["/staff"])
    );
    assert!(
        sdk.validate(&other_token).await.is_err(),
        "client binding is still enforced"
    );
    staff_membership(false).await?;
    available(&sdk.validate(token).await?, p.id, &["/staff"]);
    available(&sdk.validate(&token2).await?, p.id, &["/staff"]);
    let c3 = browser().await?;
    let session3 = login(&c3, origin, p.id).await?;
    let (removed_token, _, _) = flow(
        &c3,
        origin,
        issuer,
        session3["csrf_token"].as_str().unwrap(),
        VERIFIER,
        false,
    )
    .await?;
    assert!(
        matches!(
            sdk.validate(&removed_token).await?.groups()?,
            VerifiedGroups::Unavailable(
                rss_identity_contracts::groups::UnavailableReason::ClaimMissing
            )
        ),
        "Keycloak 26.7.3 omits the claim for zero memberships"
    );
    staff_membership(true).await?;
    let expiry = [&first, &second]
        .into_iter()
        .map(|proof| match proof.groups().unwrap() {
            VerifiedGroups::Available(g) => g.expires_at(),
            _ => panic!("early expiry"),
        })
        .max()
        .unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    tokio::time::sleep(Duration::from_secs((expiry - now).max(0) as u64)).await;
    for credential in [token, token2.as_str()] {
        let proof = sdk.validate(credential).await?;
        assert_eq!(proof.subject(), first.subject());
        assert!(matches!(proof.groups()?, VerifiedGroups::Expired));
    }
    consumer(token, "expired").await?;
    let before: Value = sqlx::query_scalar(
        "SELECT auth_facts FROM identity_authority.sessions WHERE session_id=$1::uuid",
    )
    .bind(first.session_id())
    .fetch_one(&f.owner)
    .await?;
    post(
        c,
        origin,
        &format!("/api/v1/tenants/{A}/session/refresh"),
        json!({}),
        Some(csrf),
    )
    .await?;
    let after: Value = sqlx::query_scalar(
        "SELECT auth_facts FROM identity_authority.sessions WHERE session_id=$1::uuid",
    )
    .bind(first.session_id())
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(before, after);
    assert!(matches!(
        sdk.validate(token).await?.groups()?,
        VerifiedGroups::Expired
    ));
    let c4 = browser().await?;
    let session4 = login(&c4, origin, p.id).await?;
    let (fresh_token, _, _) = flow(
        &c4,
        origin,
        issuer,
        session4["csrf_token"].as_str().unwrap(),
        VERIFIER,
        false,
    )
    .await?;
    assert_ne!(
        available(&sdk.validate(&fresh_token).await?, p.id, &["/staff"]),
        snapshot
    );
    // A directory outage cannot silently refresh groups or prevent online checks of a live snapshot.
    let container = std::env::var("IDENTITY_TEST_KEYCLOAK_CONTAINER")?;
    anyhow::ensure!(
        std::process::Command::new("docker")
            .args(["pause", &container])
            .output()?
            .status
            .success(),
        "fixture pause failed"
    );
    let outage = async {
        let existing = sdk.validate(&fresh_token).await?;
        let fresh_browser = browser().await?;
        let response = fresh_browser
            .post(format!("{origin}/api/v1/tenants/{A}/oidc/{}/login", p.id))
            .header("Origin", origin)
            .header("X-Identity-Request", "1")
            .json(&json!({"client_id":"identity","return_target":"home"}))
            .send()
            .await?;
        Ok::<_, anyhow::Error>((existing, response.status()))
    }
    .await;
    anyhow::ensure!(
        std::process::Command::new("docker")
            .args(["unpause", &container])
            .output()?
            .status
            .success(),
        "fixture unpause failed"
    );
    let (existing, status) = outage?;
    assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(existing.subject(), first.subject());
    available(&sdk.validate(&fresh_token).await?, p.id, &["/staff"]);
    // Changed claim interpretation revokes whole old sessions, including expired ones.
    let mut settings = p.settings.input();
    settings.claims.groups = Some("absent_groups".into());
    let credentials = rss_identity_core::federation::ProviderCredentials::new(
        "fixture-secret".into(),
        Some(std::fs::read_to_string(std::env::var(
            "IDENTITY_TEST_FEDERATED_CA",
        )?)?),
    )?;
    let changed = federation
        .update_provider(
            session_actor(&f.store, f.candidate().await?).await?,
            p.id,
            p.version,
            settings.try_into()?,
            credentials,
            deadline(),
        )
        .await?;
    for credential in [token, token2.as_str(), fresh_token.as_str()] {
        assert!(sdk.validate(credential).await.is_err());
    }
    let c5 = browser().await?;
    let session5 = login(&c5, origin, p.id).await?;
    let (missing_token, _, _) = flow(
        &c5,
        origin,
        issuer,
        session5["csrf_token"].as_str().unwrap(),
        VERIFIER,
        false,
    )
    .await?;
    assert!(matches!(
        sdk.validate(&missing_token).await?.groups()?,
        VerifiedGroups::Unavailable(
            rss_identity_contracts::groups::UnavailableReason::ClaimMissing
        )
    ));
    let disabled = federation
        .enable_provider(
            session_actor(&f.store, f.candidate().await?).await?,
            p.id,
            changed.version,
            false,
            deadline(),
        )
        .await?;
    assert!(sdk.validate(&missing_token).await.is_err());
    federation
        .enable_provider(
            session_actor(&f.store, f.candidate().await?).await?,
            p.id,
            disabled.version,
            true,
            deadline(),
        )
        .await?;
    assert!(
        sdk.validate(&missing_token).await.is_err(),
        "reenabling never resurrects an old epoch"
    );
    Ok(())
}

/// Disposable realm administration through Keycloak's real public TLS Admin API.
pub async fn staff_membership(member: bool) -> anyhow::Result<()> {
    let issuer = std::env::var("IDENTITY_TEST_FEDERATED_ISSUER")?;
    let origin = issuer.trim_end_matches("/realms/identity");
    let c = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(10))
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            std::env::var("IDENTITY_TEST_FEDERATED_CA")?,
        )?)?)
        .build()?;
    let token: serde_json::Value = c
        .post(format!(
            "{origin}/realms/master/protocol/openid-connect/token"
        ))
        .form(&[
            ("client_id", "admin-cli"),
            ("grant_type", "password"),
            ("username", "fixture-operator"),
            ("password", "fixture-operator-password"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let token = token["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("fixture admin credential absent"))?;
    let users: serde_json::Value = c
        .get(format!(
            "{origin}/admin/realms/identity/users?username=alice&exact=true"
        ))
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let groups: serde_json::Value = c
        .get(format!(
            "{origin}/admin/realms/identity/groups?search=staff&exact=true"
        ))
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let user = users[0]["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("fixture user absent"))?;
    let group = groups[0]["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("fixture group absent"))?;
    c.request(
        if member {
            reqwest::Method::PUT
        } else {
            reqwest::Method::DELETE
        },
        format!("{origin}/admin/realms/identity/users/{user}/groups/{group}"),
    )
    .bearer_auth(token)
    .send()
    .await?
    .error_for_status()?;
    Ok(())
}
