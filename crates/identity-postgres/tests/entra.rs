//! Real PG native personnel admission; no browser session is minted.
mod federation_support;
mod support;
use rss_identity_core::{entra::*, federation::*};
use rss_identity_postgres::*;
use std::sync::Arc;
use support::*;
use uuid::Uuid;
use zeroize::Zeroizing;

const TENANT: &str = "44444444-4444-4444-8444-444444444444";
const USER: &str = "55555555-5555-4555-8555-555555555555";
struct Verifier;
impl EntraTokenVerifier for Verifier {
    fn verify<'a>(
        &'a self,
        p: &'a EntraTokenProfile,
        token: Zeroizing<String>,
    ) -> UpstreamFuture<'a, EntraTokenClaims> {
        Box::pin(async move {
            let user = Uuid::parse_str(&token).map_err(|_| FederationError::Claims)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            Ok(EntraTokenClaims {
                tenant: p.tenant,
                user,
                device: None,
                issued_at: now - 1,
                expires_at: now + 300,
            })
        })
    }
}
async fn setup(
    f: &Fixture,
    jit: bool,
) -> anyhow::Result<(Federation, ProviderView, EntraAuthority)> {
    let federation = federation_support::service(f, federation_support::ScriptedOidc::new());
    let mut input = federation_support::settings().input();
    input.issuer = format!("https://login.microsoftonline.com/{TENANT}/v2.0");
    input.claims.subject = SubjectMapping::Entra {
        tenant: Uuid::parse_str(TENANT)?,
    };
    input.scopes.push("profile".into());
    input.jit = jit;
    let view = federation
        .create_provider(
            f.actor().await?,
            input.try_into()?,
            ProviderCredentials::new("fixture-secret".into(), None)?,
            deadline(),
        )
        .await?;
    let view = federation
        .enable_provider(f.actor().await?, view.id, view.version, true, deadline())
        .await?;
    let profile = EntraTokenProfile {
        tenant: Uuid::parse_str(TENANT)?,
        app_id: Uuid::new_v4(),
        authorized_clients: vec![Uuid::new_v4()],
        required_scopes: vec![],
        device_claim: "deviceid".into(),
    };
    let native = EntraAuthority::new(
        f.store.clone(),
        Arc::new(Verifier),
        f.key.tenant,
        view.id,
        profile,
    )?;
    Ok((federation, view, native))
}
async fn admit(native: &EntraAuthority) -> Result<RevalidatedAccount, AuthorityError> {
    let subject = native
        .verify(Zeroizing::new(USER.into()), deadline())
        .await?;
    native.resolve(subject, deadline()).await
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn native_jit_is_unique_sessionless_and_revocable() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let (federation, view, native) = setup(&f, true).await?;
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_authority.sessions")
        .fetch_one(&f.owner)
        .await?;
    let before = f.events().await?;
    let (a, b) = tokio::join!(admit(&native), admit(&native));
    let a = a?;
    let b = b?;
    assert_eq!(a.account(), b.account());
    assert_eq!(
        f.events().await?,
        before + 1,
        "JIT and identity insertion are one atomic fact"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identity_authority.sessions")
            .fetch_one(&f.owner)
            .await?,
        sessions
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.external_identities WHERE subject=$1",
    )
    .bind(format!("entra:{TENANT}:{USER}"))
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(count, 1);
    native.recheck(b, deadline()).await?;
    f.store
        .set_account_enabled(f.actor().await?, a.account(), false, deadline())
        .await?;
    assert!(native.recheck(a, deadline()).await.is_err());
    assert!(
        admit(&native).await.is_err(),
        "disabled account cannot be re-created by JIT"
    );
    federation
        .enable_provider(f.actor().await?, view.id, view.version, false, deadline())
        .await?;
    assert!(
        native
            .verify(Zeroizing::new(USER.into()), deadline())
            .await
            .is_err()
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn native_unknown_users_and_provider_changes_reject() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let (federation, view, native) = setup(&f, false).await?;
    let before = f.events().await?;
    assert!(admit(&native).await.is_err());
    assert_eq!(before, f.events().await?);
    let subject = native
        .verify(Zeroizing::new(USER.into()), deadline())
        .await?;
    federation
        .enable_provider(f.actor().await?, view.id, view.version, false, deadline())
        .await?;
    assert!(native.resolve(subject, deadline()).await.is_err());
    assert!(
        native
            .verify(Zeroizing::new("invalid-token".into()), deadline())
            .await
            .is_err()
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn native_jit_commit_unknown_does_not_return_proof() -> anyhow::Result<()> {
    use rss_transactional_messaging_postgres::PgTransactionFault;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let (_, _, native) = setup(&f, true).await?;
    let subject = native
        .verify(Zeroizing::new(USER.into()), deadline())
        .await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        native.resolve(subject, deadline()).await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    let proof = admit(&native).await?;
    assert_eq!(proof.claims()?.user, Uuid::parse_str(USER)?);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn browser_and_native_share_one_canonical_identity() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let (federation, view, native) = setup(&f, true).await?;
    let a = admit(&native).await?;
    let state = federation_support::begin(&f, &federation, &view).await?;
    let outcome = federation
        .complete(
            state,
            federation_support::BROWSER.into(),
            Zeroizing::new(USER.into()),
            view.settings.issuer().as_str().into(),
            None,
            deadline(),
        )
        .await?;
    let issued = federation_support::issued(outcome);
    let session = f
        .store
        .inspect_session(
            f.key.tenant,
            federation_support::secret(&issued),
            deadline(),
        )
        .await?;
    assert_eq!(session.account(), a.account());
    let b = admit(&native).await?;
    assert_eq!(b.account(), a.account());
    f.close().await;
    Ok(())
}
