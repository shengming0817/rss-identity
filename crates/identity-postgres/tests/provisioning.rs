//! Actual least-privilege provisioning and host transaction settlement.
mod support;
use rss_identity_core::{account::PasswordKdf, session::SessionSecret};
use rss_identity_postgres::*;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgError;
use std::sync::Arc;
use support::*;

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn provisioned_account_and_event_share_host_commit_and_revalidate_source()
-> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    // Each fixture gets its own role, avoiding shared role mutations across concurrent tests.
    let role = format!("provision_{}", uuid::Uuid::new_v4().simple());
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS"
    )))
    .execute(&f.owner)
    .await?;
    let mut conn = f.owner.acquire().await?;
    grant_profile(&mut conn, &role, AuthorityProfile::Provisioning).await?;
    drop(conn);
    let runtime = f.runtime_as(&role).await?;
    let kdf = Arc::new(PasswordKdf::new());
    let service = Arc::new(
        AccountProvisioner::connect(
            runtime.clone(),
            kdf.clone(),
            f.config(),
            f.key.tenant,
            f.policy.clone(),
            deadline(),
        )
        .await?,
    );
    assert!(
        AccountProvisioner::connect(
            f.runtime.clone(),
            kdf.clone(),
            f.config(),
            f.key.tenant,
            f.policy.clone(),
            deadline()
        )
        .await
        .is_err()
    );
    let target = TenantId::parse(B)?;
    let actor = Arc::new(f.actor().await?);
    let prepared = service
        .prepare_local_account(login("new-admin"), password(), deadline())
        .await?;
    let svc = service.clone();
    let who = actor.clone();
    let outcome = runtime
        .local_tx(target, deadline(), move |tx| {
            Box::pin(async move {
                let account = svc
                    .create_local_account_in(tx, who, prepared)
                    .await
                    .map_err(|e| PgError::from(sqlx::Error::Protocol(e.to_string())))?;
                let scope: String = tx
                    .with_connection(|c| {
                        Box::pin(async move {
                            sqlx::query_scalar("SELECT current_setting('rss.tenant_id')")
                                .fetch_one(c)
                                .await
                        })
                    })
                    .await?;
                assert_eq!(scope, B);
                Ok(account)
            })
        })
        .await;
    let account = outcome
        .fold(
            Ok,
            |e| Err(e.to_string()),
            |e| Err(e.to_string()),
            |e| Err(e.to_string()),
            |e| Err(e.to_string()),
            |_| Err("fenced".into()),
        )
        .map_err(anyhow::Error::msg)?;
    assert_eq!(account.key().tenant, target);
    let event: serde_json::Value = sqlx::query_scalar("SELECT envelope FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND envelope->>'contract'='identity.account.provisioning'")
        .bind(B).fetch_one(&f.owner).await?;
    assert_eq!(event["route"], "account.provisioned");
    let bytes: Vec<u8> = serde_json::from_value(event["payload"].clone())?;
    let payload: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(payload["actor_tenant"], A);
    assert_eq!(payload["actor_instance"], f.instance.to_string());
    assert_eq!(payload["actor"], f.key.principal.as_uuid().to_string());
    assert_eq!(payload["tenant"], B);
    assert!(payload.get("password").is_none());
    let issued = f
        .store
        .login_local(
            target,
            login("new-admin"),
            password(),
            source(),
            None,
            deadline(),
        )
        .await?;
    let proof = f
        .store
        .inspect_session(
            target,
            SessionSecret::parse(issued.secret().expose().into())?,
            deadline(),
        )
        .await?;
    assert_eq!(proof.account(), account.key());
    // A host failure rolls back the account and its security event together.
    let prepared = service
        .prepare_local_account(login("rolled-back"), password(), deadline())
        .await?;
    let svc = service.clone();
    let who = actor.clone();
    let outcome = runtime
        .local_tx(target, deadline(), move |tx| {
            Box::pin(async move {
                svc.create_local_account_in(tx, who, prepared)
                    .await
                    .map_err(|e| PgError::from(sqlx::Error::Protocol(e.to_string())))?;
                Err::<(), PgError>(sqlx::Error::Protocol("host write failed".into()).into())
            })
        })
        .await;
    assert!(outcome.fold(
        |_| false,
        |_| false,
        |_| true,
        |_| false,
        |_| false,
        |_| false
    ));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.local_credentials WHERE login_key='rolled-back'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(count, 0);
    f.policy.revoke(f.key);
    let svc = service.clone();
    let who = actor.clone();
    let outcome = runtime
        .local_tx(target, deadline(), move |tx| {
            Box::pin(async move {
                assert!(svc.authorize_in(tx, who).await.is_err());
                let scope: String = tx
                    .with_connection(|c| {
                        Box::pin(async move {
                            sqlx::query_scalar("SELECT current_setting('rss.tenant_id')")
                                .fetch_one(c)
                                .await
                        })
                    })
                    .await?;
                assert_eq!(scope, B);
                Ok(())
            })
        })
        .await;
    assert!(outcome.fold(
        |_| true,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false
    ));
    f.policy.allow(f.key);
    f.store
        .revoke_current_session(f.actor().await?, deadline())
        .await?;
    let svc = service.clone();
    let who = actor.clone();
    let outcome = runtime
        .local_tx(target, deadline(), move |tx| {
            Box::pin(async move {
                assert!(svc.authorize_in(tx, who).await.is_err());
                Ok(())
            })
        })
        .await;
    assert!(outcome.fold(
        |_| true,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false
    ));
    runtime.close().await;
    kdf.close();
    kdf.wait_closed().await;
    f.close().await;
    Ok(())
}
