//! Session T2: the authority, real PostgreSQL and durable Outbox share settlement.
#![allow(dead_code)]
mod support;
use rss_identity_core::session::SessionSecret;
use support::*;

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_rotation_and_revocation() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let issued = f
        .store
        .create_session(f.candidate().await?, None, deadline())
        .await?;
    let old = issued.secret().expose().to_owned();
    let candidate = f.candidate().await?;
    let a = f
        .store
        .refresh_session(f.key.tenant, SessionSecret::parse(old.clone())?, deadline());
    let b = f
        .store
        .refresh_session(f.key.tenant, SessionSecret::parse(old.clone())?, deadline());
    let (a, b) = tokio::join!(a, b);
    assert_ne!(a.is_ok(), b.is_ok());
    let next = a.or(b)?;
    assert_eq!(next.view().id, issued.view().id);
    assert_eq!(
        next.view().absolute_expires_at,
        issued.view().absolute_expires_at
    );
    assert!(
        f.store
            .authenticate_session(f.key.tenant, SessionSecret::parse(old)?, deadline())
            .await
            .is_err()
    );
    let auth = f
        .store
        .authenticate_session(
            f.key.tenant,
            SessionSecret::parse(next.secret().expose().into())?,
            deadline(),
        )
        .await?;
    f.store.revoke_all_sessions(auth, deadline()).await?;
    assert!(
        f.store
            .create_session(candidate, None, deadline())
            .await
            .is_err()
    );
    assert!(
        f.store
            .authenticate_session(
                f.key.tenant,
                SessionSecret::parse(next.secret().expose().into())?,
                deadline()
            )
            .await
            .is_err()
    );
    f.close().await;
    Ok(())
}

use rss_identity_core::account::{AccountChange, AccountRuleError};
use rss_identity_postgres::*;
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::{DeliveryBudget, OperationDeadline};
use rss_transactional_messaging_postgres::PgTransactionFault;
use std::time::Duration;
fn secret(s: &IssuedSession) -> SessionSecret {
    SessionSecret::parse(s.secret().expose().into()).unwrap()
}
async fn issue(f: &Fixture) -> anyhow::Result<IssuedSession> {
    f.reset_attempts().await?;
    Ok(f.store
        .create_session(f.candidate().await?, None, deadline())
        .await?)
}
async fn proof(f: &Fixture, s: &IssuedSession) -> anyhow::Result<AuthenticatedSession> {
    Ok(f.store
        .inspect_session(f.key.tenant, secret(s), deadline())
        .await?)
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_isolation_replacement_and_restart() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let first = issue(&f).await?;
    let second = issue(&f).await?;
    let member = f
        .store
        .create_local_account(
            proof(&f, &first).await?,
            login("member"),
            password(),
            rss_identity_postgres::LocalAccountRole::Member,
            deadline(),
        )
        .await?;
    let candidate = f
        .store
        .verify_password(
            f.key.tenant,
            login("member"),
            password(),
            source(),
            deadline(),
        )
        .await?;
    let member_session = f.store.create_session(candidate, None, deadline()).await?;
    assert_eq!(
        member_session.view().absolute_expires_at - member_session.view().auth_time,
        28_800
    );
    assert_eq!(
        first.view().absolute_expires_at - first.view().auth_time,
        14_400
    );
    assert!(
        f.store
            .authenticate_session(TenantId::parse(B)?, secret(&first), deadline())
            .await
            .is_err()
    );
    let page = f
        .store
        .list_sessions(proof(&f, &first).await?, None, 1, deadline())
        .await?;
    assert_eq!(page.sessions.len(), 1);
    let next = f
        .store
        .list_sessions(proof(&f, &first).await?, page.next_cursor, 1, deadline())
        .await?;
    assert_eq!(next.sessions.len(), 1);
    assert!(next.next_cursor.is_none());
    assert_ne!(page.sessions[0].id, next.sessions[0].id);
    assert!(
        page.sessions
            .iter()
            .chain(next.sessions.iter())
            .all(|s| s.id != member_session.view().id)
    );
    assert!(
        f.store
            .list_sessions(proof(&f, &first).await?, None, 101, deadline())
            .await
            .is_err()
    );
    let replacement = f
        .store
        .create_session(
            f.candidate().await?,
            Some(proof(&f, &first).await?),
            deadline(),
        )
        .await?;
    assert_ne!(replacement.view().id, first.view().id);
    assert!(proof(&f, &first).await.is_err());
    f.store
        .revoke_current_session(proof(&f, &replacement).await?, deadline())
        .await?;
    assert!(proof(&f, &replacement).await.is_err());
    assert!(proof(&f, &second).await.is_ok());
    let restarted_runtime = f.additional_runtime().await?;
    let restarted = Authority::connect(
        restarted_runtime.clone(),
        std::sync::Arc::new(rss_identity_core::account::PasswordKdf::new()),
        deployment_identity(),
        DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )?,
        f.system_key.tenant,
        AuthorityProfile::Runtime,
        deadline(),
    )
    .await?;
    assert!(
        restarted
            .authenticate_session(f.key.tenant, secret(&replacement), deadline())
            .await
            .is_err()
    );
    assert!(
        restarted
            .authenticate_session(f.key.tenant, secret(&second), deadline())
            .await
            .is_ok()
    );
    f.store
        .revoke_all_sessions(proof(&f, &second).await?, deadline())
        .await?;
    assert!(
        restarted
            .authenticate_session(f.key.tenant, secret(&second), deadline())
            .await
            .is_err()
    );
    assert_eq!(
        f.store
            .authenticate_session(f.key.tenant, secret(&member_session), deadline())
            .await?
            .account(),
        member.key()
    );
    restarted_runtime.close().await;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_account_changes_fence_racing_credentials() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let member = f
        .store
        .create_local_account(
            f.actor().await?,
            login("member"),
            password(),
            rss_identity_postgres::LocalAccountRole::Member,
            deadline(),
        )
        .await?;
    for change in [
        AccountChange::Password(password()),
        AccountChange::Enabled(false),
        AccountChange::Membership(false),
        AccountChange::Administrator(true),
        AccountChange::Administrator(false),
    ] {
        f.reset_attempts().await?;
        let c = f
            .store
            .verify_password(
                f.key.tenant,
                login("member"),
                password(),
                source(),
                deadline(),
            )
            .await?;
        let issued = f.store.create_session(c, None, deadline()).await?;
        let pending = f
            .store
            .verify_password(
                f.key.tenant,
                login("member"),
                password(),
                source(),
                deadline(),
            )
            .await?;
        let actor = f.actor().await?;
        let (rotation, change) = tokio::join!(
            f.store
                .refresh_session(f.key.tenant, secret(&issued), deadline()),
            support::apply_change(&f.store, actor, member.key(), change, deadline())
        );
        change?;
        assert!(
            f.store
                .authenticate_session(f.key.tenant, secret(&issued), deadline())
                .await
                .is_err()
        );
        if let Ok(rotated) = rotation {
            assert!(
                f.store
                    .authenticate_session(f.key.tenant, secret(&rotated), deadline())
                    .await
                    .is_err()
            );
        }
        assert!(
            f.store
                .create_session(pending, None, deadline())
                .await
                .is_err()
        );
        support::apply_change(
            &f.store,
            f.actor().await?,
            member.key(),
            AccountChange::Enabled(true),
            deadline(),
        )
        .await?;
        support::apply_change(
            &f.store,
            f.actor().await?,
            member.key(),
            AccountChange::Membership(true),
            deadline(),
        )
        .await?;
        assert!(
            f.store
                .authenticate_session(f.key.tenant, secret(&issued), deadline())
                .await
                .is_err()
        );
    }
    let recovery = issue(&f).await?;
    f.maintenance
        .recover_administrator(f.key, password(), deadline())
        .await?;
    assert!(proof(&f, &recovery).await.is_err());
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_settlement_and_event_failure_are_atomic() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let candidate = f.candidate().await?;
    let before = f.events().await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        f.store.create_session(candidate, None, deadline()).await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    assert_eq!(f.events().await?, before + 1);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.sessions WHERE tenant_id=$1::uuid",
    )
    .bind(A)
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(count, 1);
    let live = issue(&f).await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        f.store
            .refresh_session(f.key.tenant, secret(&live), deadline())
            .await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    assert!(proof(&f, &live).await.is_err());
    let live = issue(&f).await?;
    let before = f.events().await?;
    sqlx::raw_sql("CREATE FUNCTION public.reject_session_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'session secret marker'; END $$; CREATE TRIGGER reject_session_event BEFORE INSERT ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.reject_session_event();").execute(&f.owner).await?;
    let candidate = f.candidate().await?;
    assert!(matches!(
        f.store.create_session(candidate, None, deadline()).await,
        Err(AuthorityError::RolledBack(_))
    ));
    let failure = f
        .store
        .refresh_session(f.key.tenant, secret(&live), deadline())
        .await;
    assert!(matches!(failure, Err(AuthorityError::RolledBack(_))));
    assert!(!format!("{failure:?}").contains("session secret marker"));
    assert!(
        f.store
            .revoke_current_session(proof(&f, &live).await?, deadline())
            .await
            .is_err()
    );
    assert!(
        f.store
            .revoke_all_sessions(proof(&f, &live).await?, deadline())
            .await
            .is_err()
    );
    assert!(proof(&f, &live).await.is_ok());
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::RollbackFailedAfterAck);
    assert!(matches!(
        f.store
            .refresh_session(f.key.tenant, secret(&live), deadline())
            .await,
        Err(AuthorityError::RollbackFailed(_))
    ));
    assert_eq!(f.events().await?, before);
    sqlx::query("DROP TRIGGER reject_session_event ON rss_transactional_messaging.outbox")
        .execute(&f.owner)
        .await?;
    let auth = proof(&f, &live).await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        f.store.revoke_all_sessions(auth, deadline()).await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    assert!(proof(&f, &live).await.is_err());
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT envelope::text FROM rss_transactional_messaging.outbox")
            .fetch_all(&f.owner)
            .await?;
    for raw in rows {
        let envelope: serde_json::Value = serde_json::from_str(&raw)?;
        let bytes: Vec<u8> = serde_json::from_value(envelope["payload"].clone())?;
        let body = String::from_utf8(bytes)?;
        assert!(!body.contains(live.secret().expose()));
        assert!(!body.contains(PASSWORD));
        if envelope["route"] == "session.changed" {
            let payload: serde_json::Value = serde_json::from_str(&body)?;
            assert_eq!(envelope["contract"], "identity.session.security");
            assert_eq!(payload.as_object().unwrap().len(), 6);
            for banned in ["token", "cookie", "password", "hash", "verifier", "code"] {
                assert!(!body.contains(banned));
            }
        }
    }
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_expiry_deadline_permissions_and_overflow() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let live = issue(&f).await?;
    assert!(
        f.maintenance
            .authenticate_session(f.key.tenant, secret(&live), deadline())
            .await
            .is_err()
    );
    let short = f
        .store
        .inspect_session(
            f.key.tenant,
            secret(&live),
            OperationDeadline::from_remaining(Duration::from_millis(100)),
        )
        .await?;
    tokio::time::sleep(Duration::from_millis(110)).await;
    assert!(
        f.store
            .revoke_all_sessions(short, deadline())
            .await
            .is_err()
    );
    assert!(proof(&f, &live).await.is_ok());
    let mut lock = f.owner.begin().await?;
    sqlx::query(
        "SELECT tenant_id FROM identity_authority.guard WHERE tenant_id=$1::uuid FOR UPDATE",
    )
    .bind(A)
    .fetch_one(&mut *lock)
    .await?;
    assert!(
        f.store
            .authenticate_session(
                f.key.tenant,
                secret(&live),
                OperationDeadline::from_remaining(Duration::from_millis(50))
            )
            .await
            .is_err()
    );
    lock.rollback().await?;
    assert!(proof(&f, &live).await.is_ok());
    sqlx::raw_sql("UPDATE identity_authority.sessions SET auth_time=floor(extract(epoch FROM clock_timestamp()))::bigint-100, idle_expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint, absolute_expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint-100+14400").execute(&f.owner).await?;
    assert!(proof(&f, &live).await.is_err());
    let live = issue(&f).await?;
    sqlx::query("UPDATE identity_authority.sessions SET auth_time=1,idle_expires_at=14401,absolute_expires_at=14401 WHERE session_id=$1::uuid").bind(live.view().id.to_string()).execute(&f.owner).await?;
    assert!(proof(&f, &live).await.is_err());
    let live = issue(&f).await?;
    sqlx::raw_sql("UPDATE identity_authority.accounts SET auth_epoch=9223372036854775807; UPDATE identity_authority.sessions SET auth_epoch=9223372036854775807").execute(&f.owner).await?;
    let before = f.events().await?;
    assert!(matches!(
        f.store
            .revoke_all_sessions(proof(&f, &live).await?, deadline())
            .await,
        Err(AuthorityError::RuleRejected(
            AccountRuleError::EpochExhausted
        ))
    ));
    assert_eq!(f.events().await?, before);
    assert!(proof(&f, &live).await.is_ok());
    for (break_it, restore) in [
        (
            "ALTER TABLE identity_authority.sessions DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE identity_authority.sessions ENABLE ROW LEVEL SECURITY",
        ),
        (
            "GRANT SELECT ON identity_authority.sessions TO PUBLIC",
            "REVOKE SELECT ON identity_authority.sessions FROM PUBLIC",
        ),
    ] {
        sqlx::raw_sql(break_it).execute(&f.owner).await?;
        if break_it.contains("PUBLIC") {
            assert!(
                Authority::connect(
                    f.maintenance_runtime.clone(),
                    std::sync::Arc::new(rss_identity_core::account::PasswordKdf::new()),
                    deployment_identity(),
                    DeliveryBudget::new(
                        Duration::from_secs(60),
                        Duration::from_secs(5),
                        Duration::from_secs(5),
                        Duration::from_secs(5)
                    )?,
                    f.system_key.tenant,
                    AuthorityProfile::Maintenance,
                    deadline()
                )
                .await
                .is_err()
            );
        } else {
            assert!(f.probe(AuthorityProfile::Runtime).await.is_err());
        }
        sqlx::raw_sql(restore).execute(&f.owner).await?;
    }
    assert!(f.probe(AuthorityProfile::Runtime).await.is_ok());
    f.runtime.close().await;
    assert!(proof(&f, &live).await.is_err());
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_logout_rotation_races_and_invalid_storage() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    for all in [false, true] {
        let live = issue(&f).await?;
        let actor = proof(&f, &live).await?;
        let revoke = async {
            if all {
                f.store.revoke_all_sessions(actor, deadline()).await
            } else {
                f.store.revoke_current_session(actor, deadline()).await
            }
        };
        let (rotation, revoke) = tokio::join!(
            f.store
                .refresh_session(f.key.tenant, secret(&live), deadline()),
            revoke
        );
        assert!(rotation.is_ok() || revoke.is_ok());
        assert!(proof(&f, &live).await.is_err());
        if let Ok(rotated) = rotation {
            // If revocation confirmed, no concurrently rotated value can authenticate.
            assert_eq!(proof(&f, &rotated).await.is_ok(), revoke.is_err());
        }
    }
    let live = issue(&f).await?;
    sqlx::query("UPDATE identity_authority.sessions SET absolute_expires_at=auth_time+28800 WHERE session_id=$1::uuid").bind(live.view().id.to_string()).execute(&f.owner).await?;
    assert!(proof(&f, &live).await.is_err());
    sqlx::query("UPDATE identity_authority.sessions SET absolute_expires_at=auth_time+14400 WHERE session_id=$1::uuid").bind(live.view().id.to_string()).execute(&f.owner).await?;
    assert!(proof(&f, &live).await.is_ok());
    // A constraint with the right count/name but weakened meaning must fail the probe.
    sqlx::raw_sql("ALTER TABLE identity_authority.sessions DROP CONSTRAINT session_lifetime; ALTER TABLE identity_authority.sessions ADD CONSTRAINT session_lifetime CHECK(auth_time <= idle_expires_at)").execute(&f.owner).await?;
    assert!(f.probe(AuthorityProfile::Runtime).await.is_err());
    sqlx::raw_sql("ALTER TABLE identity_authority.sessions DROP CONSTRAINT session_lifetime; ALTER TABLE identity_authority.sessions ADD CONSTRAINT session_lifetime CHECK(auth_time < idle_expires_at AND idle_expires_at <= absolute_expires_at)").execute(&f.owner).await?;
    assert!(f.probe(AuthorityProfile::Runtime).await.is_ok());
    let before = f.events().await?;
    let candidate = f.candidate().await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitPending);
    assert!(
        f.store
            .create_session(
                candidate,
                None,
                OperationDeadline::from_remaining(Duration::from_millis(50))
            )
            .await
            .is_err()
    );
    assert_eq!(f.events().await?, before);
    f.close().await;
    Ok(())
}

async fn expect_session_event(
    f: &Fixture,
    action: &str,
    id: rss_identity_core::SessionId,
    replaced: Option<rss_identity_core::SessionId>,
    epoch: i64,
) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};
    let raw: String = sqlx::query_scalar(
        "SELECT envelope::text FROM rss_transactional_messaging.outbox ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(&f.owner)
    .await?;
    let envelope: serde_json::Value = serde_json::from_str(&raw)?;
    let bytes: Vec<u8> = serde_json::from_value(envelope["payload"].clone())?;
    let payload: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        payload,
        serde_json::json!({"action":action,"tenant":A,"principal":f.key.principal.as_uuid(),"session_id":id,"replaced_session_id":replaced,"epoch":epoch})
    );
    assert_eq!(
        envelope["schema"],
        format!(
            "sha256:{:x}",
            Sha256::digest(include_str!("../src/session-security-event-v1.json"))
        )
    );
    assert_eq!(envelope["route"], "session.changed");
    assert_eq!(envelope["contract"], "identity.session.security");
    Ok(())
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn session_events_match_committed_operations() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let baseline = f.events().await?;
    let first = issue(&f).await?;
    expect_session_event(&f, "created", first.view().id, None, 1).await?;
    let rotated = f
        .store
        .refresh_session(f.key.tenant, secret(&first), deadline())
        .await?;
    expect_session_event(&f, "refreshed", rotated.view().id, None, 1).await?;
    let replacement = f
        .store
        .create_session(
            f.candidate().await?,
            Some(proof(&f, &rotated).await?),
            deadline(),
        )
        .await?;
    expect_session_event(
        &f,
        "created",
        replacement.view().id,
        Some(rotated.view().id),
        1,
    )
    .await?;
    f.store
        .revoke_current_session(proof(&f, &replacement).await?, deadline())
        .await?;
    expect_session_event(&f, "revoked", replacement.view().id, None, 1).await?;
    let live = issue(&f).await?;
    f.store
        .revoke_all_sessions(proof(&f, &live).await?, deadline())
        .await?;
    expect_session_event(&f, "all_revoked", live.view().id, None, 2).await?;
    assert_eq!(f.events().await?, baseline + 6);
    f.close().await;
    Ok(())
}
