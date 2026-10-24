//! Host-owned transactions serialize live-session admission with Identity revocation.
mod federation_support;
mod support;
use rss_identity_core::session::{BearerSecret, SessionSecret};
use rss_identity_postgres::*;
use rss_transactional_messaging_postgres::{PgError, PgTransactionFault};
use sqlx::{Connection, PgConnection, Postgres, Transaction};
use std::{sync::Arc, time::Duration};
use support::*;

async fn transaction<'a>(
    c: &'a mut PgConnection,
    tenant: &str,
) -> anyhow::Result<Transaction<'a, Postgres>> {
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL ROLE identity_runtime")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}
async fn actor(f: &Fixture, issued: &IssuedSession) -> anyhow::Result<AuthenticatedSession> {
    Ok(f.store
        .inspect_session(
            f.key.tenant,
            SessionSecret::parse(issued.secret().expose().into())?,
            deadline(),
        )
        .await?)
}
async fn accepted(f: &Fixture, actor: &AuthenticatedSession) -> anyhow::Result<bool> {
    let mut c = f.owner.acquire().await?;
    let mut tx = transaction(&mut c, A).await?;
    let result = recheck_authenticated_session_on(&mut tx, actor)
        .await
        .is_ok();
    tx.rollback().await?;
    Ok(result)
}
async fn marker_table(f: &Fixture) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE TABLE public.host_binding(id integer PRIMARY KEY); GRANT SELECT,INSERT ON public.host_binding TO identity_runtime").execute(&f.owner).await?;
    Ok(())
}
async fn marker_count(f: &Fixture) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM public.host_binding")
            .fetch_one(&f.owner)
            .await?,
    )
}
// Observe a real backend waiting on the exact owner, rather than infer a lock from elapsed time.
async fn waiting(f: &Fixture, blocker: i32) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%identity_authority.guard%')").bind(blocker).fetch_one(&f.owner).await?;
            if blocked { return Ok::<_, anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn host_admission_is_passive_and_transaction_scoped() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    marker_table(&f).await?;
    let cookie = f.login().await?;
    let cookie_actor = actor(&f, &cookie).await?;
    let bearer = f
        .store
        .login_local_bearer(
            f.key.tenant,
            login("admin"),
            password(),
            source(),
            deadline(),
        )
        .await?;
    let bearer_actor = f
        .store
        .inspect_bearer(
            f.key.tenant,
            BearerSecret::parse(bearer.secret().expose().into())?,
            deadline(),
        )
        .await?;
    let before: serde_json::Value = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(s) ORDER BY session_id) FROM identity_authority.sessions s",
    )
    .fetch_one(&f.owner)
    .await?;
    let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_authority.step_up_grants")
        .fetch_one(&f.owner)
        .await?;
    let events = f.events().await?;
    for (index, proof) in [&cookie_actor, &bearer_actor].into_iter().enumerate() {
        let mut c = f.owner.acquire().await?;
        assert!(
            recheck_authenticated_session_on(&mut c, proof)
                .await
                .is_err()
        );
        let mut tx = transaction(&mut c, A).await?;
        recheck_authenticated_session_on(&mut tx, proof).await?;
        sqlx::query("INSERT INTO public.host_binding VALUES($1)")
            .bind(index as i32)
            .execute(&mut *tx)
            .await?;
        if index == 0 {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
    }
    assert_eq!(marker_count(&f).await?, 1);
    let after: serde_json::Value = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(s) ORDER BY session_id) FROM identity_authority.sessions s",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(before, after);
    assert_eq!(f.events().await?, events);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identity_authority.step_up_grants")
            .fetch_one(&f.owner)
            .await?,
        grants
    );
    let mut c = f.owner.acquire().await?;
    for tenant in ["", B] {
        let mut tx = transaction(&mut c, tenant).await?;
        assert!(
            recheck_authenticated_session_on(&mut tx, &cookie_actor)
                .await
                .is_err()
        );
        tx.rollback().await?;
    }
    for isolation in [
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
    ] {
        let mut tx = c.begin().await?;
        sqlx::query(sqlx::AssertSqlSafe(isolation))
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(A)
            .execute(&mut *tx)
            .await?;
        assert!(
            recheck_authenticated_session_on(&mut tx, &cookie_actor)
                .await
                .is_err()
        );
        tx.rollback().await?;
    }
    drop(c);
    let other = Fixture::new().await?;
    other.bootstrap().await?;
    assert!(!accepted(&other, &cookie_actor).await?);
    other.close().await;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn host_admission_serializes_commit_rollback_and_revocation() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    marker_table(&f).await?;
    // Admission wins. The real public revoke operation must wait for either host outcome.
    for commit in [true, false] {
        let issued = f.login().await?;
        let admission = actor(&f, &issued).await?;
        let revoke_actor = actor(&f, &issued).await?;
        let mut c = f.owner.acquire().await?;
        let mut tx = transaction(&mut c, A).await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await?;
        recheck_authenticated_session_on(&mut tx, &admission).await?;
        sqlx::query("INSERT INTO public.host_binding VALUES($1)")
            .bind(i32::from(commit))
            .execute(&mut *tx)
            .await?;
        let store = f.store.clone();
        let revoke =
            tokio::spawn(
                async move { store.revoke_current_session(revoke_actor, deadline()).await },
            );
        waiting(&f, pid).await?;
        if commit {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        revoke.await??;
        assert!(!accepted(&f, &admission).await?);
    }
    assert_eq!(marker_count(&f).await?, 1);
    // Revocation wins. Controlled owner SQL holds the same guard before changing session state.
    for commit in [true, false] {
        let issued = f.login().await?;
        let admission = actor(&f, &issued).await?;
        let mut writer = f.owner.begin().await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *writer)
            .await?;
        sqlx::query(
            "SELECT tenant_id FROM identity_authority.guard WHERE tenant_id=$1::uuid FOR UPDATE",
        )
        .bind(A)
        .execute(&mut *writer)
        .await?;
        sqlx::query("UPDATE identity_authority.sessions SET revoked_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE session_id=$1").bind(issued.view().id.as_uuid()).execute(&mut *writer).await?;
        let pool = f.owner.clone();
        let reader = tokio::spawn(async move {
            let mut c = pool.acquire().await?;
            let mut tx = transaction(&mut c, A).await?;
            let admitted = recheck_authenticated_session_on(&mut tx, &admission)
                .await
                .is_ok();
            if admitted {
                sqlx::query("INSERT INTO public.host_binding VALUES(2)")
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
            } else {
                tx.rollback().await?;
            }
            Ok::<_, anyhow::Error>(admitted)
        });
        waiting(&f, pid).await?;
        if commit {
            writer.commit().await?;
        } else {
            writer.rollback().await?;
        }
        assert_eq!(reader.await??, !commit);
        assert_eq!(marker_count(&f).await?, if commit { 1 } else { 2 });
    }
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn host_admission_rejects_stale_credentials_and_subjects() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let issued = f.login().await?;
    let old = actor(&f, &issued).await?;
    let rotated = f
        .store
        .refresh_session(
            f.key.tenant,
            SessionSecret::parse(issued.secret().expose().into())?,
            deadline(),
        )
        .await?;
    assert!(!accepted(&f, &old).await?);
    let current = actor(&f, &rotated).await?;
    f.store
        .revoke_all_sessions(actor(&f, &rotated).await?, deadline())
        .await?;
    assert!(!accepted(&f, &current).await?);
    // Restore exact rows after each isolated mutation, so each case proves its own predicate.
    let issued = f.login().await?;
    let proof = actor(&f, &issued).await?;
    for mutation in [
        "UPDATE identity_authority.accounts SET enabled=false",
        "UPDATE identity_authority.accounts SET auth_epoch=auth_epoch+1",
        "UPDATE identity_authority.memberships SET active=false",
        "UPDATE identity_authority.memberships SET epoch=epoch+1",
        "UPDATE identity_authority.sessions SET issued_at=issued_at-1000,local_authenticated_at=local_authenticated_at-1000,idle_expires_at=idle_expires_at-1000,absolute_expires_at=absolute_expires_at-1000",
        "UPDATE identity_authority.sessions SET issued_at=issued_at-15000,local_authenticated_at=local_authenticated_at-15000,idle_expires_at=idle_expires_at-15000,absolute_expires_at=absolute_expires_at-15000",
    ] {
        let mut c = f.owner.acquire().await?;
        let mut tx = c.begin().await?;
        sqlx::query(sqlx::AssertSqlSafe(mutation))
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(A)
            .execute(&mut *tx)
            .await?;
        assert!(
            recheck_authenticated_session_on(&mut tx, &proof)
                .await
                .is_err(),
            "{mutation}"
        );
        tx.rollback().await?;
    }
    f.maintenance
        .recover_local_password(f.key, password(), deadline())
        .await?;
    assert!(!accepted(&f, &proof).await?);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn host_admission_preserves_unknown_and_failed_settlement() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    marker_table(&f).await?;
    let issued = f.login().await?;
    let proof = Arc::new(actor(&f, &issued).await?);
    for (id, fault) in [
        (1, PgTransactionFault::CommitUnknownAfterAck),
        (2, PgTransactionFault::RollbackFailedAfterAck),
    ] {
        f.runtime.inject_next_transaction_fault(fault);
        let proof = proof.clone();
        let outcome = f
            .runtime
            .local_tx(f.key.tenant, deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(
                            async move { Ok(recheck_authenticated_session_on(c, &proof).await) },
                        )
                    })
                    .await??;
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            sqlx::query("INSERT INTO public.host_binding VALUES($1)")
                                .bind(id)
                                .execute(c)
                                .await?;
                            Ok(())
                        })
                    })
                    .await?;
                    if id == 2 {
                        return Err(PgError::from(sqlx::Error::Protocol(
                            "host rejected effect".into(),
                        )));
                    }
                    Ok(())
                })
            })
            .await;
        let classification = outcome.fold(
            |_| "committed",
            |_| "not-started",
            |_| "rolled-back",
            |_| "rollback-failed",
            |_| "commit-unknown",
            |_| "fenced",
        );
        assert_eq!(
            classification,
            if id == 1 {
                "commit-unknown"
            } else {
                "rollback-failed"
            }
        );
    }
    assert_eq!(marker_count(&f).await?, 1);
    assert!(accepted(&f, &proof).await?);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn host_admission_rechecks_federated_source() -> anyhow::Result<()> {
    use federation_support::*;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let oidc = service(&f, ScriptedOidc::new());
    let provider = enabled(&f, &oidc).await?;
    let login = issued(finish(&oidc, begin(&f, &oidc, &provider).await?, "host-user").await?);
    let proof = self::actor(&f, &login).await?;
    assert!(accepted(&f, &proof).await?);
    for mutation in [
        "UPDATE identity_authority.providers SET enabled=false",
        "UPDATE identity_authority.providers SET config_version=config_version+1",
        "UPDATE identity_authority.providers SET revocation_epoch=revocation_epoch+1",
    ] {
        let mut c = f.owner.acquire().await?;
        let mut tx = c.begin().await?;
        sqlx::query(sqlx::AssertSqlSafe(mutation))
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(A)
            .execute(&mut *tx)
            .await?;
        assert!(
            recheck_authenticated_session_on(&mut tx, &proof)
                .await
                .is_err()
        );
        tx.rollback().await?;
    }
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn host_admission_checks_expiry_after_guard_wait() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let issued = f.login().await?;
    let proof = f
        .store
        .inspect_session(
            f.key.tenant,
            SessionSecret::parse(issued.secret().expose().into())?,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                Duration::from_secs(2),
            ),
        )
        .await?;
    let mut writer = f.owner.begin().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await?;
    sqlx::query(
        "SELECT tenant_id FROM identity_authority.guard WHERE tenant_id=$1::uuid FOR UPDATE",
    )
    .bind(A)
    .execute(&mut *writer)
    .await?;
    let pool = f.owner.clone();
    let reader = tokio::spawn(async move {
        let mut c = pool.acquire().await?;
        let mut tx = transaction(&mut c, A).await?;
        let result = recheck_authenticated_session_on(&mut tx, &proof).await;
        tx.rollback().await?;
        Ok::<_, anyhow::Error>(result.is_err())
    });
    waiting(&f, pid).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    writer.rollback().await?;
    assert!(reader.await??);
    f.close().await;
    Ok(())
}
