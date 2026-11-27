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
    if let Ok(tenant) = rss_request_context::TenantId::parse(tenant) {
        crate::support::fence(&mut tx, binding(tenant)).await?;
    } else {
        sqlx::query("SELECT set_config('rss.tenant_id','',true)")
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("SET LOCAL ROLE identity_runtime")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}
async fn actor(f: &Fixture, issued: &IssuedSession) -> anyhow::Result<AuthenticatedSession> {
    Ok(f.store
        .inspect_session(
            crate::support::binding(f.key.tenant),
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
            crate::support::binding(f.key.tenant),
            login("admin"),
            password(),
            source(),
            deadline(),
        )
        .await?;
    let bearer_actor = f
        .store
        .inspect_bearer(
            crate::support::binding(f.key.tenant),
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
        crate::support::fence(&mut tx, binding(rss_request_context::TenantId::parse(A)?)).await?;
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
        wait_for_blocked_backend(&f, pid).await?;
        if commit {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        revoke.await??;
        assert!(!accepted(&f, &admission).await?);
    }
    assert_eq!(marker_count(&f).await?, 1);
    // Hold the real revoke after its row update. A forced failure checks rollback as well.
    for commit in [true, false] {
        let issued = f.login().await?;
        let admission = actor(&f, &issued).await?;
        let revoker = actor(&f, &issued).await?;
        let mut controller = f.owner.begin().await?;
        let controller_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *controller)
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(3331,1)")
            .execute(&mut *controller)
            .await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE OR REPLACE FUNCTION public.pause_session_revoke() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN PERFORM pg_advisory_xact_lock(3331,1);
             IF {fail} THEN RAISE EXCEPTION 'rolled back test revocation'; END IF;
             RETURN NEW; END $$;
             CREATE TRIGGER pause_revoke AFTER UPDATE OF revoked_at ON identity_authority.sessions
             FOR EACH ROW EXECUTE FUNCTION public.pause_session_revoke()",fail=!commit
        ))).execute(&f.owner).await?;
        let store = f.store.clone();
        let writer =
            tokio::spawn(async move { store.revoke_current_session(revoker, deadline()).await });
        let writer_pid = wait_for_blocked_backend(&f, controller_pid).await?;
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
        wait_for_blocked_backend(&f, writer_pid).await?;
        controller.commit().await?;
        assert_eq!(writer.await?.is_ok(), commit);
        assert_eq!(reader.await??, !commit);
        assert_eq!(marker_count(&f).await?, if commit { 1 } else { 2 });
        sqlx::query("DROP TRIGGER pause_revoke ON identity_authority.sessions")
            .execute(&f.owner)
            .await?;
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
            crate::support::binding(f.key.tenant),
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
        crate::support::fence(&mut tx, binding(rss_request_context::TenantId::parse(A)?)).await?;
        assert!(
            recheck_authenticated_session_on(&mut tx, &proof)
                .await
                .is_err(),
            "{mutation}"
        );
        tx.rollback().await?;
    }
    f.maintenance
        .recover_local_password(
            crate::support::binding((f.key).tenant),
            f.key,
            password(),
            deadline(),
        )
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
            .local_tx(binding(f.key.tenant), deadline(), move |tx| {
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
        crate::support::fence(&mut tx, binding(rss_request_context::TenantId::parse(A)?)).await?;
        assert!(
            recheck_authenticated_session_on(&mut tx, &proof)
                .await
                .is_err()
        );
        tx.rollback().await?;
    }
    let manager = f.actor().await?;
    let mut c = f.owner.acquire().await?;
    let mut tx = transaction(&mut c, A).await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await?;
    recheck_authenticated_session_on(&mut tx, &proof).await?;
    let revoke = tokio::spawn(async move {
        oidc.enable_provider(manager, provider.id, provider.version, false, deadline())
            .await
    });
    wait_for_blocked_backend(&f, pid).await?;
    tx.commit().await?;
    revoke.await??;
    assert!(!accepted(&f, &proof).await?);
    drop(c);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn host_admission_checks_expiry_after_session_wait() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let issued = f.login().await?;
    let proof = f
        .store
        .inspect_session(
            crate::support::binding(f.key.tenant),
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
        "SELECT session_id FROM identity_authority.sessions WHERE session_id=$1 FOR UPDATE",
    )
    .bind(issued.view().id.as_uuid())
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
    wait_for_blocked_backend(&f, pid).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    writer.rollback().await?;
    assert!(reader.await??);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn independent_subject_completes_while_host_admission_is_open() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let second = f
        .store
        .create_local_account(f.actor().await?, login("second"), password(), deadline())
        .await?;
    let first = f.actor().await?;
    let mut c = f.owner.acquire().await?;
    let mut host = transaction(&mut c, A).await?;
    recheck_authenticated_session_on(&mut host, &first).await?;
    let execution = binding(second.key().tenant);
    // All independent operations have to commit before the first host releases its locks.
    tokio::time::timeout(Duration::from_secs(8), async {
        let issued = f
            .store
            .login_local(
                execution,
                login("second"),
                password(),
                source(),
                None,
                deadline(),
            )
            .await?;
        let proof = f
            .store
            .authenticate_session(
                execution,
                SessionSecret::parse(issued.secret().expose().into())?,
                deadline(),
            )
            .await?;
        let mut other = f.owner.acquire().await?;
        let mut tx = transaction(&mut other, A).await?;
        recheck_authenticated_session_on(&mut tx, &proof).await?;
        tx.commit().await?;
        f.store.revoke_current_session(proof, deadline()).await?;
        f.maintenance
            .recover_local_password(execution, second.key(), password(), deadline())
            .await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    recheck_authenticated_session_on(&mut host, &first).await?;
    host.rollback().await?;
    drop(c);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn cancelled_session_wait_releases_transaction_locks() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let issued = f.login().await?;
    let proof = actor(&f, &issued).await?;
    let mut blocker = f.owner.begin().await?;
    let owner: i32 = sqlx::query_scalar(
        "SELECT pg_backend_pid() FROM identity_authority.sessions WHERE session_id=$1 FOR UPDATE",
    )
    .bind(issued.view().id.as_uuid())
    .fetch_one(&mut *blocker)
    .await?;
    let mut c = f.owner.acquire().await?;
    let mut tx = transaction(&mut c, A).await?;
    let waiter: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await?;
    let observer = f.owner.clone();
    let cancel = async move {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let blocked: bool = sqlx::query_scalar("SELECT $1=ANY(pg_blocking_pids($2))")
                    .bind(owner)
                    .bind(waiter)
                    .fetch_one(&observer)
                    .await?;
                if blocked {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            anyhow::ensure!(
                sqlx::query_scalar::<_, bool>("SELECT pg_cancel_backend($1)")
                    .bind(waiter)
                    .fetch_one(&observer)
                    .await?
            );
            Ok::<_, anyhow::Error>(())
        })
        .await?
    };
    let (res, cancelled) = tokio::join!(recheck_authenticated_session_on(&mut tx, &proof), cancel);
    cancelled?;
    assert!(res.is_err());
    tx.rollback().await?;
    blocker.rollback().await?;
    let mut next = transaction(&mut c, A).await?;
    recheck_authenticated_session_on(&mut next, &proof).await?;
    next.commit().await?;
    drop(c);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn host_deadlock_victim_rolls_back_and_releases_admission() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    sqlx::raw_sql(
        "CREATE TABLE public.host_rows(id int PRIMARY KEY, n int NOT NULL);
        INSERT INTO public.host_rows VALUES(1,0),(2,0);
        GRANT SELECT,UPDATE ON public.host_rows TO identity_runtime",
    )
    .execute(&f.owner)
    .await?;
    let proof = f.actor().await?;
    let mut a = f.owner.acquire().await?;
    let mut b = f.owner.acquire().await?;
    let mut left = transaction(&mut a, A).await?;
    let mut right = transaction(&mut b, A).await?;
    recheck_authenticated_session_on(&mut left, &proof).await?;
    recheck_authenticated_session_on(&mut right, &proof).await?;
    let bump = "UPDATE public.host_rows SET n=n+1 WHERE id=$1";
    sqlx::query(bump).bind(1).execute(&mut *left).await?;
    sqlx::query(bump).bind(2).execute(&mut *right).await?;
    let settle = async |mut tx: Transaction<'_, Postgres>, id: i32| -> anyhow::Result<bool> {
        match sqlx::query(bump).bind(id).execute(&mut *tx).await {
            Ok(_) => {
                tx.commit().await?;
                Ok(true)
            }
            Err(e) => {
                anyhow::ensure!(
                    e.as_database_error().and_then(|db| db.code()).as_deref() == Some("40P01")
                );
                tx.rollback().await?;
                Ok(false)
            }
        }
    };
    let (l, r) = tokio::try_join!(settle(left, 2), settle(right, 1))?;
    assert_ne!(l, r);
    let sum: i64 = sqlx::query_scalar("SELECT sum(n) FROM public.host_rows")
        .fetch_one(&f.owner)
        .await?;
    assert_eq!(sum, 2);
    f.store.revoke_current_session(proof, deadline()).await?;
    drop((a, b));
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn host_settlement_orders_account_eligibility_changes() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    for operation in ["password", "disable", "membership"] {
        let subject = f
            .store
            .create_local_account(f.actor().await?, login(operation), password(), deadline())
            .await?
            .key();
        let issued = f
            .store
            .login_local(
                binding(subject.tenant),
                login(operation),
                password(),
                source(),
                None,
                deadline(),
            )
            .await?;
        let checked = actor(&f, &issued).await?;
        let manager = f.actor().await?;
        let mut c = f.owner.acquire().await?;
        let mut host = transaction(&mut c, A).await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *host)
            .await?;
        recheck_authenticated_session_on(&mut host, &checked).await?;
        let store = f.store.clone();
        let maintenance = f.maintenance.clone();
        let writer = tokio::spawn(async move {
            match operation {
                "password" => {
                    maintenance
                        .recover_local_password(
                            binding(subject.tenant),
                            subject,
                            password(),
                            deadline(),
                        )
                        .await
                }
                "disable" => {
                    store
                        .set_account_enabled(manager, subject, false, deadline())
                        .await
                }
                _ => {
                    store
                        .set_account_membership(manager, subject, false, deadline())
                        .await
                }
            }
        });
        wait_for_blocked_backend(&f, pid).await?;
        host.rollback().await?;
        writer.await??;
        assert!(!accepted(&f, &checked).await?);
    }
    f.close().await;
    Ok(())
}
