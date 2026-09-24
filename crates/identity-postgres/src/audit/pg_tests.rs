use super::*;
use crate::support;
use rss_audit_postgres::{Control, Cursor, Integrity, ReadLimit};
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    inbox::{IdempotencyDisposition, InboxStore},
    transaction::{ConsumerTx, verify_ingress},
};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgTransactionFault};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use support::{A, B, Fixture, SYSTEM};
use tokio_util::sync::CancellationToken;
struct Setup {
    f: Fixture,
    runtime: Arc<PgRuntime>,
    pool: PgPool,
    audit: Arc<PgAudit>,
    worker: AuditDelivery,
}
impl Setup {
    async fn new() -> anyhow::Result<Self> {
        let f = Fixture::new().await?;
        sqlx::raw_sql("DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='identity_audit_test_owner') THEN CREATE ROLE identity_audit_test_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE identity_audit_test LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; END IF; END $$").execute(&f.owner).await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "GRANT CREATE ON DATABASE {} TO identity_audit_test_owner",
            f.database
        )))
        .execute(&f.owner)
        .await?;
        let mut c = f.owner.acquire().await?;
        sqlx::raw_sql("SET ROLE identity_audit_test_owner")
            .execute(&mut *c)
            .await?;
        sqlx::raw_sql(rss_audit_postgres::MIGRATION_SQL)
            .execute(&mut *c)
            .await?;
        sqlx::raw_sql("RESET ROLE; GRANT USAGE ON SCHEMA rss_audit TO identity_audit_test; GRANT SELECT ON ALL TABLES IN SCHEMA rss_audit TO identity_audit_test; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_audit TO identity_audit_test;").execute(&mut *c).await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(
            include_str!("../../../../app/identity/src/audit-grants.sql")
                .replace("{role}", "identity_audit_test"),
        ))
        .execute(&mut *c)
        .await?;
        drop(c);
        let binding = ExecutionBinding::new(
            StorageIdentity::new([1; 16], [2; 16])?,
            [SYSTEM, A, B]
                .into_iter()
                .map(|t| Ok((TenantId::parse(t)?, Epoch::new(1)?)))
                .collect::<anyhow::Result<Vec<_>>>()?,
        )?;
        let runtime = Arc::new(
            PgRuntime::connect(
                PgConfig::new_for_test_plaintext(
                    "127.0.0.1",
                    f.port,
                    &f.database,
                    "identity_audit_test",
                    PgPassword::new("fixture-only"),
                ),
                Timer,
                binding,
            )
            .await?,
        );
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(
                PgConnectOptions::new()
                    .host("127.0.0.1")
                    .port(f.port)
                    .database(&f.database)
                    .username("identity_audit_test")
                    .password("fixture-only"),
            )
            .await?;
        let cancel = CancellationToken::new();
        let control = Control::new(
            &Timer,
            Deadline::from_timeout(&Timer, Duration::from_secs(10))?,
            &cancel,
        );
        let audit = Arc::new(PgAudit::new(pool.clone(), Integrity::Plain, &control).await?);
        let worker = AuditDelivery::new(
            runtime.clone(),
            audit.clone(),
            f.instance,
            [SYSTEM, A, B]
                .into_iter()
                .map(|t| TenantId::parse(t).unwrap())
                .collect(),
            DeliveryBudget::new(
                Duration::from_secs(60),
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(5),
            )?,
        )?;
        Ok(Self {
            f,
            runtime,
            pool,
            audit,
            worker,
        })
    }
    async fn count(&self, tenant: &str) -> anyhow::Result<usize> {
        let cancel = CancellationToken::new();
        let control = Control::new(
            &Timer,
            Deadline::from_timeout(&Timer, Duration::from_secs(10))?,
            &cancel,
        );
        let page = self
            .audit
            .read_page(
                Cursor::start(TenantId::parse(tenant)?),
                ReadLimit::new(100, 131072)?,
                &control,
            )
            .await
            .fold(
                |v| Ok(v.into_value()),
                |_| Err(anyhow::anyhow!("read not started")),
                |_| Err(anyhow::anyhow!("read rollback")),
                |_| Err(anyhow::anyhow!("rollback failed")),
                |_| Err(anyhow::anyhow!("commit unknown")),
                |_| Err(anyhow::anyhow!("fenced")),
            )?;
        Ok(page.records().len())
    }
}
#[tokio::test]
#[ignore = "requires real PG"]
async fn authentication_outbox_reaches_audit_and_recovers() -> anyhow::Result<()> {
    let s = Setup::new().await?;
    s.f.bootstrap().await?;
    let issued = s.f.login().await?;
    let secret = issued.secret().expose().to_owned();
    let actor =
        s.f.store
            .inspect_session(
                s.f.key.tenant,
                rss_identity_core::session::SessionSecret::parse(secret.clone())?,
                support::deadline(),
            )
            .await?;
    s.f.store
        .revoke_all_sessions(actor, support::deadline())
        .await?;
    assert_eq!(s.count(A).await?, 0);
    let limit = RelayBatchLimit::new(std::num::NonZeroUsize::new(32).unwrap())?;
    for _ in 0..3 {
        s.worker.run_once(limit).await?;
    }
    assert_eq!(s.count(A).await?, 3);
    assert_eq!(s.count(SYSTEM).await?, 1);
    assert_eq!(s.count(B).await?, 0);
    let bytes: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT canonical FROM rss_audit.records ORDER BY position")
            .fetch_all(&s.f.owner)
            .await?;
    assert!(
        bytes
            .iter()
            .all(|b| !b.windows(secret.len()).any(|w| w == secret.as_bytes()))
    );
    assert!(bytes.iter().any(|b| {
        rss_audit_core::decode_untrusted(b)
            .unwrap()
            .event()
            .facts()
            .resource()
            .kind()
            .as_str()
            == "account_sessions"
    }));
    // Lost source acknowledgement: original identity, original payload, fresh relay ownership.
    manipulate(&s.f.owner,"UPDATE rss_transactional_messaging.outbox SET status='pending' WHERE status='published' AND tenant_id=$1::uuid").await?;
    for _ in 0..3 {
        s.worker.run_once(limit).await?;
    }
    assert_eq!(s.count(A).await?, 3);
    let forbidden:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='identity_authority' AND c.relname='local_credentials' AND has_table_privilege(current_user,c.oid,'SELECT')) OR has_table_privilege(current_user,'rss_audit.records','INSERT') OR has_table_privilege(current_user,'rss_transactional_messaging.outbox','UPDATE')").fetch_one(&s.pool).await?;
    assert!(!forbidden);
    s.runtime.close().await;
    s.pool.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PG"]
async fn conflicts_rollback_unknown_commit_and_lease_loss() -> anyhow::Result<()> {
    let s = Setup::new().await?;
    let body = serde_json::json!({"action":"created","tenant":A,"principal":B,"session_id":SYSTEM,"replaced_session_id":null,"epoch":1});
    let message = super::tests::envelope("session", body.clone());
    let p = &s.worker.publisher;
    let meta = message.metadata();
    let sub = SubscriptionIdentity::new(
        meta.domain().clone(),
        meta.route().clone(),
        meta.contract().clone(),
    );
    let binding = verify_ingress(&p.validator, p.group.clone(), &sub, &message)
        .map_err(|_| anyhow::anyhow!("ingress"))?;
    let IdempotencyDisposition::Acquired(claim) = p
        .inbox
        .claim(binding.identity(), support::deadline())
        .await?
    else {
        anyhow::bail!("expected claim")
    };
    s.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let result =
        p.tx.execute(
            &claim,
            &message,
            binding.receipt_intent(),
            support::deadline(),
        )
        .await;
    assert!(result.fold(|_| false, |_| false, |_| false, || false, || true, || false));
    assert_eq!(s.count(A).await?, 1);
    assert!(matches!(
        p.publish(&message, support::deadline()).await,
        PublishOutcome::Confirmed(())
    ));
    let mut conflict = body.clone();
    conflict["epoch"] = serde_json::json!(2);
    assert!(matches!(
        p.publish(
            &super::tests::envelope("session", conflict),
            support::deadline()
        )
        .await,
        PublishOutcome::DefinitelyNotPublished(_)
    ));
    // Bad payload/schema never receives success, including a repeated terminal rejection.
    let mut bad = body.clone();
    bad["token"] = serde_json::json!("never-store-this");
    let bad = MessageEnvelope::new(
        rss_transactional_messaging::message::MessageId::parse("bad-schema")?,
        meta.clone(),
        serde_json::to_vec(&bad)?,
    );
    for _ in 0..2 {
        assert!(matches!(
            p.publish(&bad, support::deadline()).await,
            PublishOutcome::DefinitelyNotPublished(_)
        ));
    }
    assert_eq!(s.count(A).await?, 1);
    // New identity: a lost Inbox lease must roll back both the append and receipt.
    let lost = MessageEnvelope::new(
        rss_transactional_messaging::message::MessageId::parse("lease-lost")?,
        meta.clone(),
        message.payload().clone(),
    );
    let b = verify_ingress(&p.validator, p.group.clone(), &sub, &lost)
        .map_err(|_| anyhow::anyhow!("ingress"))?;
    let IdempotencyDisposition::Acquired(c) =
        p.inbox.claim(b.identity(), support::deadline()).await?
    else {
        anyhow::bail!("claim")
    };
    manipulate(&s.f.owner,"UPDATE rss_transactional_messaging.inbox SET lease_until=clock_timestamp()-interval '1 second' WHERE message_id='lease-lost' AND tenant_id=$1::uuid").await?;
    assert!(
        p.tx.execute(&c, &lost, b.receipt_intent(), support::deadline())
            .await
            .fold(|_| false, |_| false, |_| false, || false, || false, || true)
    );
    assert_eq!(s.count(A).await?, 1);
    assert!(matches!(
        p.publish(&lost, support::deadline()).await,
        PublishOutcome::Confirmed(())
    ));
    assert_eq!(s.count(A).await?, 2);
    // Storage rejection rolls back Audit and leaves the receipt nonterminal.
    let pending = MessageEnvelope::new(
        rss_transactional_messaging::message::MessageId::parse("rollback")?,
        meta.clone(),
        message.payload().clone(),
    );
    let b = verify_ingress(&p.validator, p.group.clone(), &sub, &pending)
        .map_err(|_| anyhow::anyhow!("ingress"))?;
    let IdempotencyDisposition::Acquired(c) =
        p.inbox.claim(b.identity(), support::deadline()).await?
    else {
        anyhow::bail!("claim")
    };
    s.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitPending);
    let short = OperationDeadline::from_remaining(Duration::from_millis(200));
    assert!(
        p.tx.execute(&c, &pending, b.receipt_intent(), short)
            .await
            .fold(|_| false, |_| false, |_| false, || false, || true, || false)
    );
    assert_eq!(s.count(A).await?, 2);
    manipulate(&s.f.owner,"UPDATE rss_transactional_messaging.inbox SET lease_until=clock_timestamp()-interval '1 second' WHERE message_id='rollback' AND tenant_id=$1::uuid").await?;
    assert!(matches!(
        p.publish(&pending, support::deadline()).await,
        PublishOutcome::Confirmed(())
    ));
    assert_eq!(s.count(A).await?, 3);
    s.runtime.close().await;
    s.pool.close().await;
    Ok(())
}

async fn manipulate(pool: &PgPool, sql: &str) -> anyhow::Result<()> {
    for tenant in [A, B, SYSTEM] {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('rss.storage_target',repeat('01',16),true),set_config('rss.storage_lineage',repeat('02',16),true),set_config('rss.execution_epoch','1',true)").bind(tenant).execute(&mut *tx).await?;
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PG"]
async fn relay_quarantines_bad_events_and_recovers_lost_source_lease() -> anyhow::Result<()> {
    use rss_transactional_messaging::outbox::{OutboxWriter, PendingMessage};
    let s = Setup::new().await?;
    let writer = rss_transactional_messaging_postgres::PgOutboxWriter::new(
        s.f.runtime.clone(),
        MessagingDomain::parse("identity.security")?,
    );
    let base = serde_json::json!({"action":"created","tenant":A,"principal":B,"session_id":SYSTEM,"replaced_session_id":null,"epoch":1});
    let valid = super::tests::envelope("session", base.clone());
    let mut bad = base;
    bad["tenant"] = serde_json::json!(B);
    let bad = MessageEnvelope::new(
        rss_transactional_messaging::message::MessageId::parse("wrong-tenant")?,
        valid.metadata().clone(),
        serde_json::to_vec(&bad)?,
    );
    s.f.runtime
        .local_tx(TenantId::parse(A)?, support::deadline(), move |tx| {
            Box::pin(async move {
                writer.append(tx, PendingMessage::new(bad)).await?;
                writer.append(tx, PendingMessage::new(valid)).await?;
                Ok(())
            })
        })
        .await
        .fold(
            |_| Ok(()),
            |e| Err(anyhow::anyhow!(e)),
            |e| Err(anyhow::anyhow!(e)),
            |e| Err(anyhow::anyhow!(e)),
            |e| Err(anyhow::anyhow!(e)),
            |_| Err(anyhow::anyhow!("fenced")),
        )?;
    let limit = RelayBatchLimit::new(std::num::NonZeroUsize::new(8).unwrap())?;
    let mut lock = s.f.owner.begin().await?;
    sqlx::raw_sql("LOCK TABLE rss_audit.heads IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await?;
    let (result, injection) = tokio::join!(s.worker.run_once(limit), async {
        // Wait for the real relay claim, then revoke its source lease while the append is blocked.
        tokio::time::timeout(Duration::from_secs(3),async {
            loop {
                let held:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_transactional_messaging.outbox WHERE status='publishing')").fetch_one(&s.f.owner).await?;
                if held { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<_,sqlx::Error>(())
        }).await??;
        manipulate(&s.f.owner,"UPDATE rss_transactional_messaging.outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE status='publishing' AND tenant_id=$1::uuid").await?;
        lock.rollback().await?;
        Ok::<_, anyhow::Error>(())
    });
    injection?;
    // Lease loss can surface as a fenced report or store CAS error, never false source success.
    let _ = result;
    let published: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.outbox WHERE status='published'",
    )
    .fetch_one(&s.f.owner)
    .await?;
    assert_eq!(published, 0);
    for _ in 0..3 {
        s.worker.run_once(limit).await?;
    }
    assert_eq!(s.count(A).await?, 1);
    let states: Vec<(String, String)> = sqlx::query_as(
        "SELECT message_id,status FROM rss_transactional_messaging.outbox ORDER BY message_id",
    )
    .fetch_all(&s.f.owner)
    .await?;
    assert_eq!(
        states,
        vec![
            ("event-1".into(), "published".into()),
            ("wrong-tenant".into(), "dead_letter".into())
        ]
    );
    s.runtime.close().await;
    s.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PG"]
async fn permanent_storage_failure_stops_delivery_without_ack() -> anyhow::Result<()> {
    let s = Setup::new().await?;
    let message = super::tests::envelope(
        "session",
        serde_json::json!({"action":"created","tenant":A,"principal":B,"session_id":SYSTEM,"replaced_session_id":null,"epoch":1}),
    );
    // Runtime permission loss is infrastructure failure, not a poison authentication event.
    sqlx::raw_sql("REVOKE USAGE ON SCHEMA rss_audit FROM identity_audit_test")
        .execute(&s.f.owner)
        .await?;
    assert!(matches!(
        s.worker
            .publisher
            .publish(&message, support::deadline())
            .await,
        PublishOutcome::Ambiguous(_)
    ));
    assert!(s.worker.fatal.load(std::sync::atomic::Ordering::SeqCst));
    let terminal: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.inbox WHERE disposition IS NOT NULL",
    )
    .fetch_one(&s.f.owner)
    .await?;
    assert_eq!(terminal, 0);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_audit.records")
        .fetch_one(&s.f.owner)
        .await?;
    assert_eq!(count, 0);
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_audit TO identity_audit_test")
        .execute(&s.f.owner)
        .await?;
    s.runtime.close().await;
    s.pool.close().await;
    Ok(())
}
