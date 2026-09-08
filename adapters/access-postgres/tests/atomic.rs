//! Real PostgreSQL seam, launched by `make test-pg`. No skip-on-missing-provider.
use access_postgres::{AccessPostgres, WriteError};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    message::*,
    policy::{DeliveryBudget, OperationDeadline},
};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgRuntime, PgTransactionFault};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
const TENANT: &str = "11111111-1111-4111-8111-111111111111";
struct Timer;
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)] // Clock implementation is the time source boundary.
    fn now(&self) -> Instant {
        Instant::now()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, deadline: Deadline) {
        tokio::time::sleep(deadline.remaining(self.now()).unwrap_or_default()).await;
    }
}
fn cutoff() -> OperationDeadline {
    OperationDeadline::from_cutoff(
        Deadline::from_timeout(&Timer, Duration::from_secs(5)).unwrap(),
        &Timer,
    )
}
fn event(id: &str, tenant: TenantId) -> MessageEnvelope<Vec<u8>> {
    MessageEnvelope::new(
        MessageId::parse(id).unwrap(),
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                Timepoint::try_from(1_i64).unwrap(),
                MessagingDomain::parse("access.security").unwrap(),
                MessageRoute::parse("probe").unwrap(),
                ContractIdentity::new(
                    ContractId::parse("access.probe").unwrap(),
                    ContractVersion::from_major(1).unwrap(),
                    SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64))).unwrap(),
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        br#"{"kind":"test-only"}"#.to_vec(),
    )
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; make test-pg starts it"]
async fn business_and_security_event_are_atomic() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(90), run()).await?
}
async fn run() -> anyhow::Result<()> {
    let port: u16 = std::env::var("ACCESS_TEST_PG_PORT")?.parse()?;
    let owner = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(port)
                .username("postgres")
                .password("fixture-only")
                .database("postgres"),
        )
        .await?;
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; CREATE ROLE access_runtime LOGIN PASSWORD 'fixture-only' NOBYPASSRLS;").execute(&owner).await?;
    sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
        .execute(&owner)
        .await?;
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO access_runtime; GRANT SELECT ON rss_transactional_messaging.policy TO access_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO access_runtime; GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO access_runtime; GRANT USAGE ON ALL SEQUENCES IN SCHEMA rss_transactional_messaging TO access_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid),rss_transactional_messaging.check_execution() TO access_runtime;").execute(&owner).await?;
    sqlx::raw_sql("CREATE SCHEMA access_probe; CREATE TABLE access_probe.effects(tenant_id uuid NOT NULL, id text NOT NULL, PRIMARY KEY(tenant_id,id)); ALTER TABLE access_probe.effects ENABLE ROW LEVEL SECURITY; ALTER TABLE access_probe.effects FORCE ROW LEVEL SECURITY; CREATE POLICY tenant_effect ON access_probe.effects USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid); GRANT USAGE ON SCHEMA access_probe TO access_runtime; GRANT SELECT,INSERT ON access_probe.effects TO access_runtime;").execute(&owner).await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,$1,$2)")
        .bind([1u8; 16].as_slice())
        .bind([2u8; 16].as_slice())
        .execute(&owner)
        .await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
        .bind(TENANT)
        .execute(&owner)
        .await?;
    let tenant = TenantId::parse(TENANT)?;
    let binding = ExecutionBinding::new(
        StorageIdentity::new([1; 16], [2; 16])?,
        vec![(tenant, Epoch::new(1)?)],
    )?;
    let runtime = Arc::new(
        PgRuntime::connect(
            PgConfig::new_for_test_plaintext(
                "127.0.0.1",
                port,
                "postgres",
                "access_runtime",
                PgPassword::new("fixture-only"),
            ),
            Timer,
            binding,
        )
        .await?,
    );
    let store = AccessPostgres::new(
        runtime.clone(),
        DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )?,
    )?;
    for (id, rollback, unknown) in [
        ("commit", false, false),
        ("rollback", true, false),
        ("unknown", false, true),
    ] {
        if unknown {
            runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
        }
        let result = store
            .write_with_event(tenant, cutoff(), event(id, tenant), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            sqlx::query("INSERT INTO access_probe.effects VALUES($1::uuid,$2)")
                                .bind(TENANT)
                                .bind(id)
                                .execute(c)
                                .await?;
                            Ok(())
                        })
                    })
                    .await?;
                    if rollback {
                        return Err(sqlx::Error::RowNotFound.into());
                    }
                    Ok("committed-result")
                })
            })
            .await;
        if unknown {
            assert!(matches!(result, Err(WriteError::CommitUnknown(_))));
        } else if rollback {
            assert!(matches!(result, Err(WriteError::RolledBack(_))));
        } else {
            assert_eq!(result.unwrap(), "committed-result");
        }
        let counts: (i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM access_probe.effects WHERE id=$1),(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id=$1)").bind(id).fetch_one(&owner).await?;
        assert_eq!(counts, if rollback { (0, 0) } else { (1, 1) });
    }
    // A repeated event must not commit a new companion write.
    let duplicate = store
        .write_with_event(tenant, cutoff(), event("commit", tenant), |tx| {
            Box::pin(async move {
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query(
                            "INSERT INTO access_probe.effects VALUES($1::uuid,'duplicate-write')",
                        )
                        .bind(TENANT)
                        .execute(c)
                        .await?;
                        Ok(())
                    })
                })
                .await
            })
        })
        .await;
    assert!(matches!(duplicate, Err(WriteError::RolledBack(_))));
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM access_probe.effects WHERE id='duplicate-write'")
            .fetch_one(&owner)
            .await?;
    assert_eq!(count, 0);
    let other = TenantId::parse("22222222-2222-4222-8222-222222222222")?;
    let mismatch = store
        .write_with_event(tenant, cutoff(), event("mismatch", other), |_| {
            Box::pin(async {
                panic!("must reject before business write");
                #[allow(unreachable_code)]
                Ok(())
            })
        })
        .await;
    assert!(matches!(mismatch, Err(WriteError::Binding)));
    // RLS rejects a cross-tenant companion effect, even with a valid bound event.
    let cross = store.write_with_event(tenant, cutoff(), event("cross",tenant), |tx| Box::pin(async move {
        tx.with_connection(|c| Box::pin(async move { sqlx::query("INSERT INTO access_probe.effects VALUES('22222222-2222-4222-8222-222222222222','cross')").execute(c).await?; Ok(()) })).await
    })).await;
    assert!(matches!(cross, Err(WriteError::RolledBack(_))));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id='cross'",
    )
    .fetch_one(&owner)
    .await?;
    assert_eq!(count, 0);
    runtime.close().await;
    owner.close().await;
    Ok(())
}
