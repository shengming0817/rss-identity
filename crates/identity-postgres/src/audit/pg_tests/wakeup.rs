use super::*;
use crate::AuthorityError;
use sqlx::postgres::PgListener;
use support::{deadline, login, password};

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn notifications_settle_with_security_events() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let _ = f.actor().await?; // Establish the management session before listening.
    let channel = notification_channel(f.instance, f.key.tenant);
    let mut listener = PgListener::connect_with(&f.owner).await?;
    let channels = [
        channel.clone(),
        notification_channel(f.instance, TenantId::parse(B)?),
        notification_channel(f.instance, TenantId::parse(SYSTEM)?),
        notification_channel(InstanceId::generate(), f.key.tenant),
    ];
    listener
        .listen_all(channels.iter().map(String::as_str))
        .await?;
    committed_event(&f, &mut listener, &channel).await?;
    unknown_commit(&f, &mut listener, &channel).await?;
    empty_and_failed_notify(&f, &mut listener).await?;
    drop(listener);
    f.close().await;
    Ok(())
}

async fn quiet(listener: &mut PgListener) {
    assert!(
        tokio::time::timeout(Duration::from_millis(80), listener.recv())
            .await
            .is_err()
    );
}

async fn received(listener: &mut PgListener, channel: &str) -> anyhow::Result<()> {
    let notification = tokio::time::timeout(Duration::from_secs(5), listener.recv()).await??;
    assert_eq!(notification.channel(), channel);
    assert_eq!(notification.payload(), "");
    quiet(listener).await; // Other instance/tenant channels and duplicate hints stay absent.
    Ok(())
}

async fn committed_event(
    f: &Fixture,
    listener: &mut PgListener,
    channel: &str,
) -> anyhow::Result<()> {
    let before = f.events().await?;
    // A deferred trigger blocks COMMIT after Identity has appended and queued NOTIFY.
    sqlx::raw_sql("CREATE FUNCTION public.commit_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(2715); RETURN NULL; END $$; CREATE CONSTRAINT TRIGGER commit_gate AFTER INSERT ON rss_transactional_messaging.outbox DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.commit_gate()")
        .execute(&f.owner).await?;
    let mut gate = f.owner.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(2715)")
        .execute(&mut *gate)
        .await?;
    let actor = f.actor().await?;
    let store = f.store.clone();
    let pending = tokio::spawn(async move {
        store
            .create_local_account(actor, login("notify-commit"), password(), deadline())
            .await
    });
    wait_for_commit_gate(f).await?;
    quiet(listener).await;
    assert_eq!(
        f.events().await?,
        before,
        "uncommitted outbox is not visible"
    );
    gate.rollback().await?;
    pending.await??;
    received(listener, channel).await?;
    assert_eq!(f.events().await?, before + 1);
    sqlx::raw_sql("DROP TRIGGER commit_gate ON rss_transactional_messaging.outbox; DROP FUNCTION public.commit_gate()")
        .execute(&f.owner).await?;
    Ok(())
}

async fn wait_for_commit_gate(f: &Fixture) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND objid=2715 AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()))")
                .fetch_one(&f.owner).await?;
            if waiting { return Ok::<_, sqlx::Error>(()); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    Ok(())
}

async fn unknown_commit(
    f: &Fixture,
    listener: &mut PgListener,
    channel: &str,
) -> anyhow::Result<()> {
    let actor = f.actor().await?;
    let before = f.events().await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let result = f
        .store
        .create_local_account(actor, login("notify-unknown"), password(), deadline())
        .await;
    assert!(matches!(result, Err(AuthorityError::CommitUnknown(_))));
    received(listener, channel).await?;
    assert_eq!(
        f.events().await?,
        before + 1,
        "a notification cannot resolve the caller's unknown outcome"
    );
    Ok(())
}

async fn empty_and_failed_notify(f: &Fixture, listener: &mut PgListener) -> anyhow::Result<()> {
    f.store
        .conditional_write_sql(f.key.tenant, deadline(), |_| {
            Box::pin(async { Ok(((), Vec::new())) })
        })
        .await?;
    quiet(listener).await;
    let actor = f.actor().await?;
    let before = f.events().await?;
    // Function ACL changes are local to this isolated fixture database.
    sqlx::raw_sql("REVOKE EXECUTE ON FUNCTION pg_catalog.pg_notify(text,text) FROM PUBLIC")
        .execute(&f.owner)
        .await?;
    let result = f
        .store
        .create_local_account(actor, login("notify-failure"), password(), deadline())
        .await;
    sqlx::raw_sql("GRANT EXECUTE ON FUNCTION pg_catalog.pg_notify(text,text) TO PUBLIC")
        .execute(&f.owner)
        .await?;
    assert!(matches!(result, Err(AuthorityError::RolledBack(_))));
    assert_eq!(
        f.events().await?,
        before,
        "notify failure rolls back all staged events"
    );
    let accounts: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_authority.local_credentials WHERE login_key='notify-failure'").fetch_one(&f.owner).await?;
    assert_eq!(
        accounts, 0,
        "notify failure rolls back companion business state"
    );
    quiet(listener).await;
    Ok(())
}
