//! Password-file to maintenance authority seam; not a binary/configuration T3.
#[allow(dead_code)]
#[path = "../../../crates/identity-postgres/tests/support/mod.rs"]
mod support;
use rss_identity_app::read_secret;
use rss_identity_core::account::Password;
use rss_identity_postgres::*;
use rss_transactional_messaging_postgres::PgTransactionFault;
use std::os::unix::fs::PermissionsExt;
use support::*;

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn maintenance_file_and_settlement() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let dir = std::env::temp_dir().join(format!("identity-maintenance-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir)?;
    let file = dir.join("password");
    std::fs::write(&file, PASSWORD)?;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
    let input =
        || -> anyhow::Result<Password> { Ok(Password::new(read_secret(&file)?.to_string())?) };
    // Both operations have one business transaction: faults target the mutation itself.
    for initialize in [true, false] {
        sqlx::raw_sql("CREATE FUNCTION public.reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic private marker'; END $$; CREATE TRIGGER reject_event BEFORE INSERT ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.reject_event();").execute(&f.owner).await?;
        for fault in [None, Some(PgTransactionFault::RollbackFailedAfterAck)] {
            if let Some(fault) = fault {
                f.maintenance_runtime.inject_next_transaction_fault(fault);
            }
            let result = if initialize {
                f.maintenance
                    .initialize(f.key, login("admin"), input()?, deadline())
                    .await
            } else {
                f.maintenance
                    .recover_administrator(f.key, input()?, deadline())
                    .await
            };
            if fault.is_some() {
                assert!(matches!(result, Err(AuthorityError::RollbackFailed(_))));
            } else {
                assert!(matches!(result, Err(AuthorityError::RolledBack(_))));
            }
            assert!(!format!("{result:?}").contains("synthetic private marker"));
            assert_eq!(f.events().await?, if initialize { 0 } else { 1 });
            let initialized: bool = sqlx::query_scalar(
                "SELECT bootstrap_tenant IS NOT NULL FROM identity_authority.deployment",
            )
            .fetch_one(&f.owner)
            .await?;
            assert_eq!(initialized, !initialize);
            let epochs: Vec<i64> =
                sqlx::query_scalar("SELECT auth_epoch FROM identity_authority.accounts")
                    .fetch_all(&f.owner)
                    .await?;
            assert_eq!(epochs, if initialize { vec![] } else { vec![1] });
        }
        sqlx::raw_sql("DROP TRIGGER reject_event ON rss_transactional_messaging.outbox; DROP FUNCTION public.reject_event()").execute(&f.owner).await?;
        f.maintenance_runtime
            .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
        let result = if initialize {
            f.maintenance
                .initialize(f.key, login("admin"), input()?, deadline())
                .await
        } else {
            f.maintenance
                .recover_administrator(f.key, input()?, deadline())
                .await
        };
        assert!(matches!(result, Err(AuthorityError::CommitUnknown(_))));
        assert_eq!(f.events().await?, if initialize { 1 } else { 2 });
        let epoch: i64 = sqlx::query_scalar("SELECT auth_epoch FROM identity_authority.accounts")
            .fetch_one(&f.owner)
            .await?;
        assert_eq!(epoch, if initialize { 1 } else { 2 });
        // The existing input is untouched and no output secret is created.
        assert_eq!(std::fs::read_dir(&dir)?.count(), 1);
        assert!(std::fs::read_to_string(&file)? == PASSWORD);
    }
    assert!(f.actor().await.is_ok());
    std::fs::remove_dir_all(dir)?;
    f.close().await;
    Ok(())
}
