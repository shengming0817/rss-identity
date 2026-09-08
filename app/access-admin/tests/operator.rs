//! Real PG issuance + file delivery seam. Reuse the existing provider fixture, not a second runtime.
#[allow(dead_code)]
#[path = "../../../adapters/access-postgres/tests/support/mod.rs"]
mod support;
use access_admin::deliver_authorization;
use access_postgres::*;
use rss_transactional_messaging_postgres::PgTransactionFault;
use support::*;
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn delivery_failure_can_be_resigned() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let dir = std::env::temp_dir().join(format!("access-delivery-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir)?;
    let first = f
        .issuer
        .issue_authorization(f.key, AuthorizationPurpose::Initialize, deadline())
        .await?;
    let obsolete = token(first.secret());
    let file = dir.join("secret");
    std::fs::write(&file, "existing file must survive")?;
    assert!(deliver_authorization(&file, Ok(first)).is_err());
    assert_eq!(
        std::fs::read_to_string(&file)?,
        "existing file must survive"
    );
    let second = f
        .issuer
        .issue_authorization(f.key, AuthorizationPurpose::Initialize, deadline())
        .await?;
    assert!(
        f.store
            .initialize(
                f.key,
                login("admin"),
                password(),
                obsolete,
                source(),
                deadline()
            )
            .await
            .is_err()
    );
    let second_file = dir.join("second");
    let current = token(second.secret());
    deliver_authorization(&second_file, Ok(second))?;
    f.store
        .initialize(
            f.key,
            login("admin"),
            password(),
            current,
            source(),
            deadline(),
        )
        .await?;
    f.issuer_runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let unknown = dir.join("unknown");
    assert!(
        deliver_authorization(
            &unknown,
            f.issuer
                .issue_authorization(f.key, AuthorizationPurpose::Recover, deadline())
                .await
        )
        .is_err()
    );
    assert!(!unknown.exists());
    let fresh = f
        .issuer
        .issue_authorization(f.key, AuthorizationPurpose::Recover, deadline())
        .await?;
    f.store
        .recover_administrator(f.key, password(), fresh.into_secret(), source(), deadline())
        .await?;
    std::fs::remove_dir_all(dir)?;
    f.close().await;
    Ok(())
}
