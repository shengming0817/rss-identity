use super::*;
use rss_transactional_messaging::policy::OperationDeadline;

const DAY_MS: i64 = 86_400_000;

fn operation(ms: i64) -> ProfileOperationId {
    let ts = uuid::Timestamp::from_unix(
        uuid::NoContext,
        (ms / 1000) as u64,
        (ms % 1000) as u32 * 1_000_000,
    );
    Uuid::new_v7(ts).try_into().unwrap()
}

fn change(id: ProfileOperationId, revision: i64) -> ProfileChange {
    ProfileChange {
        operation_id: id,
        expected_revision: revision,
        value: None,
    }
}

async fn now(f: &Fixture) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(&f.owner)
            .await?,
    )
}

async fn advance(f: &Fixture, ms: i64) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE identity_authority.guard SET profile_receipt_time_ms=$2 WHERE tenant_id=$1::uuid",
    )
    .bind(A)
    .bind(ms)
    .execute(&f.owner)
    .await?;
    Ok(())
}

async fn capacity(f: &Fixture, slots: u32) -> anyhow::Result<Authority> {
    Ok(Authority::connect_runtime(
        f.runtime.clone(),
        Arc::new(rss_identity_core::account::PasswordKdf::new(
            4usize.try_into()?,
            (128u64 * 1024 * 1024).try_into()?,
        )?),
        f.config().with_profile_receipt_capacity(slots.try_into()?),
        binding(f.key.tenant),
        f.policy.clone(),
        deadline(),
    )
    .await?)
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn admission_after_quota_changes_and_concurrent_reclamation() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let actor = f.actor().await?;
    // Seed one coherent revision history, including the Profile row the real writer owns.
    let initial = now(&f).await?;
    let ids: Vec<_> = (1..8192).map(|_| operation(initial).as_uuid()).collect();
    let mut tx = f.owner.begin().await?;
    sqlx::query("INSERT INTO identity_authority.local_profiles(tenant_id,principal_id,revision) VALUES ($1::uuid,$2,8191)")
        .bind(A).bind(f.key.principal.as_uuid()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO identity_authority.profile_operations(tenant_id,operation_id,principal_id,actor,digest,revision,accepted_at_ms)
        SELECT $1::uuid,id,$2,$2,decode(repeat('00',32),'hex'),revision,$4 FROM unnest($3::uuid[]) WITH ORDINALITY AS seed(id,revision)")
        .bind(A).bind(f.key.principal.as_uuid()).bind(ids).bind(initial).execute(&mut *tx).await?;
    tx.commit().await?;
    let normal = capacity(&f, 8192).await?;
    let left = change(operation(initial), 8191);
    let right = change(operation(initial - 1), 8191);
    let a = f.actor().await?;
    let b = f.actor().await?;
    let audit = f.events().await?;
    let (one, two) = tokio::join!(
        normal.update_local_profile(a, f.key, left.clone(), deadline()),
        normal.update_local_profile(b, f.key, right.clone(), deadline())
    );
    let winner = match (one, two) {
        (Ok(r), Err(AuthorityError::ProfileReceiptCapacityReached)) if r.revision == 8192 => left,
        (Err(AuthorityError::ProfileReceiptCapacityReached), Ok(r)) if r.revision == 8192 => right,
        _ => anyhow::bail!("last receipt slot did not have exactly one winner"),
    };
    let small = capacity(&f, 1).await?;
    assert_eq!(
        small
            .update_local_profile(f.actor().await?, f.key, winner.clone(), deadline())
            .await?
            .revision,
        8192
    );
    assert!(matches!(
        small
            .update_local_profile(
                f.actor().await?,
                f.key,
                change(operation(initial), 8192),
                deadline()
            )
            .await,
        Err(AuthorityError::ProfileReceiptCapacityReached)
    ));
    assert_eq!(f.events().await?, audit + 1);
    let large = capacity(&f, 8193).await?;
    // Older client time arrives last; acceptance order owns the live suffix.
    large
        .update_local_profile(
            f.actor().await?,
            f.key,
            change(operation(initial - 1000), 8192),
            deadline(),
        )
        .await?;
    let last: i64 =
        sqlx::query_scalar("SELECT max(accepted_at_ms) FROM identity_authority.profile_operations")
            .fetch_one(&f.owner)
            .await?;
    let mut future = last + DAY_MS;
    advance(&f, future).await?;
    // The physical wall clock stays behind the durable floor across Authority reconstruction.
    let small = capacity(&f, 1).await?;
    for i in 0..3 {
        let revision = 8193 + i;
        let first = change(operation(future), revision);
        let second = change(operation(future), revision);
        let a = f.actor().await?;
        let b = f.actor().await?;
        let (one, two) = tokio::join!(
            small.update_local_profile(a, f.key, first, deadline()),
            small.update_local_profile(b, f.key, second, deadline())
        );
        assert!(matches!(
            (one, two),
            (Ok(_), Err(AuthorityError::ProfileReceiptCapacityReached))
                | (Err(AuthorityError::ProfileReceiptCapacityReached), Ok(_))
        ));
        let (rows,live):(i64,i64)=sqlx::query_as("SELECT count(*),count(*) FILTER(WHERE accepted_at_ms>$1) FROM identity_authority.profile_operations")
            .bind(future-DAY_MS).fetch_one(&f.owner).await?;
        assert_eq!((rows, live), (8193 - (i + 1) * 63, 1));
        assert_eq!(
            small
                .read_local_profile(&actor, f.key, deadline())
                .await?
                .revision,
            revision + 1
        );
        future += DAY_MS;
        advance(&f, future).await?;
    }
    assert_eq!(f.events().await?, audit + 5);
    assert!(matches!(
        small
            .update_local_profile(
                f.actor().await?,
                f.key,
                change(winner.operation_id, 8196),
                deadline()
            )
            .await,
        Err(AuthorityError::ProfileOperationExpired)
    ));
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn receipt_visibility_expiry_and_uncertain_writes() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let target = f
        .store
        .create_local_account(f.actor().await?, login("other"), password(), deadline())
        .await?
        .key();
    f.policy.allow(target);
    let session = f
        .store
        .login_local(
            binding(target.tenant),
            login("other"),
            password(),
            source(),
            None,
            deadline(),
        )
        .await?;
    let other = proof(&f.store, &f, &session).await?;
    let issued = f
        .store
        .login_local(
            binding(f.system_key.tenant),
            login("platform"),
            password(),
            source(),
            None,
            deadline(),
        )
        .await?;
    let system = f
        .store
        .inspect_session(
            binding(f.system_key.tenant),
            rss_identity_core::session::SessionSecret::parse(issued.secret().expose().into())?,
            deadline(),
        )
        .await?;
    let reader = f.actor().await?;
    let start = now(&f).await? + 60_000;
    advance(&f, start).await?;
    let c = change(operation(start - 299_999), 0);
    let actor = f.actor().await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitPending);
    assert!(matches!(
        f.store
            .update_local_profile(
                actor,
                f.key,
                c.clone(),
                OperationDeadline::from_remaining(std::time::Duration::from_millis(500))
            )
            .await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    assert!(
        f.store
            .local_profile_receipt(&reader, f.key, c.operation_id, deadline())
            .await?
            .is_none()
    );
    let audit = f.events().await?;
    let actor = f.actor().await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        f.store
            .update_local_profile(actor, f.key, c.clone(), deadline())
            .await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    assert_eq!(
        f.store
            .local_profile_receipt(&reader, f.key, c.operation_id, deadline())
            .await?
            .unwrap()
            .revision,
        1
    );
    assert!(
        f.store
            .local_profile_receipt(&other, f.key, c.operation_id, deadline())
            .await?
            .is_none()
    );
    assert!(
        f.store
            .local_profile_receipt(&reader, target, c.operation_id, deadline())
            .await?
            .is_none()
    );
    assert!(matches!(
        f.store
            .update_local_profile(other, f.key, c.clone(), deadline())
            .await,
        Err(AuthorityError::OperationConflict)
    ));
    assert!(matches!(
        f.store
            .update_local_profile(f.actor().await?, target, c.clone(), deadline())
            .await,
        Err(AuthorityError::OperationConflict)
    ));
    assert!(matches!(
        f.store
            .update_local_profile(
                f.actor().await?,
                f.key,
                change(c.operation_id, 1),
                deadline()
            )
            .await,
        Err(AuthorityError::OperationConflict)
    ));
    assert!(matches!(
        f.store
            .local_profile_receipt(&system, f.key, c.operation_id, deadline())
            .await,
        Err(AuthorityError::Rejected)
    ));
    assert!(
        f.store
            .local_profile_receipt(&system, f.system_key, c.operation_id, deadline())
            .await?
            .is_none()
    );
    advance(&f, start + DAY_MS - 1).await?;
    assert_eq!(
        f.store
            .update_local_profile(f.actor().await?, f.key, c.clone(), deadline())
            .await?
            .revision,
        1
    );
    assert_eq!(f.events().await?, audit + 1);
    advance(&f, start + DAY_MS).await?;
    assert!(matches!(
        f.store
            .local_profile_receipt(&reader, f.key, c.operation_id, deadline())
            .await,
        Err(AuthorityError::ProfileOperationExpired)
    ));
    // Force physical deletion then try the old ID with both a new revision and a different target.
    f.store
        .update_local_profile(
            f.actor().await?,
            f.key,
            change(operation(start + DAY_MS), 1),
            deadline(),
        )
        .await?;
    for (key, rev) in [(f.key, 2), (target, 0)] {
        assert!(matches!(
            f.store
                .update_local_profile(
                    f.actor().await?,
                    key,
                    change(c.operation_id, rev),
                    deadline()
                )
                .await,
            Err(AuthorityError::ProfileOperationExpired)
        ));
    }
    f.close().await;
    Ok(())
}
