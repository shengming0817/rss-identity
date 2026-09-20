//! Canonical real PostgreSQL account scenarios; the provider runner owns the exact test set.
use crate::support;
use rss_identity_core::account::{AccountChange, AccountKey, AccountRuleError, AccountState};
use rss_identity_core::{
    PrincipalId,
    account::{Password, PasswordKdf},
};
use rss_identity_postgres::*;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgTransactionFault;
use std::time::Duration;
use support::*;

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn initialization_and_recovery() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    assert_eq!(
        f.store
            .initialize(f.key, login("admin"), password(), deadline())
            .await
            .unwrap_err(),
        AuthorityError::Rejected
    );
    assert_eq!(
        f.store
            .recover_local_password(f.key, password(), deadline())
            .await
            .unwrap_err(),
        AuthorityError::Rejected
    );
    assert!(
        f.maintenance
            .verify_password(
                f.key.tenant,
                login("admin"),
                password(),
                source(),
                deadline()
            )
            .await
            .is_err()
    );
    let mut jobs = Vec::new();
    for _ in 0..4 {
        let maintenance = f.maintenance.clone();
        let key = f.system_key;
        jobs.push(tokio::spawn(async move {
            maintenance
                .initialize(key, login("platform"), password(), deadline())
                .await
        }));
    }
    let mut successes = 0;
    for job in jobs {
        successes += usize::from(job.await?.is_ok());
    }
    assert_eq!(successes, 1);
    assert_eq!(f.account_events().await?, 1);
    assert_eq!(f.events().await?, 1);
    let unordered: bool = sqlx::query_scalar(
        "SELECT bool_and(partition_key IS NULL AND partition_seq IS NULL) FROM rss_transactional_messaging.outbox",
    ).fetch_one(&f.owner).await?;
    assert!(unordered, "security events retain unordered delivery");
    f.provision_a().await?;
    let instance: uuid::Uuid =
        sqlx::query_scalar("SELECT authority_id FROM identity_authority.deployment")
            .fetch_one(&f.owner)
            .await?;
    assert_eq!(instance, f.instance.as_uuid());
    for reset in [
        "DELETE FROM identity_authority.deployment",
        "UPDATE identity_authority.deployment SET authority_id=gen_random_uuid()",
    ] {
        assert!(sqlx::raw_sql(reset).execute(&f.owner).await.is_err());
    }
    let foreign = AccountKey {
        tenant: TenantId::parse("33333333-3333-4333-8333-333333333333")?,
        principal: f.key.principal,
    };
    assert!(
        f.maintenance
            .initialize(foreign, login("admin"), password(), deadline())
            .await
            .is_err()
    );
    assert_eq!(
        f.maintenance
            .recover_local_password(foreign, password(), deadline())
            .await
            .unwrap_err(),
        AuthorityError::Rejected
    );
    let absent = AccountKey {
        tenant: f.key.tenant,
        principal: PrincipalId::generate(),
    };
    assert_eq!(
        f.maintenance
            .recover_local_password(absent, password(), deadline())
            .await
            .unwrap_err(),
        AuthorityError::Rejected
    );
    let member = f
        .store
        .create_local_account(f.actor().await?, login("member"), password(), deadline())
        .await?;
    assert_eq!(
        f.maintenance
            .recover_local_password(member.key(), password(), deadline())
            .await?
            .epoch(),
        2
    );
    let emergency = f
        .store
        .create_local_account(f.actor().await?, login("emergency"), password(), deadline())
        .await?;
    support::apply_change(
        &f.store,
        f.actor().await?,
        emergency.key(),
        AccountChange::Enabled(false),
        deadline(),
    )
    .await?;
    let inactive = support::apply_change(
        &f.store,
        f.actor().await?,
        emergency.key(),
        AccountChange::Membership(false),
        deadline(),
    )
    .await?;
    let recovered = f
        .maintenance
        .recover_local_password(emergency.key(), password(), deadline())
        .await?;
    assert_eq!(recovered, inactive.recover()?.0);
    assert!(!recovered.enabled());
    assert!(!recovered.member_active());
    assert_event(
        &f,
        "password_recovered",
        emergency.key(),
        None,
        recovered.epoch(),
        Some(recovered),
    )
    .await?;
    assert!(
        f.store
            .verify_password(
                f.key.tenant,
                login("emergency"),
                password(),
                source(),
                deadline()
            )
            .await
            .is_err()
    );
    f.reset_attempts().await?;
    let old = f.actor().await?;
    let first_password = "first maintenance password";
    let second_password = "second maintenance password";
    let (first, second) = tokio::join!(
        f.maintenance.recover_local_password(
            f.key,
            Password::new(first_password.into())?,
            deadline()
        ),
        f.maintenance.recover_local_password(
            f.key,
            Password::new(second_password.into())?,
            deadline()
        )
    );
    let first = first?;
    let second = second?;
    assert_eq!(first.epoch().min(second.epoch()), 2);
    assert_eq!(first.epoch().max(second.epoch()), 3);
    let (winning, losing, state) = if first.epoch() > second.epoch() {
        (first_password, second_password, first)
    } else {
        (second_password, first_password, second)
    };
    assert_event(&f, "password_recovered", f.key, None, 3, Some(state)).await?;
    assert_eq!(
        support::apply_change(
            &f.store,
            old,
            f.key,
            AccountChange::Password(password()),
            deadline()
        )
        .await
        .unwrap_err(),
        AuthorityError::Rejected
    );
    assert!(
        f.store
            .verify_password(
                f.key.tenant,
                login("admin"),
                Password::new(winning.into())?,
                source(),
                deadline()
            )
            .await
            .is_ok()
    );
    assert!(
        f.store
            .verify_password(
                f.key.tenant,
                login("admin"),
                Password::new(losing.into())?,
                source(),
                deadline()
            )
            .await
            .is_err()
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn account_races_and_isolation() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let second = f
        .store
        .create_local_account(f.actor().await?, login("second"), password(), deadline())
        .await?;
    f.policy.allow(second.key());
    let old = f.actor().await?;
    let actor = f.actor().await?;
    support::apply_change(
        &f.store,
        actor,
        f.key,
        AccountChange::Password(password()),
        deadline(),
    )
    .await?;
    assert!(
        f.store
            .create_local_account(old, login("stale"), password(), deadline())
            .await
            .is_err()
    );
    f.reset_attempts().await?;
    // Race an actual password verification against three invalidating writes.
    for (i, mode) in ["password", "disable", "recovery"].iter().enumerate() {
        f.reset_attempts().await?;
        let name = format!("race-{i}");
        let victim = f
            .store
            .create_local_account(f.actor().await?, login(&name), password(), deadline())
            .await?;
        let actor = f.actor().await?;
        let change = async {
            if *mode == "recovery" {
                f.maintenance
                    .recover_local_password(
                        victim.key(),
                        Password::new("a newly recovered password".into())?,
                        deadline(),
                    )
                    .await
            } else {
                support::apply_change(
                    &f.store,
                    actor,
                    victim.key(),
                    if *mode == "disable" {
                        AccountChange::Enabled(false)
                    } else {
                        AccountChange::Password(Password::new("a newly changed password".into())?)
                    },
                    deadline(),
                )
                .await
            }
        };
        let (verified, changed) = tokio::join!(
            f.store
                .verify_password(f.key.tenant, login(&name), password(), source(), deadline()),
            change
        );
        changed?;
        if let Ok(candidate) = verified {
            assert!(
                f.store
                    .create_session(candidate, None, deadline())
                    .await
                    .is_err()
            );
        }
        support::apply_change(
            &f.store,
            f.actor().await?,
            victim.key(),
            AccountChange::Enabled(false),
            deadline(),
        )
        .await?;
    }
    f.reset_attempts().await?;
    let a = f.actor().await?;
    let b = f
        .store
        .verify_password(
            f.key.tenant,
            login("second"),
            password(),
            source(),
            deadline(),
        )
        .await?;
    let b = crate::session_actor(&f.store, b).await?;
    let (ra, rb) = tokio::join!(
        support::apply_change(
            &f.store,
            a,
            f.key,
            AccountChange::Enabled(false),
            deadline()
        ),
        support::apply_change(
            &f.store,
            b,
            second.key(),
            AccountChange::Enabled(false),
            deadline()
        )
    );
    assert_eq!(usize::from(ra.is_ok()) + usize::from(rb.is_ok()), 2);
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.accounts WHERE tenant_id='11111111-1111-4111-8111-111111111111' AND enabled",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(n, 0);
    // Same global principal in another tenant has an independent local credential and epoch.
    let other = AccountKey {
        tenant: TenantId::parse(B)?,
        principal: f.key.principal,
    };
    sqlx::query("INSERT INTO identity_authority.guard VALUES($1::uuid)")
        .bind(B)
        .execute(&f.owner)
        .await?;
    let hash = PasswordKdf::new()
        .hash(Password::new("other tenant secret password".into())?)
        .await?;
    sqlx::query(
        "INSERT INTO identity_authority.accounts(tenant_id,principal_id) VALUES($1::uuid,$2::uuid)",
    )
    .bind(B)
    .bind(other.principal.as_uuid().to_string())
    .execute(&f.owner)
    .await?;
    sqlx::query(
        "INSERT INTO identity_authority.local_credentials VALUES($1::uuid,$2::uuid,'admin',$3)",
    )
    .bind(B)
    .bind(other.principal.as_uuid().to_string())
    .bind(hash.as_str())
    .execute(&f.owner)
    .await?;
    sqlx::query("INSERT INTO identity_authority.memberships(tenant_id,principal_id) VALUES($1::uuid,$2::uuid)").bind(B).bind(other.principal.as_uuid().to_string()).execute(&f.owner).await?;
    assert!(
        f.store
            .verify_password(
                other.tenant,
                login("admin"),
                password(),
                source(),
                deadline()
            )
            .await
            .is_err()
    );
    let other_actor = f
        .store
        .verify_password(
            other.tenant,
            login("ADMIN"),
            Password::new("other tenant secret password".into())?,
            source(),
            deadline(),
        )
        .await?;
    let other_actor = crate::session_actor(&f.store, other_actor).await?;
    assert!(
        support::apply_change(
            &f.store,
            other_actor,
            f.key,
            AccountChange::Enabled(true),
            deadline()
        )
        .await
        .is_err()
    );
    let before: i64 = sqlx::query_scalar(
        "SELECT auth_epoch FROM identity_authority.accounts WHERE tenant_id=$1::uuid",
    )
    .bind(B)
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(before, 1);
    let result=f.runtime.local_tx(f.key.tenant,deadline(),|tx|Box::pin(async move {tx.with_connection(|c|Box::pin(async move {sqlx::query("UPDATE identity_authority.accounts SET auth_epoch=99 WHERE tenant_id='22222222-2222-4222-8222-222222222222'").execute(c).await.map(|r|r.rows_affected())})).await})).await.fold(Ok,Err,Err,Err,Err,Err)?;
    assert_eq!(result, 0);
    f.maintenance
        .recover_local_password(f.key, password(), deadline())
        .await?;
    let other_epoch: i64 = sqlx::query_scalar("SELECT auth_epoch FROM identity_authority.accounts WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
        .bind(B).bind(f.key.principal.as_uuid().to_string()).fetch_one(&f.owner).await?;
    assert_eq!(other_epoch, 1);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn attempts_are_shared_and_bounded() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    f.reset_attempts().await?;
    let mut jobs = Vec::new();
    for _ in 0..12 {
        let s = f.store.clone();
        let t = f.key.tenant;
        jobs.push(tokio::spawn(async move {
            s.verify_password(t, login("unknown"), password(), source(), deadline())
                .await
        }));
    }
    let mut limited = 0;
    for j in jobs {
        if matches!(j.await?, Err(AuthorityError::RateLimited)) {
            limited += 1;
        }
    }
    assert_eq!(limited, 7);
    let count: i32 =
        sqlx::query_scalar("SELECT count FROM identity_authority.attempts WHERE key='p:unknown'")
            .fetch_one(&f.owner)
            .await?;
    assert_eq!(count, 5);
    f.reset_attempts().await?;
    sqlx::query("INSERT INTO identity_authority.attempts SELECT $1::uuid,'full:'||i,1,clock_timestamp()+interval '1 hour' FROM generate_series(1,10000) i").bind(A).execute(&f.owner).await?;
    assert!(matches!(
        f.store
            .verify_password(
                f.key.tenant,
                login("admin"),
                password(),
                source(),
                deadline()
            )
            .await,
        Err(AuthorityError::RateLimited)
    ));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_authority.attempts")
        .fetch_one(&f.owner)
        .await?;
    assert_eq!(n, 10000);
    sqlx::query(
        "UPDATE identity_authority.attempts SET expires_at=clock_timestamp()-interval '1 second'",
    )
    .execute(&f.owner)
    .await?;
    assert!(f.actor().await.is_ok());
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn settlement_never_releases_uncertain_success() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let before = f.account_events().await?;
    let actor = f.actor().await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        f.store
            .create_local_account(actor, login("unknown-commit"), password(), deadline())
            .await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    assert_eq!(f.account_events().await?, before + 1);
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.local_credentials WHERE login_key='unknown-commit'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(n, 1);
    // Event failure rolls back the actual companion account and membership.
    sqlx::raw_sql("CREATE FUNCTION public.reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic secret must not escape'; END $$; CREATE TRIGGER reject_event BEFORE INSERT ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.reject_event();").execute(&f.owner).await?;
    let actor = f.actor().await?;
    let result = f
        .store
        .create_local_account(actor, login("rollback"), password(), deadline())
        .await;
    assert!(matches!(result, Err(AuthorityError::RolledBack(_))));
    assert!(!format!("{result:?}").contains("synthetic secret"));
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.local_credentials WHERE login_key='rollback'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(n, 0);
    assert_eq!(f.account_events().await?, before + 1);
    let actor = f.actor().await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::RollbackFailedAfterAck);
    assert!(matches!(
        f.store
            .create_local_account(actor, login("rollback-failed"), password(), deadline())
            .await,
        Err(AuthorityError::RollbackFailed(_))
    ));
    sqlx::query("DROP TRIGGER reject_event ON rss_transactional_messaging.outbox")
        .execute(&f.owner)
        .await?;
    // Force a real duplicate outbox identity; the new companion account must roll back.
    sqlx::raw_sql("CREATE OR REPLACE FUNCTION public.reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.message_id := (SELECT message_id FROM rss_transactional_messaging.outbox WHERE tenant_id=NEW.tenant_id LIMIT 1); RETURN NEW; END $$; CREATE TRIGGER reject_event BEFORE INSERT ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.reject_event();").execute(&f.owner).await?;
    f.reset_attempts().await?;
    assert!(
        f.store
            .create_local_account(
                f.actor().await?,
                login("duplicate-event"),
                password(),
                deadline()
            )
            .await
            .is_err()
    );
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.local_credentials WHERE login_key='duplicate-event'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(n, 0);
    assert_eq!(f.account_events().await?, before + 1);
    sqlx::query("DROP TRIGGER reject_event ON rss_transactional_messaging.outbox")
        .execute(&f.owner)
        .await?;
    f.reset_attempts().await?;
    let actor = f.actor().await?;
    assert!(
        f.store
            .create_local_account(
                actor,
                login("expired"),
                password(),
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    Duration::ZERO
                )
            )
            .await
            .is_err()
    );
    assert_eq!(f.account_events().await?, before + 1);
    let foreign = AccountKey {
        tenant: TenantId::parse(B)?,
        principal: PrincipalId::generate(),
    };
    assert!(
        f.maintenance
            .recover_local_password(foreign, password(), deadline())
            .await
            .is_err()
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn storage_contract_is_checked() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    assert!(matches!(
        f.probe(AuthorityProfile::Maintenance).await,
        Err(AuthorityError::StorageIncompatible(
            StorageMismatch::Privileges
        ))
    ));
    for (break_sql, repair_sql, expected) in [
        // #2359: the retired namespace must never be accepted as a fallback.
        (
            "ALTER SCHEMA identity_authority RENAME TO access_authority",
            "ALTER SCHEMA access_authority RENAME TO identity_authority",
            StorageMismatch::SchemaContract,
        ),
        (
            "GRANT TRUNCATE ON identity_authority.accounts TO identity_runtime",
            "REVOKE TRUNCATE ON identity_authority.accounts FROM identity_runtime",
            StorageMismatch::Privileges,
        ),
        (
            "ALTER TABLE identity_authority.accounts DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE identity_authority.accounts ENABLE ROW LEVEL SECURITY",
            StorageMismatch::SchemaContract,
        ),
        (
            "ALTER POLICY tenant ON identity_authority.accounts USING(true)",
            "ALTER POLICY tenant ON identity_authority.accounts USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
            StorageMismatch::SchemaContract,
        ),
        (
            "GRANT UPDATE(authority_id) ON identity_authority.deployment TO identity_runtime",
            "REVOKE UPDATE(authority_id) ON identity_authority.deployment FROM identity_runtime",
            StorageMismatch::Privileges,
        ),
        (
            "GRANT identity_maintenance TO identity_runtime",
            "REVOKE identity_maintenance FROM identity_runtime",
            StorageMismatch::Privileges,
        ),
        (
            "ALTER TABLE identity_authority.local_credentials DROP CONSTRAINT local_credentials_tenant_id_login_key_key",
            "ALTER TABLE identity_authority.local_credentials ADD UNIQUE(tenant_id,login_key)",
            StorageMismatch::SchemaContract,
        ),
    ] {
        sqlx::raw_sql(break_sql).execute(&f.owner).await?;
        assert!(matches!(
            f.probe(AuthorityProfile::Runtime).await,
            Err(AuthorityError::StorageIncompatible(reason)) if reason == expected
        ));
        sqlx::raw_sql(repair_sql).execute(&f.owner).await?;
        assert!(f.probe(AuthorityProfile::Runtime).await.is_ok());
    }
    for (profile, role, runtime) in [
        (
            AuthorityProfile::Runtime,
            "identity_runtime",
            f.runtime.clone(),
        ),
        (
            AuthorityProfile::Maintenance,
            "identity_maintenance",
            f.maintenance_runtime.clone(),
        ),
    ] {
        for (table, privilege) in [
            ("accounts", "TRUNCATE"),
            ("memberships", "REFERENCES"),
            ("guard", "TRIGGER"),
            ("attempts", "TRUNCATE"),
            ("deployment", "TRIGGER"),
            ("schema_version", "UPDATE"),
        ]
        .into_iter()
        .chain(if profile == AuthorityProfile::Maintenance {
            vec![
                ("accounts", "UPDATE(principal_id)"),
                ("accounts", "UPDATE(enabled)"),
                ("memberships", "UPDATE(active)"),
                ("attempts", "SELECT"),
            ]
        } else {
            vec![("deployment", "UPDATE(authority_id)")]
        }) {
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "GRANT {privilege} ON identity_authority.{table} TO {role}"
            )))
            .execute(&f.owner)
            .await?;
            let result = match profile {
                rss_identity_postgres::AuthorityProfile::Runtime => {
                    Authority::connect_runtime(
                        runtime.clone(),
                        std::sync::Arc::new(rss_identity_core::account::PasswordKdf::new()),
                        f.config(),
                        f.policy.clone(),
                        deadline(),
                    )
                    .await
                }
                rss_identity_postgres::AuthorityProfile::Maintenance => {
                    Authority::connect_maintenance(
                        runtime.clone(),
                        std::sync::Arc::new(rss_identity_core::account::PasswordKdf::new()),
                        f.config(),
                        deadline(),
                    )
                    .await
                }
            };
            assert!(
                matches!(result, Err(AuthorityError::StorageIncompatible(_))),
                "accepted {profile:?} {table} {privilege}"
            );
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "REVOKE {privilege} ON identity_authority.{table} FROM {role}"
            )))
            .execute(&f.owner)
            .await?;
            match profile {
                rss_identity_postgres::AuthorityProfile::Runtime => {
                    Authority::connect_runtime(
                        runtime.clone(),
                        std::sync::Arc::new(rss_identity_core::account::PasswordKdf::new()),
                        f.config(),
                        f.policy.clone(),
                        deadline(),
                    )
                    .await
                }
                rss_identity_postgres::AuthorityProfile::Maintenance => {
                    Authority::connect_maintenance(
                        runtime.clone(),
                        std::sync::Arc::new(rss_identity_core::account::PasswordKdf::new()),
                        f.config(),
                        deadline(),
                    )
                    .await
                }
            }?;
        }
    }
    // A second database installs independently; the component creates no cluster-global roles.
    let collision = format!("collision_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {collision}")))
        .execute(&f.admin)
        .await?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::postgres::PgConnectOptions::new()
                .host("127.0.0.1")
                .port(f.port)
                .username("postgres")
                .password("fixture-only")
                .database(&collision),
        )
        .await?;
    sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await?;
    let absent: bool = sqlx::query_scalar("SELECT to_regnamespace('identity_authority') IS NULL")
        .fetch_one(&pool)
        .await?;
    assert!(!absent);
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {collision}")))
        .execute(&f.admin)
        .await?;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn source_budgets_are_shared() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    f.reset_attempts().await?;
    let other_runtime = f.additional_runtime().await?;
    let other = Authority::connect_runtime(
        other_runtime.clone(),
        std::sync::Arc::new(rss_identity_core::account::PasswordKdf::new()),
        f.config(),
        f.policy.clone(),
        deadline(),
    )
    .await?;
    let mut tasks = Vec::new();
    for i in 0..40 {
        let store = if i % 2 == 0 {
            f.store.clone()
        } else {
            other.clone()
        };
        let t = f.key.tenant;
        tasks.push(tokio::spawn(async move {
            store
                .verify_password(
                    t,
                    login(&format!("distinct-{i}")),
                    password(),
                    source(),
                    deadline(),
                )
                .await
        }));
    }
    let mut limited = 0;
    for t in tasks {
        if matches!(t.await?, Err(AuthorityError::RateLimited)) {
            limited += 1;
        }
    }
    assert_eq!(limited, 10);
    let count: i32 = sqlx::query_scalar(
        "SELECT count FROM identity_authority.attempts WHERE key='s:local-test'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(count, 30);
    other_runtime.close().await;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn fencing_and_generation_overflow() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    f.store
        .create_local_account(f.actor().await?, login("spare"), password(), deadline())
        .await?;
    let before = f.account_events().await?;
    for (setup, change) in [
        (
            "UPDATE identity_authority.accounts SET auth_epoch=9223372036854775807",
            AccountChange::Password(password()),
        ),
        (
            "UPDATE identity_authority.memberships SET epoch=9223372036854775807",
            AccountChange::Membership(false),
        ),
    ] {
        f.reset_attempts().await?;
        sqlx::raw_sql(setup).execute(&f.owner).await?;
        let before_rows:String=sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(a) ORDER BY principal_id)::text FROM identity_authority.accounts a").fetch_one(&f.owner).await?;
        assert_eq!(
            support::apply_change(&f.store, f.actor().await?, f.key, change, deadline())
                .await
                .unwrap_err(),
            AuthorityError::RuleRejected(AccountRuleError::EpochExhausted)
        );
        let after_rows:String=sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(a) ORDER BY principal_id)::text FROM identity_authority.accounts a").fetch_one(&f.owner).await?;
        // Avoid assertion formatting of stored credential data on failure.
        assert!(before_rows == after_rows);
        assert_eq!(f.account_events().await?, before);
        sqlx::raw_sql("UPDATE identity_authority.accounts SET auth_epoch=1; UPDATE identity_authority.memberships SET epoch=1;").execute(&f.owner).await?;
    }
    f.reset_attempts().await?;
    let actor = f.actor().await?;
    sqlx::query("UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2")
        .execute(&f.owner)
        .await?;
    assert_eq!(
        support::apply_change(
            &f.store,
            actor,
            f.key,
            AccountChange::Enabled(false),
            deadline()
        )
        .await
        .unwrap_err(),
        AuthorityError::Fenced
    );
    assert_eq!(f.account_events().await?, before);
    f.close().await;
    Ok(())
}

async fn assert_event(
    f: &Fixture,
    action: &str,
    key: AccountKey,
    actor: Option<AccountKey>,
    epoch: i64,
    state: Option<AccountState>,
) -> anyhow::Result<()> {
    let raw: String = sqlx::query_scalar(
        "SELECT envelope::text FROM rss_transactional_messaging.outbox ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_envelope(&raw, action, key, actor, epoch, state)
}

fn assert_envelope(
    raw: &str,
    action: &str,
    key: AccountKey,
    actor: Option<AccountKey>,
    epoch: i64,
    state: Option<AccountState>,
) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};
    let envelope: serde_json::Value = serde_json::from_str(raw)?;
    let bytes: Vec<u8> = serde_json::from_value(envelope["payload"].clone())?;
    let payload: serde_json::Value = serde_json::from_slice(&bytes)?;
    let expected_state = state.map(|s| serde_json::json!({"enabled":s.enabled(),"member_active":s.member_active(),"membership_epoch":s.membership_epoch()}));
    assert_eq!(
        payload,
        serde_json::json!({"action":action,"tenant":key.tenant.to_string(),"principal":key.principal.as_uuid(),"actor":actor.map(|a| a.principal.as_uuid()),"epoch":epoch,"state":expected_state})
    );
    assert_eq!(envelope["tenant"], key.tenant.to_string());
    assert_eq!(envelope["domain"], "identity.security");
    assert_eq!(envelope["route"], "account.changed");
    assert_eq!(envelope["contract"], "identity.account.security");
    assert_eq!(
        envelope["version"],
        rss_contract::ContractVersion::from_major(3)?.to_string()
    );
    assert_eq!(
        envelope["schema"],
        format!(
            "sha256:{:x}",
            Sha256::digest(include_str!("../security-event-v3.json"))
        )
    );
    assert!(uuid::Uuid::parse_str(envelope["id"].as_str().unwrap()).is_ok());
    assert!(envelope["occurred_at"].as_i64().unwrap() > 0);
    assert_eq!(envelope["attributes"], serde_json::json!({}));
    for field in [
        "correlation",
        "partition",
        "causation",
        "trace",
        "tenant_authority",
    ] {
        assert!(envelope[field].is_null());
    }
    // Exact payload keys above also exclude credentials, login, token, digest and provider data.
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn account_transition_matrix_and_events() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    assert_eq!(f.account_events().await?, 2);
    let denied = f.actor().await?;
    f.policy.revoke(f.key);
    let before = f.events().await?;
    assert_eq!(
        f.store
            .set_account_enabled(denied, f.key, false, deadline())
            .await
            .unwrap_err(),
        AuthorityError::RuleRejected(AccountRuleError::InsufficientPrivilege)
    );
    assert_eq!(f.events().await?, before);
    let actor = f.actor().await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::RollbackFailedAfterAck);
    assert!(matches!(
        f.store
            .set_account_enabled(actor, f.key, false, deadline())
            .await,
        Err(AuthorityError::RollbackFailed(_))
    ));
    f.policy.allow(f.key);
    let member = f
        .store
        .create_local_account(f.actor().await?, login("member"), password(), deadline())
        .await?;
    assert_event(
        &f,
        "account_created",
        member.key(),
        Some(f.key),
        1,
        Some(member),
    )
    .await?;
    let mut expected = member;
    for (change, action, active) in [
        (
            AccountChange::Membership(false),
            "membership_disabled",
            false,
        ),
        (AccountChange::Membership(true), "membership_enabled", true),
    ] {
        f.reset_attempts().await?;
        let old = f
            .store
            .verify_password(
                f.key.tenant,
                login("member"),
                password(),
                source(),
                deadline(),
            )
            .await
            .ok();
        let next =
            support::apply_change(&f.store, f.actor().await?, member.key(), change, deadline())
                .await?;
        assert_eq!(next.epoch(), expected.epoch() + 1);
        assert_eq!(
            next.membership_epoch(),
            expected.membership_epoch() + i64::from(expected.member_active() != active)
        );
        assert_eq!(next.member_active(), active);
        assert_event(
            &f,
            action,
            member.key(),
            Some(f.key),
            next.epoch(),
            Some(next),
        )
        .await?;
        let before = f.account_events().await?;
        if let Some(old) = old {
            assert_eq!(
                f.store
                    .create_session(old, None, deadline())
                    .await
                    .unwrap_err(),
                AuthorityError::Rejected
            );
        }
        assert_eq!(f.account_events().await?, before);
        assert_eq!(
            f.store
                .verify_password(
                    f.key.tenant,
                    login("member"),
                    password(),
                    source(),
                    deadline()
                )
                .await
                .is_ok(),
            active
        );
        expected = next;
    }
    f.reset_attempts().await?;
    let disabled = support::apply_change(
        &f.store,
        f.actor().await?,
        member.key(),
        AccountChange::Enabled(false),
        deadline(),
    )
    .await?;
    assert_event(
        &f,
        "account_disabled",
        member.key(),
        Some(f.key),
        disabled.epoch(),
        Some(disabled),
    )
    .await?;
    let enabled = support::apply_change(
        &f.store,
        f.actor().await?,
        member.key(),
        AccountChange::Enabled(true),
        deadline(),
    )
    .await?;
    assert_event(
        &f,
        "account_enabled",
        member.key(),
        Some(f.key),
        enabled.epoch(),
        Some(enabled),
    )
    .await?;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn maintenance_races_preserve_current_state() -> anyhow::Result<()> {
    // ref: postgres REL_17_STABLE src/test/isolation/README: explicit permutations
    // and observed pg_locks waits, never executor timing or sleeps for ordering.
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    for maintenance_first in [false, true] {
        for (i, change) in [
            AccountChange::Enabled(false),
            AccountChange::Membership(false),
            AccountChange::Password(Password::new("daily replacement password".into())?),
        ]
        .into_iter()
        .enumerate()
        {
            f.reset_attempts().await?;
            let name = format!("race-{maintenance_first}-{i}");
            let target = f
                .store
                .create_local_account(f.actor().await?, login(&name), password(), deadline())
                .await?;
            let actor = f.actor().await?;
            let before_seq: i64 =
                sqlx::query_scalar("SELECT max(seq) FROM rss_transactional_messaging.outbox")
                    .fetch_one(&f.owner)
                    .await?;
            let first_role = if maintenance_first {
                "identity_maintenance"
            } else {
                "identity_runtime"
            };
            let second_role = if maintenance_first {
                "identity_runtime"
            } else {
                "identity_maintenance"
            };
            // Pause the first writer after it reads state, inside its account UPDATE.
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "CREATE FUNCTION public.pause_first_writer() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
                 IF current_user='{first_role}' THEN PERFORM pg_advisory_xact_lock(2358,1); END IF;
                 RETURN NEW; END $$;
                 CREATE TRIGGER pause_first_writer BEFORE UPDATE ON identity_authority.accounts
                 FOR EACH ROW EXECUTE FUNCTION public.pause_first_writer();"
            ))).execute(&f.owner).await?;
            let mut controller = f.owner.acquire().await?;
            sqlx::query("SELECT pg_advisory_lock(2358,1)")
                .execute(&mut *controller)
                .await?;
            let store = f.store.clone();
            let maintenance = f.maintenance.clone();
            let key = target.key();
            let runtime_write =
                async move { support::apply_change(&store, actor, key, change, deadline()).await };
            let maintenance_write = async move {
                maintenance
                    .recover_local_password(
                        key,
                        Password::new("maintenance replacement password".into()).unwrap(),
                        deadline(),
                    )
                    .await
            };
            let (first, second_work): (
                _,
                futures::future::BoxFuture<'static, Result<AccountState, AuthorityError>>,
            ) = if maintenance_first {
                (tokio::spawn(maintenance_write), Box::pin(runtime_write))
            } else {
                (tokio::spawn(runtime_write), Box::pin(maintenance_write))
            };
            let first_wait = wait_for_writer_lock(&f.owner, first_role, None).await;
            let second = first_wait.as_ref().ok().map(|_| tokio::spawn(second_work));
            let overlap = match first_wait {
                Ok(first_pid) => wait_for_writer_lock(&f.owner, second_role, Some(first_pid))
                    .await
                    .map(|_| ()),
                Err(error) => Err(error),
            };
            // Release and join even when a mutant fails the synchronization assertion.
            sqlx::query("SELECT pg_advisory_unlock(2358,1)")
                .execute(&mut *controller)
                .await?;
            let first_result = first.await?;
            let second_result = match second {
                Some(job) => Some(job.await?),
                None => None,
            };
            drop(controller);
            sqlx::raw_sql("DROP TRIGGER pause_first_writer ON identity_authority.accounts; DROP FUNCTION public.pause_first_writer();").execute(&f.owner).await?;
            overlap?;
            let second_result = second_result.expect("overlap requires the second writer");
            let (changed, recovered) = if maintenance_first {
                (second_result, first_result)
            } else {
                (first_result, second_result)
            };
            let changed = changed?;
            let recovery_succeeds = true;
            if recovery_succeeds {
                assert!(recovered.is_ok());
            } else {
                assert_eq!(recovered.as_ref().unwrap_err(), &AuthorityError::Rejected);
            }
            let row: (bool,bool,i64,i64) = sqlx::query_as("SELECT a.enabled,m.active,a.auth_epoch,m.epoch FROM identity_authority.accounts a JOIN identity_authority.memberships m USING(tenant_id,principal_id) WHERE a.tenant_id=$1::uuid AND a.principal_id=$2::uuid")
                .bind(key.tenant.to_string()).bind(key.principal.as_uuid().to_string()).fetch_one(&f.owner).await?;
            assert_eq!((row.0, row.1), (i != 0, i != 1));
            assert_eq!(
                (row.2, row.3),
                (2 + i64::from(recovery_succeeds), 1 + i64::from(i == 1))
            );
            let expected_password = if i == 2 && maintenance_first {
                "daily replacement password"
            } else if recovery_succeeds {
                "maintenance replacement password"
            } else {
                PASSWORD
            };
            let hash: String = sqlx::query_scalar("SELECT password_hash FROM identity_authority.local_credentials WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
                .bind(key.tenant.to_string()).bind(key.principal.as_uuid().to_string()).fetch_one(&f.owner).await?;
            assert!(
                PasswordKdf::new()
                    .verify(
                        Password::new(expected_password.into())?,
                        rss_identity_core::account::PasswordEncoding::from_storage(hash)?
                    )
                    .await?
            );
            let action = [
                "account_disabled",
                "membership_disabled",
                "password_changed",
            ][i];
            let mut expected = vec![(action, Some(f.key), changed)];
            if let Ok(recovered) = recovered {
                if maintenance_first {
                    expected.insert(0, ("password_recovered", None, recovered));
                } else {
                    expected.push(("password_recovered", None, recovered));
                }
            }
            let events: Vec<String> = sqlx::query_scalar("SELECT envelope::text FROM rss_transactional_messaging.outbox WHERE seq>$1 ORDER BY seq").bind(before_seq).fetch_all(&f.owner).await?;
            assert_eq!(events.len(), expected.len());
            for (index, (raw, (action, actor, state))) in events.iter().zip(expected).enumerate() {
                assert_eq!(state.epoch(), 2 + index as i64);
                assert_envelope(raw, action, key, actor, state.epoch(), Some(state))?;
            }
        }
    }
    f.close().await;
    Ok(())
}

async fn wait_for_writer_lock(
    owner: &sqlx::PgPool,
    role: &str,
    blocker: Option<i32>,
) -> anyhow::Result<i32> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let wait: Option<(i32,String)> = sqlx::query_as("SELECT a.pid,a.query FROM pg_stat_activity a WHERE a.datname=current_database() AND a.usename=$1 AND a.wait_event_type='Lock' AND ($2::int IS NULL OR $2=ANY(pg_blocking_pids(a.pid)))")
            .bind(role).bind(blocker).fetch_optional(owner).await?;
        if let Some((pid, query)) = wait {
            if blocker.is_some() {
                anyhow::ensure!(
                    query.contains("identity_authority.guard"),
                    "second writer bypassed the tenant guard"
                );
                return Ok(pid);
            }
            let at_gate: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted AND classid=2358 AND objid=1)").bind(pid).fetch_one(owner).await?;
            if at_gate {
                return Ok(pid);
            }
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "writer did not reach its expected database lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn maintenance_permissions_and_schema_are_exact() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    for role in ["identity_runtime", "identity_maintenance"] {
        let valid: bool = sqlx::query_scalar(
            "SELECT has_table_privilege($1,'rss_transactional_messaging.outbox','SELECT')
              AND NOT has_table_privilege($1,'rss_transactional_messaging.outbox','INSERT')
              AND NOT has_sequence_privilege($1,'rss_transactional_messaging.outbox_seq_seq','USAGE,SELECT,UPDATE')
              AND has_function_privilege($1,'rss_transactional_messaging.prepare_outbox_partitions(jsonb)','EXECUTE')
              AND has_function_privilege($1,'rss_transactional_messaging.append_outbox(bytea,jsonb)','EXECUTE')",
        ).bind(role).fetch_one(&f.owner).await?;
        assert!(valid, "profile must use the public Outbox write contract");
    }
    for query in [
        "UPDATE identity_authority.accounts SET enabled=true",
        "UPDATE identity_authority.accounts SET principal_id=gen_random_uuid()",
        "UPDATE identity_authority.memberships SET active=true",
        "SELECT * FROM identity_authority.attempts",
    ] {
        let result = f
            .maintenance_runtime
            .local_tx(f.key.tenant, deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move { sqlx::query(query).execute(c).await.map(|_| ()) })
                    })
                    .await
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err);
        assert!(result.is_err(), "maintenance accepted forbidden operation");
    }
    let result = f
        .runtime
        .local_tx(f.key.tenant, deadline(), |tx| {
            Box::pin(async move {
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query("UPDATE identity_authority.deployment SET authority_id=gen_random_uuid()")
                            .execute(c)
                            .await
                            .map(|_| ())
                    })
                })
                .await
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err);
    assert!(result.is_err());
    sqlx::raw_sql("ALTER TABLE identity_authority.schema_version DROP CONSTRAINT schema_version_version_check; UPDATE identity_authority.schema_version SET version=1").execute(&f.owner).await?;
    assert!(matches!(
        f.probe(AuthorityProfile::Runtime).await,
        Err(AuthorityError::StorageIncompatible(
            StorageMismatch::SchemaVersion
        ))
    ));
    sqlx::raw_sql("UPDATE identity_authority.schema_version SET version=11; ALTER TABLE identity_authority.schema_version ADD CHECK(version=11)").execute(&f.owner).await?;
    assert!(f.probe(AuthorityProfile::Runtime).await.is_ok());
    for (remove, restore, expected) in [
        (
            "ALTER TABLE identity_authority.attempts RENAME TO temporarily_absent_attempts",
            "ALTER TABLE identity_authority.temporarily_absent_attempts RENAME TO attempts",
            StorageMismatch::SchemaContract,
        ),
        (
            "ALTER TABLE identity_authority.schema_version RENAME TO temporarily_absent_version",
            "ALTER TABLE identity_authority.temporarily_absent_version RENAME TO schema_version",
            StorageMismatch::SchemaContract,
        ),
    ] {
        sqlx::raw_sql(remove).execute(&f.owner).await?;
        assert!(
            matches!(f.probe(AuthorityProfile::Runtime).await, Err(AuthorityError::StorageIncompatible(reason)) if reason == expected)
        );
        sqlx::raw_sql(restore).execute(&f.owner).await?;
        assert!(f.probe(AuthorityProfile::Runtime).await.is_ok());
    }
    for (remove, restore) in [
        (
            "REVOKE USAGE ON SCHEMA identity_authority FROM identity_runtime",
            "GRANT USAGE ON SCHEMA identity_authority TO identity_runtime",
        ),
        (
            "REVOKE SELECT ON identity_authority.schema_version FROM identity_runtime",
            "GRANT SELECT ON identity_authority.schema_version TO identity_runtime",
        ),
    ] {
        sqlx::raw_sql(remove).execute(&f.owner).await?;
        assert!(matches!(
            f.probe(AuthorityProfile::Runtime).await,
            Err(AuthorityError::StorageIncompatible(
                StorageMismatch::Privileges
            ))
        ));
        sqlx::raw_sql(restore).execute(&f.owner).await?;
        assert!(f.probe(AuthorityProfile::Runtime).await.is_ok());
    }
    // Effective inherited and PUBLIC privileges must also be rejected.
    for (grant, revoke) in [
        (
            "GRANT UPDATE ON identity_authority.deployment TO PUBLIC",
            "REVOKE UPDATE ON identity_authority.deployment FROM PUBLIC",
        ),
        (
            "GRANT SELECT ON identity_authority.accounts TO identity_runtime WITH GRANT OPTION",
            "REVOKE GRANT OPTION FOR SELECT ON identity_authority.accounts FROM identity_runtime",
        ),
    ] {
        sqlx::raw_sql(grant).execute(&f.owner).await?;
        assert!(matches!(
            f.probe(AuthorityProfile::Runtime).await,
            Err(AuthorityError::StorageIncompatible(_))
        ));
        sqlx::raw_sql(revoke).execute(&f.owner).await?;
        assert!(f.probe(AuthorityProfile::Runtime).await.is_ok());
    }
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn maintenance_deadline_fencing_and_overflow() -> anyhow::Result<()> {
    use rss_transactional_messaging::policy::OperationDeadline;
    let f = Fixture::new().await?;
    assert!(
        f.maintenance
            .initialize(
                f.key,
                login("admin"),
                password(),
                OperationDeadline::from_remaining(Duration::ZERO)
            )
            .await
            .is_err()
    );
    assert_eq!(f.account_events().await?, 0);
    f.bootstrap().await?;
    assert!(
        f.maintenance
            .recover_local_password(
                f.key,
                password(),
                OperationDeadline::from_remaining(Duration::ZERO)
            )
            .await
            .is_err()
    );
    for column in ["auth_epoch"] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "UPDATE identity_authority.accounts SET {column}=9223372036854775807"
        )))
        .execute(&f.owner)
        .await?;
        assert_eq!(
            f.maintenance
                .recover_local_password(f.key, password(), deadline())
                .await
                .unwrap_err(),
            AuthorityError::RuleRejected(AccountRuleError::EpochExhausted)
        );
        assert_eq!(f.account_events().await?, 2);
        sqlx::raw_sql("UPDATE identity_authority.accounts SET auth_epoch=1")
            .execute(&f.owner)
            .await?;
    }
    sqlx::raw_sql("UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2")
        .execute(&f.owner)
        .await?;
    assert_eq!(
        f.maintenance
            .recover_local_password(f.key, password(), deadline())
            .await
            .unwrap_err(),
        AuthorityError::Fenced
    );
    assert_eq!(
        f.maintenance
            .initialize(f.system_key, login("platform"), password(), deadline())
            .await
            .unwrap_err(),
        AuthorityError::Fenced
    );
    assert_eq!(f.account_events().await?, 2);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn maintenance_runbook_respects_forced_rls() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let other = AccountKey {
        tenant: TenantId::parse(B)?,
        principal: f.key.principal,
    };
    f.maintenance
        .initialize(other, login("admin"), password(), deadline())
        .await?;
    let rows = f
        .maintenance_runtime
        .local_tx(f.key.tenant, deadline(), |tx| {
            Box::pin(async move {
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query_scalar::<_, String>(
                            "SELECT tenant_id::text FROM identity_authority.accounts",
                        )
                        .fetch_all(c)
                        .await
                    })
                })
                .await
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    assert_eq!(rows, vec![A.to_string()]);
    let old = f
        .store
        .set_account_enabled(f.actor().await?, f.key, false, deadline())
        .await?;
    let reset = f
        .maintenance
        .recover_local_password(f.key, password(), deadline())
        .await?;
    assert!(!reset.enabled());
    assert_eq!(reset.epoch(), old.epoch() + 1);
    let untouched: i64 = sqlx::query_scalar(
        "SELECT auth_epoch FROM identity_authority.accounts WHERE tenant_id=$1::uuid",
    )
    .bind(B)
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(untouched, 1);
    f.close().await;
    Ok(())
}
