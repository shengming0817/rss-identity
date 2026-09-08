//! Canonical real PostgreSQL account scenarios; the provider runner owns the exact test set.
use access_core::account::{AccountChange, AccountKey, AccountRuleError, AccountState};
mod support;
use access_core::{
    PrincipalId,
    account::{Password, PasswordKdf},
};
use access_postgres::*;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgTransactionFault;
use std::time::Duration;
use support::*;

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn initialization_and_recovery() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    assert!(
        f.store
            .issue_authorization(f.key, AuthorizationPurpose::Initialize, deadline())
            .await
            .is_err()
    );
    let first = f
        .issuer
        .issue_authorization(f.key, AuthorizationPurpose::Initialize, deadline())
        .await?;
    assert_event(&f, "initialization_authorized", f.key, None, 0, None).await?;
    let grant = f
        .issuer
        .issue_authorization(f.key, AuthorizationPurpose::Initialize, deadline())
        .await?;
    assert!(
        f.store
            .initialize(
                f.key,
                login("admin"),
                password(),
                first.into_secret(),
                source(),
                deadline()
            )
            .await
            .is_err()
    );
    let mut jobs = Vec::new();
    for _ in 0..4 {
        let s = f.store.clone();
        let key = f.key;
        let secret = token(grant.secret());
        jobs.push(tokio::spawn(async move {
            s.initialize(
                key,
                login("admin"),
                password(),
                secret,
                source(),
                deadline(),
            )
            .await
        }));
    }
    let mut successes = 0;
    for j in jobs {
        if j.await?.is_ok() {
            successes += 1;
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(f.events().await?, 3); // two issuance events + one initialization
    assert!(
        f.issuer
            .issue_authorization(f.key, AuthorizationPurpose::Initialize, deadline())
            .await
            .is_err()
    );
    f.reset_attempts().await?;
    let emergency = f
        .store
        .create_account(
            f.actor().await?,
            login("emergency"),
            password(),
            true,
            true,
            deadline(),
        )
        .await?;
    assert_event(
        &f,
        "account_created",
        emergency.key(),
        Some(f.key),
        1,
        Some(emergency),
    )
    .await?;
    let disabled = f
        .store
        .change_account(
            f.actor().await?,
            emergency.key(),
            AccountChange::Enabled(false),
            deadline(),
        )
        .await?;
    assert_event(
        &f,
        "account_disabled",
        emergency.key(),
        Some(f.key),
        2,
        Some(disabled),
    )
    .await?;
    let g = f
        .issuer
        .issue_authorization(emergency.key(), AuthorizationPurpose::Recover, deadline())
        .await?;
    assert_event(&f, "recovery_authorized", emergency.key(), None, 2, None).await?;
    let stale = token(g.secret());
    let recovered = f
        .store
        .recover_administrator(
            emergency.key(),
            password(),
            g.into_secret(),
            source(),
            deadline(),
        )
        .await?;
    assert_event(
        &f,
        "administrator_recovered",
        emergency.key(),
        None,
        3,
        Some(recovered),
    )
    .await?;
    assert!(!recovered.enabled());
    assert!(recovered.administrator());
    assert_eq!(recovered.epoch(), 3);
    assert!(
        f.store
            .recover_administrator(emergency.key(), password(), stale, source(), deadline())
            .await
            .is_err()
    );
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
    let g = f
        .issuer
        .issue_authorization(f.key, AuthorizationPurpose::Recover, deadline())
        .await?;
    let changed = f
        .store
        .change_account(
            f.actor().await?,
            f.key,
            AccountChange::Password(password()),
            deadline(),
        )
        .await?;
    assert_event(&f, "password_changed", f.key, Some(f.key), 2, Some(changed)).await?;
    assert_eq!(changed.epoch(), 2);
    assert!(
        f.store
            .recover_administrator(f.key, password(), g.into_secret(), source(), deadline())
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
        .create_account(
            f.actor().await?,
            login("second"),
            password(),
            true,
            false,
            deadline(),
        )
        .await?;
    let old = f.actor().await?;
    let actor = f.actor().await?;
    f.store
        .change_account(
            actor,
            f.key,
            AccountChange::Password(password()),
            deadline(),
        )
        .await?;
    assert!(
        f.store
            .create_account(old, login("stale"), password(), false, false, deadline())
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
            .create_account(
                f.actor().await?,
                login(&name),
                password(),
                true,
                false,
                deadline(),
            )
            .await?;
        let actor = f.actor().await?;
        let issued = if *mode == "recovery" {
            Some(
                f.issuer
                    .issue_authorization(victim.key(), AuthorizationPurpose::Recover, deadline())
                    .await?,
            )
        } else {
            None
        };
        let change = async {
            if let Some(g) = issued {
                f.store
                    .recover_administrator(
                        victim.key(),
                        Password::new("a newly recovered password".into())?,
                        g.into_secret(),
                        source(),
                        deadline(),
                    )
                    .await
            } else {
                f.store
                    .change_account(
                        actor,
                        victim.key(),
                        if *mode == "disable" {
                            AccountChange::Enabled(false)
                        } else {
                            AccountChange::Password(Password::new(
                                "a newly changed password".into(),
                            )?)
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
                    .change_account(
                        candidate,
                        victim.key(),
                        AccountChange::Password(password()),
                        deadline()
                    )
                    .await
                    .is_err()
            );
        }
        f.store
            .change_account(
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
    let (ra, rb) = tokio::join!(
        f.store
            .change_account(a, f.key, AccountChange::Enabled(false), deadline()),
        f.store
            .change_account(b, second.key(), AccountChange::Enabled(false), deadline())
    );
    assert_eq!(usize::from(ra.is_ok()) + usize::from(rb.is_ok()), 1);
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM access_authority.accounts WHERE administrator AND enabled",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(n, 1);
    // Same global principal in another tenant has an independent local credential and epoch.
    let other = AccountKey {
        tenant: TenantId::parse(B)?,
        principal: f.key.principal,
    };
    let hash = PasswordKdf::new()
        .hash(Password::new("other tenant secret password".into())?)
        .await?;
    sqlx::query("INSERT INTO access_authority.accounts(tenant_id,principal_id,login_key,password_hash,administrator) VALUES($1::uuid,$2::uuid,'admin',$3,true)").bind(B).bind(other.principal.as_uuid().to_string()).bind(hash.as_str()).execute(&f.owner).await?;
    sqlx::query("INSERT INTO access_authority.memberships(tenant_id,principal_id) VALUES($1::uuid,$2::uuid)").bind(B).bind(other.principal.as_uuid().to_string()).execute(&f.owner).await?;
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
    assert!(
        f.store
            .change_account(other_actor, f.key, AccountChange::Enabled(true), deadline())
            .await
            .is_err()
    );
    let before: i64 = sqlx::query_scalar(
        "SELECT auth_epoch FROM access_authority.accounts WHERE tenant_id=$1::uuid",
    )
    .bind(B)
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(before, 1);
    let result=f.runtime.local_tx(f.key.tenant,deadline(),|tx|Box::pin(async move {tx.with_connection(|c|Box::pin(async move {sqlx::query("UPDATE access_authority.accounts SET auth_epoch=99 WHERE tenant_id='22222222-2222-4222-8222-222222222222'").execute(c).await.map(|r|r.rows_affected())})).await})).await.fold(Ok,Err,Err,Err,Err,Err)?;
    assert_eq!(result, 0);
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
        sqlx::query_scalar("SELECT count FROM access_authority.attempts WHERE key='p:unknown'")
            .fetch_one(&f.owner)
            .await?;
    assert_eq!(count, 5);
    f.reset_attempts().await?;
    sqlx::query("INSERT INTO access_authority.attempts SELECT $1::uuid,'full:'||i,1,clock_timestamp()+interval '1 hour' FROM generate_series(1,10000) i").bind(A).execute(&f.owner).await?;
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
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM access_authority.attempts")
        .fetch_one(&f.owner)
        .await?;
    assert_eq!(n, 10000);
    sqlx::query(
        "UPDATE access_authority.attempts SET expires_at=clock_timestamp()-interval '1 second'",
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
    f.issuer_runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        f.issuer
            .issue_authorization(f.key, AuthorizationPurpose::Initialize, deadline())
            .await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    f.bootstrap().await?;
    let before = f.events().await?;
    let actor = f.actor().await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        f.store
            .create_account(
                actor,
                login("unknown-commit"),
                password(),
                false,
                false,
                deadline()
            )
            .await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    assert_eq!(f.events().await?, before + 1);
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM access_authority.accounts WHERE login_key='unknown-commit'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(n, 1);
    // Event failure rolls back the actual companion account and membership.
    sqlx::raw_sql("CREATE FUNCTION public.reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic secret must not escape'; END $$; CREATE TRIGGER reject_event BEFORE INSERT ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.reject_event();").execute(&f.owner).await?;
    let actor = f.actor().await?;
    let result = f
        .store
        .create_account(
            actor,
            login("rollback"),
            password(),
            false,
            false,
            deadline(),
        )
        .await;
    assert!(matches!(result, Err(AuthorityError::RolledBack(_))));
    assert!(!format!("{result:?}").contains("synthetic secret"));
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM access_authority.accounts WHERE login_key='rollback'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(n, 0);
    assert_eq!(f.events().await?, before + 1);
    let actor = f.actor().await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::RollbackFailedAfterAck);
    assert!(matches!(
        f.store
            .create_account(
                actor,
                login("rollback-failed"),
                password(),
                false,
                false,
                deadline()
            )
            .await,
        Err(AuthorityError::RollbackFailed(_))
    ));
    sqlx::query("DROP TRIGGER reject_event ON rss_transactional_messaging.outbox")
        .execute(&f.owner)
        .await?;
    // Force a real duplicate outbox identity; the new companion account must roll back.
    sqlx::raw_sql("CREATE OR REPLACE FUNCTION public.reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.message_id := (SELECT message_id FROM rss_transactional_messaging.outbox LIMIT 1); RETURN NEW; END $$; CREATE TRIGGER reject_event BEFORE INSERT ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.reject_event();").execute(&f.owner).await?;
    f.reset_attempts().await?;
    assert!(
        f.store
            .create_account(
                f.actor().await?,
                login("duplicate-event"),
                password(),
                false,
                false,
                deadline()
            )
            .await
            .is_err()
    );
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM access_authority.accounts WHERE login_key='duplicate-event'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(n, 0);
    assert_eq!(f.events().await?, before + 1);
    sqlx::query("DROP TRIGGER reject_event ON rss_transactional_messaging.outbox")
        .execute(&f.owner)
        .await?;
    f.reset_attempts().await?;
    let actor = f.actor().await?;
    assert!(
        f.store
            .create_account(
                actor,
                login("expired"),
                password(),
                false,
                false,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    Duration::ZERO
                )
            )
            .await
            .is_err()
    );
    assert_eq!(f.events().await?, before + 1);
    let foreign = AccountKey {
        tenant: TenantId::parse(B)?,
        principal: PrincipalId::generate(),
    };
    let g = f
        .issuer
        .issue_authorization(f.key, AuthorizationPurpose::Recover, deadline())
        .await?;
    assert!(
        f.store
            .recover_administrator(foreign, password(), token(g.secret()), source(), deadline())
            .await
            .is_err()
    );
    sqlx::query("UPDATE access_authority.authorizations SET expires_at=clock_timestamp()-interval '1 second'").execute(&f.owner).await?;
    assert!(
        f.store
            .recover_administrator(f.key, password(), g.into_secret(), source(), deadline())
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
        f.probe(AuthorityProfile::Issuer).await,
        Err(AuthorityError::StorageIncompatible)
    ));
    for (break_sql, repair_sql) in [
        (
            "GRANT TRUNCATE ON access_authority.accounts TO access_runtime",
            "REVOKE TRUNCATE ON access_authority.accounts FROM access_runtime",
        ),
        (
            "ALTER TABLE access_authority.accounts DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE access_authority.accounts ENABLE ROW LEVEL SECURITY",
        ),
        (
            "ALTER POLICY tenant ON access_authority.accounts USING(true)",
            "ALTER POLICY tenant ON access_authority.accounts USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
        ),
        (
            "GRANT INSERT ON access_authority.authorizations TO access_runtime",
            "REVOKE INSERT ON access_authority.authorizations FROM access_runtime",
        ),
        (
            "GRANT access_authorization_issuer TO access_runtime",
            "REVOKE access_authorization_issuer FROM access_runtime",
        ),
        (
            "ALTER TABLE access_authority.accounts DROP CONSTRAINT accounts_tenant_id_login_key_key",
            "ALTER TABLE access_authority.accounts ADD UNIQUE(tenant_id,login_key)",
        ),
    ] {
        sqlx::raw_sql(break_sql).execute(&f.owner).await?;
        assert!(matches!(
            f.probe(AuthorityProfile::Runtime).await,
            Err(AuthorityError::StorageIncompatible)
        ));
        sqlx::raw_sql(repair_sql).execute(&f.owner).await?;
        assert!(f.probe(AuthorityProfile::Runtime).await.is_ok());
    }
    for (profile, role, runtime) in [
        (
            AuthorityProfile::Runtime,
            "access_runtime",
            f.runtime.clone(),
        ),
        (
            AuthorityProfile::Issuer,
            "access_issuer",
            f.issuer_runtime.clone(),
        ),
    ] {
        for (table, privilege) in [
            ("accounts", "TRUNCATE"),
            ("memberships", "REFERENCES"),
            ("guard", "TRIGGER"),
            ("attempts", "TRUNCATE"),
            ("authorizations", "REFERENCES"),
            ("deployment", "TRIGGER"),
            ("schema_version", "UPDATE"),
        ]
        .into_iter()
        .chain(if profile == AuthorityProfile::Issuer {
            vec![
                ("accounts", "UPDATE(administrator)"),
                ("accounts", "INSERT(tenant_id)"),
                ("memberships", "SELECT(tenant_id)"),
            ]
        } else {
            vec![
                ("authorizations", "UPDATE(account_epoch)"),
                ("deployment", "UPDATE(authority_id)"),
            ]
        }) {
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "GRANT {privilege} ON access_authority.{table} TO {role}"
            )))
            .execute(&f.owner)
            .await?;
            let result = Authority::connect(
                runtime.clone(),
                rss_transactional_messaging::policy::DeliveryBudget::new(
                    Duration::from_secs(60),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )?,
                f.key.tenant,
                profile,
                deadline(),
            )
            .await;
            assert!(
                matches!(result, Err(AuthorityError::StorageIncompatible)),
                "accepted {profile:?} {table} {privilege}"
            );
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "REVOKE {privilege} ON access_authority.{table} FROM {role}"
            )))
            .execute(&f.owner)
            .await?;
            Authority::connect(
                runtime.clone(),
                rss_transactional_messaging::policy::DeliveryBudget::new(
                    Duration::from_secs(60),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )?,
                f.key.tenant,
                profile,
                deadline(),
            )
            .await?;
        }
    }
    // A second database cannot silently adopt the existing global roles, even if their names match.
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
    assert!(sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.is_err());
    let absent: bool = sqlx::query_scalar("SELECT to_regnamespace('access_authority') IS NULL")
        .fetch_one(&pool)
        .await?;
    assert!(absent);
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {collision}")))
        .execute(&f.admin)
        .await?;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn source_and_authorization_budgets() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    f.reset_attempts().await?;
    let other_runtime = f.additional_runtime().await?;
    let other = Authority::connect(
        other_runtime.clone(),
        rss_transactional_messaging::policy::DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )?,
        f.key.tenant,
        AuthorityProfile::Runtime,
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
    let count: i32 =
        sqlx::query_scalar("SELECT count FROM access_authority.attempts WHERE key='s:local-test'")
            .fetch_one(&f.owner)
            .await?;
    assert_eq!(count, 30);
    for purpose in [
        AuthorizationPurpose::Initialize,
        AuthorizationPurpose::Recover,
    ] {
        f.reset_attempts().await?;
        for i in 0..6 {
            let store = if i % 2 == 0 { &f.store } else { &other };
            let secret = AuthorizationSecret::parse("0".repeat(64))?;
            let result = if purpose == AuthorizationPurpose::Initialize {
                store
                    .initialize(
                        f.key,
                        login("admin"),
                        password(),
                        secret,
                        source(),
                        deadline(),
                    )
                    .await
            } else {
                store
                    .recover_administrator(f.key, password(), secret, source(), deadline())
                    .await
            };
            assert_eq!(
                result.unwrap_err(),
                if i < 5 {
                    AuthorityError::Rejected
                } else {
                    AuthorityError::RateLimited
                }
            );
        }
    }
    // Invalid authorization targets still share the trusted source budget.
    f.reset_attempts().await?;
    for i in 0..31 {
        let key = AccountKey {
            tenant: f.key.tenant,
            principal: PrincipalId::generate(),
        };
        let result = other
            .recover_administrator(
                key,
                password(),
                AuthorizationSecret::parse("0".repeat(64))?,
                source(),
                deadline(),
            )
            .await;
        assert_eq!(
            result.unwrap_err(),
            if i < 30 {
                AuthorityError::Rejected
            } else {
                AuthorityError::RateLimited
            }
        );
    }
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
        .create_account(
            f.actor().await?,
            login("spare"),
            password(),
            true,
            false,
            deadline(),
        )
        .await?;
    let before = f.events().await?;
    for (setup, change) in [
        (
            "UPDATE access_authority.accounts SET auth_epoch=9223372036854775807",
            AccountChange::Password(password()),
        ),
        (
            "UPDATE access_authority.accounts SET credential_version=9223372036854775807",
            AccountChange::Password(password()),
        ),
        (
            "UPDATE access_authority.memberships SET epoch=9223372036854775807",
            AccountChange::Membership(false),
        ),
    ] {
        f.reset_attempts().await?;
        sqlx::raw_sql(setup).execute(&f.owner).await?;
        let before_rows:String=sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(a) ORDER BY principal_id)::text FROM access_authority.accounts a").fetch_one(&f.owner).await?;
        assert_eq!(
            f.store
                .change_account(f.actor().await?, f.key, change, deadline())
                .await
                .unwrap_err(),
            AuthorityError::RuleRejected(AccountRuleError::EpochExhausted)
        );
        let after_rows:String=sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(a) ORDER BY principal_id)::text FROM access_authority.accounts a").fetch_one(&f.owner).await?;
        // Avoid assertion formatting of stored credential data on failure.
        assert!(before_rows == after_rows);
        assert_eq!(f.events().await?, before);
        sqlx::raw_sql("UPDATE access_authority.accounts SET auth_epoch=1,credential_version=1; UPDATE access_authority.memberships SET epoch=1;").execute(&f.owner).await?;
    }
    f.reset_attempts().await?;
    let actor = f.actor().await?;
    sqlx::query("UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2")
        .execute(&f.owner)
        .await?;
    assert_eq!(
        f.store
            .change_account(actor, f.key, AccountChange::Enabled(false), deadline())
            .await
            .unwrap_err(),
        AuthorityError::Fenced
    );
    assert_eq!(f.events().await?, before);
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
    use sha2::{Digest, Sha256};
    let raw: String = sqlx::query_scalar(
        "SELECT envelope::text FROM rss_transactional_messaging.outbox ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(&f.owner)
    .await?;
    let envelope: serde_json::Value = serde_json::from_str(&raw)?;
    let bytes: Vec<u8> = serde_json::from_value(envelope["payload"].clone())?;
    let payload: serde_json::Value = serde_json::from_slice(&bytes)?;
    let expected_state = state.map(|s| serde_json::json!({"enabled":s.enabled(),"administrator":s.administrator(),"emergency":s.emergency(),"member_active":s.member_active(),"credential_version":s.credential_version(),"membership_epoch":s.membership_epoch()}));
    assert_eq!(
        payload,
        serde_json::json!({"action":action,"tenant":key.tenant.to_string(),"principal":key.principal.as_uuid(),"actor":actor.map(|a| a.principal.as_uuid()),"epoch":epoch,"state":expected_state})
    );
    assert_eq!(envelope["tenant"], key.tenant.to_string());
    assert_eq!(envelope["domain"], "access.security");
    assert_eq!(envelope["route"], "account.changed");
    assert_eq!(envelope["contract"], "access.account.security");
    assert_eq!(
        envelope["version"],
        rss_contract::ContractVersion::from_major(1)?.to_string()
    );
    assert_eq!(
        envelope["schema"],
        format!(
            "sha256:{:x}",
            Sha256::digest(include_str!("../src/security-event-v1.json"))
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
    assert_event(
        &f,
        "initialized",
        f.key,
        None,
        1,
        Some(AccountState::new_local(f.key, true, false)?),
    )
    .await?;
    for change in [
        AccountChange::Administrator(false),
        AccountChange::Membership(false),
        AccountChange::Enabled(false),
    ] {
        let before = f.events().await?;
        assert_eq!(
            f.store
                .change_account(f.actor().await?, f.key, change, deadline())
                .await
                .unwrap_err(),
            AuthorityError::RuleRejected(AccountRuleError::LastAdministrator)
        );
        assert_eq!(f.events().await?, before);
    }
    let actor = f.actor().await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::RollbackFailedAfterAck);
    assert!(matches!(
        f.store
            .change_account(
                actor,
                f.key,
                AccountChange::Administrator(false),
                deadline()
            )
            .await,
        Err(AuthorityError::RollbackFailed(_))
    ));
    f.reset_attempts().await?;
    let member = f
        .store
        .create_account(
            f.actor().await?,
            login("member"),
            password(),
            false,
            false,
            deadline(),
        )
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
    for (change, action, admin, active) in [
        (
            AccountChange::Administrator(true),
            "administrator_granted",
            true,
            true,
        ),
        (
            AccountChange::Administrator(false),
            "administrator_revoked",
            false,
            true,
        ),
        (
            AccountChange::Membership(false),
            "membership_disabled",
            false,
            false,
        ),
        (
            AccountChange::Membership(true),
            "membership_enabled",
            false,
            true,
        ),
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
        let next = f
            .store
            .change_account(f.actor().await?, member.key(), change, deadline())
            .await?;
        assert_eq!(next.epoch(), expected.epoch() + 1);
        assert_eq!(
            next.membership_epoch(),
            expected.membership_epoch() + i64::from(expected.member_active() != active)
        );
        assert_eq!(next.administrator(), admin);
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
        let before = f.events().await?;
        if let Some(old) = old {
            assert_eq!(
                f.store
                    .change_account(
                        old,
                        member.key(),
                        AccountChange::Password(password()),
                        deadline()
                    )
                    .await
                    .unwrap_err(),
                AuthorityError::Rejected
            );
        }
        assert_eq!(f.events().await?, before);
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
    let disabled = f
        .store
        .change_account(
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
    let enabled = f
        .store
        .change_account(
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
