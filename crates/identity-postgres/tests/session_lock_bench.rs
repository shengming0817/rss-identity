//! Manual release-mode measurement against the same pinned fixture on both revisions.
mod support;
use futures::{StreamExt, TryStreamExt, stream};
use rss_identity_core::{PrincipalId, account::AccountKey, session::SessionSecret};
use rss_identity_postgres::{
    AttemptWindow, AuthenticatedSession, AuthenticationPolicy, Authority,
    recheck_authenticated_session_on,
};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use sqlx::{
    Connection, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use support::{Fixture, binding, deadline, login, password, source};

struct Subject {
    tenant: TenantId,
    name: String,
    secret: String,
    proof: AuthenticatedSession,
}
#[derive(Clone, Copy)]
enum Work {
    Host,
    Touch,
    Issue,
}
impl Work {
    fn name(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Touch => "touch",
            Self::Issue => "issue",
        }
    }
}
#[derive(Default)]
struct Sample {
    total: u64,
    pool: Option<u64>,
    retained: Option<u64>,
    failed: bool,
}
fn micros(start: Instant) -> u64 {
    start.elapsed().as_micros() as u64
}
fn percentile(mut values: Vec<u64>, p: usize) -> Option<u64> {
    values.sort_unstable();
    if values.is_empty() {
        None
    } else {
        Some(values[(p * values.len()).div_ceil(100) - 1])
    }
}
async fn measure(
    work: Work,
    store: &Authority,
    pool: &PgPool,
    s: &Subject,
) -> anyhow::Result<Sample> {
    let start = Instant::now();
    let mut sample = Sample::default();
    match work {
        Work::Host => {
            let mut c = pool.acquire().await?;
            sample.pool = Some(micros(start));
            let mut tx = c.begin().await?;
            support::fence(&mut tx, binding(s.tenant)).await?;
            recheck_authenticated_session_on(&mut tx, &s.proof).await?;
            let held = Instant::now();
            sqlx::query("INSERT INTO public.host_effects(subject) VALUES($1)")
                .bind(s.proof.account().principal.as_uuid())
                .execute(&mut *tx)
                .await?;
            tokio::time::sleep(Duration::from_millis(2)).await;
            tx.commit().await?;
            sample.retained = Some(micros(held));
        }
        Work::Touch => {
            store
                .authenticate_session(
                    binding(s.tenant),
                    SessionSecret::parse(s.secret.clone())?,
                    deadline(),
                )
                .await?;
        }
        Work::Issue => {
            match store
                .login_local(
                    binding(s.tenant),
                    login(&s.name),
                    password(),
                    source(),
                    None,
                    deadline(),
                )
                .await
            {
                Ok(_) => {}
                Err(rss_identity_postgres::AuthorityError::Busy) => sample.failed = true,
                Err(e) => return Err(e.into()),
            }
        }
    }
    sample.total = micros(start);
    Ok(sample)
}
async fn server_time(pool: &PgPool) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(pool)
            .await?,
    )
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual release benchmark, run with hack/session_lock_bench.py"]
async fn session_lock_measurements() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let window = AttemptWindow::new(1_000_000, 3600)?;
    let policy =
        AuthenticationPolicy::new(window, window, window, 10_000, 128, Duration::from_secs(30))?;
    let runtime = rss_transactional_messaging_postgres::PgRuntime::connect_producer(
        rss_transactional_messaging_postgres::PgConfig::new_for_test_plaintext(
            "127.0.0.1",
            f.port,
            &f.database,
            "identity_runtime",
            rss_transactional_messaging_postgres::PgPassword::new("fixture-only"),
        )
        .with_pool_limits(16, 16),
        support::Timer,
        rss_transactional_messaging::fence::StorageIdentity::new([1; 16], [2; 16])?,
    )
    .await?;
    let store = Authority::connect_runtime(
        Arc::new(runtime),
        Arc::new(rss_identity_core::account::PasswordKdf::new(
            16usize.try_into()?,
            (1024u64 * 1024 * 1024).try_into()?,
        )?),
        f.config().with_authentication_policy(policy),
        binding(f.key.tenant),
        f.policy.clone(),
        deadline(),
    )
    .await?;
    sqlx::raw_sql("CREATE TABLE public.host_effects(subject uuid NOT NULL); GRANT INSERT ON public.host_effects TO identity_runtime").execute(&f.owner).await?;
    let host = PgPoolOptions::new()
        .min_connections(16)
        .max_connections(16)
        .connect_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(f.port)
                .username("identity_runtime")
                .password("fixture-only")
                .database(&f.database),
        )
        .await?;
    let mut single = Vec::new();
    let mut multiple = Vec::new();
    for i in 0..16 {
        let name = format!("bench{i}");
        store
            .create_local_account(f.actor().await?, login(&name), password(), deadline())
            .await?;
        let other = TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
            .bind(other.to_string())
            .execute(&f.owner)
            .await?;
        f.maintenance
            .initialize(
                binding(other),
                AccountKey {
                    tenant: other,
                    principal: PrincipalId::generate(),
                },
                login(&name),
                password(),
                deadline(),
            )
            .await?;
        for (tenant, set) in [(f.key.tenant, &mut single), (other, &mut multiple)] {
            let session = store
                .login_local(
                    binding(tenant),
                    login(&name),
                    password(),
                    source(),
                    None,
                    deadline(),
                )
                .await?;
            let secret = session.secret().expose().to_owned();
            let proof = store
                .inspect_session(
                    binding(tenant),
                    SessionSecret::parse(secret.clone())?,
                    OperationDeadline::from_remaining(Duration::from_secs(3600)),
                )
                .await?;
            set.push(Subject {
                tenant,
                name: name.clone(),
                secret,
                proof,
            });
        }
    }
    let trace = std::env::var_os("IDENTITY_BENCH_TRACE").is_some();
    for round in 1..=if trace { 1 } else { 3 } {
        for work in [Work::Host, Work::Touch, Work::Issue] {
            for shape in ["one_account", "one_tenant", "many_tenants"] {
                let subjects = match shape {
                    "one_account" => &single[..1],
                    "one_tenant" => &single[..],
                    _ => &multiple[..],
                };
                for concurrency in [1, 8, 16] {
                    let requests = if trace { 32 } else { 160 };
                    let run = |count: usize| {
                        stream::iter(0..count)
                            .map(|i| measure(work, &store, &host, &subjects[i % subjects.len()]))
                            .buffer_unordered(concurrency)
                            .try_collect::<Vec<_>>()
                    };
                    run(concurrency).await?;
                    let begin = server_time(&f.owner).await?;
                    let start = Instant::now();
                    let samples = run(requests).await?;
                    let duration = start.elapsed();
                    let end = server_time(&f.owner).await?;
                    let accepted: Vec<_> = samples.iter().filter(|s| !s.failed).collect();
                    let latencies: Vec<_> = accepted.iter().map(|s| s.total).collect();
                    let row = serde_json::json!({"db":f.database,"begin_us":begin,"end_us":end,"work":work.name(),"shape":shape,"concurrency":concurrency,"round":round,"pool_max":16,"trace":trace,
                        "ok":accepted.len(),"busy":requests-accepted.len(),"ops_s":accepted.len() as f64/duration.as_secs_f64(),
                        "p95_us":percentile(latencies.clone(),95),"p99_us":percentile(latencies,99),
                        "pool_p95_us":percentile(accepted.iter().filter_map(|s|s.pool).collect(),95),
                        "admitted_to_commit_p95_us":percentile(accepted.iter().filter_map(|s|s.retained).collect(),95)});
                    println!("LOCK_BENCH {row}");
                }
            }
        }
    }
    host.close().await;
    drop(store);
    f.close().await;
    Ok(())
}
