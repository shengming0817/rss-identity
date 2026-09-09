//! Opt-in finite component measurements, not a production SLO or CI performance gate.
mod downstream_support;
#[allow(dead_code)]
#[path = "../../identity-postgres/tests/support/mod.rs"]
mod support;
use downstream_support::*;
use futures::{StreamExt, stream};
use rss_identity_client::{ClientConfig, IdentityClient};
use rss_identity_core::{downstream::Secret, session::SessionSecret};
use rss_identity_postgres::LocalAccountRole;
use serde_json::json;
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};
use support::*;
use zeroize::Zeroizing;

async fn measure<F, Fut>(operation: &str, concurrency: usize, requests: usize, f: F)
where
    F: Fn(usize) -> Fut,
    Fut: Future<Output = bool>,
{
    let started = Instant::now();
    let samples: Vec<_> = stream::iter(0..requests)
        .map(|i| {
            let future = f(i);
            async move {
                let start = Instant::now();
                let ok = future.await;
                (start.elapsed().as_secs_f64() * 1000.0, ok)
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;
    let seconds = started.elapsed().as_secs_f64();
    let succeeded = samples.iter().filter(|(_, ok)| *ok).count();
    let mut times: Vec<_> = samples.into_iter().map(|(ms, _)| ms).collect();
    times.sort_by(f64::total_cmp);
    let percentile = |p: usize| {
        times[(times.len() * p)
            .div_ceil(100)
            .saturating_sub(1)
            .min(times.len() - 1)]
    };
    eprintln!(
        "CAPACITY {}",
        json!({"operation":operation,"concurrency":concurrency,"requests":requests,"succeeded":succeeded,"failed":requests-succeeded,"seconds":seconds,"successful_rps":succeeded as f64/seconds,"p50_ms":percentile(50),"p95_ms":percentile(95),"p99_ms":percentile(99)})
    );
}

#[tokio::test]
#[ignore = "make measure-capacity: finite diagnostic run, no acceptance threshold"]
async fn measure_single_consumer_identity_paths() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let mut cookies = Vec::new();
    for i in 0..16 {
        let name = format!("measure-{i}");
        f.store
            .create_local_account(
                f.actor().await?,
                login(&name),
                password(),
                LocalAccountRole::Member,
                deadline(),
            )
            .await?;
        let candidate = f
            .store
            .verify_password(f.key.tenant, login(&name), password(), source(), deadline())
            .await?;
        cookies.push(
            f.store
                .create_session(candidate, None, deadline())
                .await?
                .secret()
                .expose()
                .to_owned(),
        );
    }
    let issuer = std::env::var("IDENTITY_TEST_DOWNSTREAM_ISSUER")?;
    let origin = issuer.trim_end_matches('/');
    let ca = std::fs::read(std::env::var("IDENTITY_TEST_DOWNSTREAM_CA")?)?;
    let hydra = Arc::new(rss_identity_hydra::Hydra::new(
        &issuer,
        &issuer,
        vec!["127.0.0.1/32".parse()?, "::1/128".parse()?],
        Secret::new(SERVICE.into())?,
        Some(&ca),
    )?);
    let d = downstream(f.store.clone(), hydra, &issuer)?;
    let server = serve(f.store.clone(), d.clone(), origin).await?;
    let c = reqwest::Client::builder()
        .no_proxy()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
        .timeout(Duration::from_secs(10))
        .build()?;
    let session = post(
        &c,
        origin,
        &format!("/api/v1/tenants/{A}/login"),
        json!({"login":"admin","password":PASSWORD}),
        None,
    )
    .await?;
    let csrf = session["csrf_token"].as_str().unwrap();
    let mut tokens = Vec::new();
    for _ in 0..8 {
        tokens.push(
            flow(
                &c,
                origin,
                &issuer,
                csrf,
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                false,
            )
            .await?
            .0,
        );
    }
    let sdk = IdentityClient::new(
        ClientConfig {
            identity_origin: origin.into(),
            issuer: issuer.clone(),
            client_id: "mdm".into(),
            validation_secret: Zeroizing::new(VALIDATION.into()),
            tenant_id: A.into(),
            audience: "mdm-api".into(),
            timeout: Duration::from_secs(10),
            ca_pem: Some(ca),
        },
        Arc::new(rss_identity_client::SystemClock),
    )?;
    sdk.validate(&tokens[0]).await?;
    for concurrency in [1, 4, 16] {
        let f = &f;
        let cookies = &cookies;
        let sdk = &sdk;
        let tokens = &tokens;
        // Each independent run starts with fresh attempt budgets; never reset within a measurement.
        f.reset_attempts().await?;
        measure("local_login", concurrency, 64, |i| async move {
            let result = f
                .store
                .verify_password(
                    f.key.tenant,
                    login(&format!("measure-{}", i % 16)),
                    password(),
                    source(),
                    deadline(),
                )
                .await;
            match result {
                Ok(candidate) => f
                    .store
                    .create_session(candidate, None, deadline())
                    .await
                    .is_ok(),
                Err(_) => false,
            }
        })
        .await;
        measure("session_inspect", concurrency, 64, |i| async move {
            f.store
                .inspect_session(
                    f.key.tenant,
                    SessionSecret::parse(cookies[i % 16].clone()).unwrap(),
                    deadline(),
                )
                .await
                .is_ok()
        })
        .await;
        measure("online_validation", concurrency, 64, |i| async move {
            sdk.validate(&tokens[i % 8]).await.is_ok()
        })
        .await;
    }
    f.store
        .revoke_all_sessions(f.actor().await?, deadline())
        .await?;
    sqlx::query("UPDATE identity_authority.downstream_grants SET next_attempt=created_at")
        .execute(&f.owner)
        .await?;
    let start = Instant::now();
    d.cleanup_once(f.key.tenant, 128, deadline()).await?;
    let seconds = start.elapsed().as_secs_f64();
    let revoking: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.downstream_grants WHERE state=5",
    )
    .fetch_one(&f.owner)
    .await?;
    anyhow::ensure!(revoking == 8, "cleanup did not process the seeded backlog");
    eprintln!(
        "CAPACITY {}",
        json!({"operation":"cleanup_8_grants","concurrency":1,"requests":8,"succeeded":8,"failed":0,"seconds":seconds,"successful_rps":8.0/seconds})
    );
    server.abort();
    let _ = server.await;
    f.close().await;
    Ok(())
}
