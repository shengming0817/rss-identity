use super::{upstream::Peer, *};
use crate::test_support::reuse_policy;
use std::sync::atomic::Ordering::SeqCst;

fn sign(
    issuer: &str,
    nonce: &str,
    kid: &str,
    use_b: bool,
    change: Option<(&str, serde_json::Value)>,
) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut claims =
        json!({"iss":issuer,"sub":"subject","aud":"client","iat":now,"exp":now+120,"nonce":nonce});
    if let Some((name, value)) = change {
        claims[name] = value;
    }
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.into());
    let key = if use_b {
        include_bytes!("../../tests/fixtures/entra-b.der").as_slice()
    } else {
        include_bytes!("../../tests/fixtures/entra-a.der").as_slice()
    };
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_der(key),
    )
    .unwrap()
}
fn setup(peer: &Peer, policy: ReusePolicy) -> (HttpOidc, ProviderSettings, ProviderCredentials) {
    (
        HttpOidc::for_loopback_test(vec![], transport_policy(), policy).unwrap(),
        config(&peer.issuer),
        ProviderCredentials::new("fixture-secret".into(), Some(peer.ca.clone())).unwrap(),
    )
}
async fn prepare(p: &HttpOidc, bound: BoundProvider<'_>) -> Result<(), FederationError> {
    let material = ProtocolMaterial::new("state".into())?;
    p.prepare(
        bound,
        &material,
        AuthenticationMode::Login,
        upstream_deadline(),
    )
    .await
    .map(drop)
}
async fn exchange(
    p: &HttpOidc,
    bound: BoundProvider<'_>,
    peer: &Peer,
    kid: &str,
    b: bool,
    change: Option<(&str, serde_json::Value)>,
) -> Result<UpstreamClaims, FederationError> {
    let material = ProtocolMaterial::new("state".into())?;
    *peer.token.lock().unwrap() = sign(&peer.issuer, &material.nonce, kid, b, change);
    p.exchange(bound, material, random_secret()?, upstream_deadline())
        .await
}

/// The same workload is run in release mode against the base revision during PR acceptance.
#[tokio::test]
async fn sequential_https_workload() -> anyhow::Result<()> {
    let peer = Peer::start().await?;
    let (oidc, settings, credentials) = setup(&peer, reuse_policy());
    let bound = fixture_provider(tenant(), &settings, &credentials);
    let mut samples = Vec::new();
    for _ in 0..32 {
        let start = std::time::Instant::now();
        prepare(&oidc, bound).await?;
        exchange(&oidc, bound, &peer, "entra-a", false, None).await?;
        samples.push(start.elapsed().as_micros());
    }
    samples.sort_unstable();
    let counts = peer.counts.snapshot();
    println!(
        "32 sequential logins: TCP/TLS/Discovery/JWKS/POST={counts:?}, p95={}us p99={}us",
        samples[30], samples[31]
    );
    assert_eq!(counts, [1, 1, 1, 1, 32]);
    Ok(())
}

#[tokio::test]
async fn lazy_keys_rotation_and_per_token_verification() -> anyhow::Result<()> {
    let peer = Peer::start().await?;
    let policy = ReusePolicy {
        refresh_cooldown: Duration::from_millis(60),
        ..reuse_policy()
    };
    let (p, c, creds) = setup(&peer, policy);
    let bound = fixture_provider(tenant(), &c, &creds);
    peer.keys_down.store(true, SeqCst);
    prepare(&p, bound).await?;
    prepare(&p, bound).await?;
    assert_eq!(peer.counts.snapshot(), [1, 1, 1, 0, 0]);
    assert!(
        exchange(&p, bound, &peer, "entra-a", false, None)
            .await
            .is_err()
    );
    peer.keys_down.store(false, SeqCst);
    exchange(&p, bound, &peer, "entra-a", false, None).await?;
    for (name, value) in [
        ("iss", json!("https://other")),
        ("aud", json!("other")),
        ("exp", json!(1)),
        ("nonce", json!("wrong")),
    ] {
        assert_eq!(
            exchange(&p, bound, &peer, "entra-a", false, Some((name, value)))
                .await
                .err(),
            Some(FederationError::Claims)
        );
    }
    assert!(
        exchange(&p, bound, &peer, "entra-a", true, None)
            .await
            .is_err()
    );
    assert_eq!(peer.counts.jwks.load(SeqCst), 2);
    tokio::time::sleep(policy.refresh_cooldown).await;
    peer.key_b.store(true, SeqCst);
    exchange(&p, bound, &peer, "entra-b", true, None).await?;
    for kid in ["missing-1", "missing-2"] {
        assert!(exchange(&p, bound, &peer, kid, true, None).await.is_err());
    }
    assert_eq!(peer.counts.jwks.load(SeqCst), 3);
    assert_eq!(peer.counts.post.load(SeqCst), 10);
    let material = ProtocolMaterial::new("state".into())?;
    let claims = json!({"iss":peer.issuer,"sub":"subject","aud":"client","iat":1,"exp":4102444800_i64,"nonce":material.nonce.as_str()});
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(creds.client_secret().as_bytes()),
    )?;
    *peer.token.lock().unwrap() = token;
    p.exchange(bound, material, random_secret()?, upstream_deadline())
        .await?;
    assert_eq!(peer.counts.jwks.load(SeqCst), 3);
    p.test(bound, upstream_deadline()).await?;
    assert_eq!(peer.counts.snapshot(), [2, 2, 2, 4, 11]);
    Ok(())
}

#[tokio::test]
async fn expired_documents_coalesce_and_validators_follow_uri() -> anyhow::Result<()> {
    let peer = Peer::start().await?;
    let policy = ReusePolicy {
        discovery_ttl: Duration::from_millis(100),
        jwks_ttl: Duration::from_millis(100),
        ..reuse_policy()
    };
    let (p, c, creds) = setup(&peer, policy);
    let bound = fixture_provider(tenant(), &c, &creds);
    exchange(&p, bound, &peer, "entra-a", false, None).await?;
    tokio::time::sleep(policy.discovery_ttl).await;
    peer.hold.store(true, SeqCst);
    let concurrent = futures_util::future::join_all((0..12).map(|_| async {
        let (_, doc, t) = p.discover(bound, upstream_deadline()).await?;
        p.signing_keys(&doc, &t, Some("entra-a")).await
    }));
    let release = async {
        for _ in 0..2 {
            peer.entered.notified().await;
            peer.release.add_permits(1);
        }
    };
    let (results, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(concurrent, release)
    })
    .await?;
    for result in results {
        result?;
    }
    assert_eq!(peer.counts.snapshot(), [1, 1, 2, 2, 1]);
    assert_eq!(
        peer.headers.lock().unwrap()[2..],
        [
            ("discovery".into(), Some("\"d1\"".into())),
            ("/realm/keys".into(), Some("\"a\"".into()))
        ]
    );
    peer.hold.store(false, SeqCst);
    tokio::time::sleep(policy.discovery_ttl).await;
    peer.keys_down.store(true, SeqCst);
    assert!(
        exchange(&p, bound, &peer, "entra-a", false, None)
            .await
            .is_err()
    );
    peer.keys_down.store(false, SeqCst);
    peer.alternate_uri.store(true, SeqCst);
    tokio::time::sleep(policy.discovery_ttl).await;
    exchange(&p, bound, &peer, "entra-a", false, None).await?;
    assert_eq!(
        peer.headers.lock().unwrap().last(),
        Some(&("/realm/next".into(), None))
    );
    Ok(())
}

#[tokio::test]
async fn bounded_waiters_eviction_and_generation_fences() -> anyhow::Result<()> {
    let peer = Peer::start().await?;
    let policy = ReusePolicy {
        max_refreshes: 1,
        max_providers: 1,
        ..reuse_policy()
    };
    let (p, c, creds) = setup(&peer, policy);
    let mut bound = fixture_provider(tenant(), &c, &creds);
    let mut other = bound;
    other.revision.provider = ProviderId::generate();
    peer.hold.store(true, SeqCst);
    let mut leader = Box::pin(p.discover(bound, upstream_deadline()));
    tokio::select! { _ = &mut leader => panic!("held response"), _ = peer.entered.notified() => () }
    assert!(p.discover(other, upstream_deadline()).await.is_err());
    let short =
        rss_request_context::Deadline::at(std::time::Instant::now() + Duration::from_millis(10));
    assert!(matches!(
        p.discover(bound, short).await,
        Err(FederationError::Provider(ProviderFailure {
            reason: ProviderReason::Timeout,
            ..
        }))
    ));
    drop(leader);
    assert_eq!(p.resources.refreshes.available_permits(), 1);
    peer.hold.store(false, SeqCst);
    peer.release.add_permits(1);
    prepare(&p, other).await?;
    let (_, _, old) = p.discover(bound, upstream_deadline()).await?;
    for version in [2, 3] {
        bound.revision.version = version;
        p.observe_revision(bound.revision);
        assert!(matches!(
            get(&old, &peer.issuer).await,
            Err(FederationError::StaleConfiguration)
        ));
        prepare(&p, bound).await?;
    }
    bound.revision.version = 1;
    assert!(matches!(
        p.discover(bound, upstream_deadline()).await,
        Err(FederationError::StaleConfiguration)
    ));
    let (tiny, c, creds) = setup(
        &peer,
        ReusePolicy {
            max_resident_bytes: 32,
            ..policy
        },
    );
    assert!(
        prepare(&tiny, fixture_provider(tenant(), &c, &creds))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn bindings_and_independent_refresh_waiters() -> anyhow::Result<()> {
    let peer = Peer::start().await?;
    let (p, c, creds) = setup(
        &peer,
        ReusePolicy {
            max_refreshes: 1,
            ..reuse_policy()
        },
    );
    let bound = fixture_provider(tenant(), &c, &creds);
    let mut other = bound;
    other.revision.tenant = TenantId::parse("33333333-3333-4333-8333-333333333333")?;
    peer.hold.store(true, SeqCst);
    let mut first = Box::pin(p.discover(bound, upstream_deadline()));
    tokio::select! { _ = &mut first => panic!("held GET"), _ = peer.entered.notified() => () }
    assert!(matches!(
        p.discover(other, upstream_deadline()).await,
        Err(FederationError::Provider(ProviderFailure {
            reason: ProviderReason::Unavailable,
            ..
        }))
    ));
    let mut joined = Box::pin(p.discover(bound, upstream_deadline()));
    assert!(futures_util::poll!(&mut joined).is_pending());
    drop(first);
    peer.hold.store(false, SeqCst);
    peer.release.add_permits(1);
    joined.await?;
    prepare(&p, other).await?;
    assert_eq!(peer.counts.snapshot(), [2, 2, 2, 0, 0]);
    let mut input = c.input();
    input.client_id = "other-client".into();
    let settings = ProviderSettings::try_from(input)?;
    let mut second = BoundProvider {
        settings: &settings,
        ..bound
    };
    second.revision.provider = ProviderId::generate();
    prepare(&p, second).await?;
    assert_eq!(peer.counts.snapshot(), [3, 3, 3, 0, 0]);
    let no_ca = ProviderCredentials::new("fixture".into(), None)?;
    let mut rotated = BoundProvider {
        credentials: &no_ca,
        ..bound
    };
    rotated.revision.version += 1;
    assert!(matches!(
        p.discover(rotated, upstream_deadline()).await,
        Err(FederationError::Provider(ProviderFailure {
            reason: ProviderReason::TlsRejected,
            ..
        }))
    ));
    assert!(matches!(
        p.discover(bound, upstream_deadline()).await,
        Err(FederationError::StaleConfiguration)
    ));
    Ok(())
}
