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
async fn prepare(p: &HttpOidc, bound: BoundProvider) -> Result<(), FederationError> {
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
    bound: BoundProvider,
    peer: &Peer,
    kid: &str,
    b: bool,
    change: Option<(&str, serde_json::Value)>,
) -> Result<UpstreamClaims, FederationError> {
    let material = ProtocolMaterial::new("state".into())?;
    *peer.token.lock().unwrap() = sign(&peer.issuer, &material.nonce, kid, b, change);
    p.exchange(
        bound.clone(),
        material,
        random_secret()?,
        upstream_deadline(),
    )
    .await
}

/// The same workload is run in release mode against the base revision during PR acceptance.
#[tokio::test]
async fn sequential_https_workload() -> anyhow::Result<()> {
    let peer = Peer::start().await?;
    let (oidc, settings, credentials) = setup(&peer, reuse_policy());
    let bound = fixture_provider(&oidc, tenant(), &settings, &credentials);
    let mut samples = Vec::new();
    for _ in 0..32 {
        let start = std::time::Instant::now();
        prepare(&oidc, bound.clone()).await?;
        exchange(&oidc, bound.clone(), &peer, "entra-a", false, None).await?;
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
        refresh_cooldown: Duration::from_secs(60),
        ..reuse_policy()
    };
    let (p, c, creds) = setup(&peer, policy);
    let bound = fixture_provider(&p, tenant(), &c, &creds);
    peer.keys_down.store(true, SeqCst);
    prepare(&p, bound.clone()).await?;
    prepare(&p, bound.clone()).await?;
    assert_eq!(peer.counts.snapshot(), [1, 1, 1, 0, 0]);
    assert!(
        exchange(&p, bound.clone(), &peer, "entra-a", false, None)
            .await
            .is_err()
    );
    peer.keys_down.store(false, SeqCst);
    exchange(&p, bound.clone(), &peer, "entra-a", false, None).await?;
    for (name, value) in [
        ("iss", json!("https://other")),
        ("aud", json!("other")),
        ("exp", json!(1)),
        ("nonce", json!("wrong")),
    ] {
        assert_eq!(
            exchange(
                &p,
                bound.clone(),
                &peer,
                "entra-a",
                false,
                Some((name, value))
            )
            .await
            .err(),
            Some(FederationError::Claims)
        );
    }
    assert!(
        exchange(&p, bound.clone(), &peer, "entra-a", true, None)
            .await
            .is_err()
    );
    assert_eq!(peer.counts.jwks.load(SeqCst), 2);
    peer.key_b.store(true, SeqCst);
    exchange(&p, bound.clone(), &peer, "entra-b", true, None).await?;
    for kid in ["missing-1", "missing-2"] {
        assert!(
            exchange(&p, bound.clone(), &peer, kid, true, None)
                .await
                .is_err()
        );
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
    p.exchange(
        bound.clone(),
        material,
        random_secret()?,
        upstream_deadline(),
    )
    .await?;
    assert_eq!(peer.counts.jwks.load(SeqCst), 3);
    p.test(bound.clone(), upstream_deadline()).await?;
    assert_eq!(peer.counts.snapshot(), [2, 2, 2, 4, 11]);
    Ok(())
}

#[tokio::test]
async fn expired_documents_coalesce_and_validators_follow_uri() -> anyhow::Result<()> {
    let peer = Peer::start().await?;
    let policy = ReusePolicy {
        discovery_ttl: Duration::from_secs(60),
        jwks_ttl: Duration::from_secs(60),
        ..reuse_policy()
    };
    let (p, c, creds) = setup(&peer, policy);
    let bound = fixture_provider(&p, tenant(), &c, &creds);
    exchange(&p, bound.clone(), &peer, "entra-a", false, None).await?;
    p.resources.advance(policy.discovery_ttl);
    peer.hold.store(true, SeqCst);
    let concurrent = futures_util::future::join_all((0..12).map(|_| async {
        let (_, doc, t) = p.discover(bound.clone(), upstream_deadline()).await?;
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
    p.resources.advance(policy.discovery_ttl);
    peer.keys_down.store(true, SeqCst);
    assert!(
        exchange(&p, bound.clone(), &peer, "entra-a", false, None)
            .await
            .is_err()
    );
    peer.keys_down.store(false, SeqCst);
    peer.alternate_uri.store(true, SeqCst);
    p.resources.advance(policy.discovery_ttl);
    exchange(&p, bound.clone(), &peer, "entra-a", false, None).await?;
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
    let bound = fixture_provider(&p, tenant(), &c, &creds);
    let other = crate::test_support::fixture_install(
        &p,
        ProviderRevision {
            provider: ProviderId::generate(),
            ..bound.revision()
        },
        &c,
        &creds,
    )?;
    peer.hold.store(true, SeqCst);
    let mut leader = Box::pin(p.discover(bound.clone(), upstream_deadline()));
    tokio::select! { _ = &mut leader => panic!("held response"), _ = peer.entered.notified() => () }
    assert!(
        p.discover(other.clone(), upstream_deadline())
            .await
            .is_err()
    );
    let short =
        rss_request_context::Deadline::at(std::time::Instant::now() + Duration::from_millis(10));
    assert!(matches!(
        p.discover(bound.clone(), short).await,
        Err(FederationError::Provider(ProviderFailure {
            reason: ProviderReason::Timeout,
            ..
        }))
    ));
    drop(leader);
    assert_eq!(p.resources.refreshes.available_permits(), 1);
    peer.hold.store(false, SeqCst);
    peer.release.add_permits(1);
    prepare(&p, other.clone()).await?;
    let (_, _, old) = p.discover(bound.clone(), upstream_deadline()).await?;
    let old_revision = bound.revision();
    let v2 = ProviderRevision {
        version: 2,
        ..old_revision
    };
    p.revisions().observe(v2);
    assert!(matches!(
        get(&old, &peer.issuer).await,
        Err(FederationError::StaleConfiguration)
    ));
    let next = crate::test_support::fixture_install(&p, v2, &c, &creds)?;
    assert!(matches!(
        prepare(&p, next.clone()).await,
        Err(FederationError::Provider(ProviderFailure {
            stage: ProviderStage::Binding,
            reason: ProviderReason::Unavailable
        }))
    ));
    drop(old);
    prepare(&p, next).await?;
    let v3 = ProviderRevision {
        version: 3,
        ..old_revision
    };
    prepare(
        &p,
        crate::test_support::fixture_install(&p, v3, &c, &creds)?,
    )
    .await?;
    assert!(matches!(
        p.discover(bound.clone(), upstream_deadline()).await,
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
        prepare(&tiny, fixture_provider(&tiny, tenant(), &c, &creds))
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
    let bound = fixture_provider(&p, tenant(), &c, &creds);
    let other = crate::test_support::fixture_install(
        &p,
        ProviderRevision {
            tenant: TenantId::parse("33333333-3333-4333-8333-333333333333")?,
            ..bound.revision()
        },
        &c,
        &creds,
    )?;
    peer.hold.store(true, SeqCst);
    let mut first = Box::pin(p.discover(bound.clone(), upstream_deadline()));
    tokio::select! { _ = &mut first => panic!("held GET"), _ = peer.entered.notified() => () }
    assert!(matches!(
        p.discover(other.clone(), upstream_deadline()).await,
        Err(FederationError::Provider(ProviderFailure {
            reason: ProviderReason::Unavailable,
            ..
        }))
    ));
    let mut joined = Box::pin(p.discover(bound.clone(), upstream_deadline()));
    assert!(futures_util::poll!(&mut joined).is_pending());
    drop(first);
    peer.hold.store(false, SeqCst);
    peer.release.add_permits(1);
    joined.await?;
    prepare(&p, other.clone()).await?;
    assert_eq!(peer.counts.snapshot(), [2, 2, 2, 0, 0]);
    let mut input = c.input();
    input.client_id = "other-client".into();
    let settings = ProviderSettings::try_from(input)?;
    let second = crate::test_support::fixture_install(
        &p,
        ProviderRevision {
            provider: ProviderId::generate(),
            ..bound.revision()
        },
        &settings,
        &creds,
    )?;
    prepare(&p, second).await?;
    assert_eq!(peer.counts.snapshot(), [3, 3, 3, 0, 0]);
    let no_ca = ProviderCredentials::new("fixture".into(), None)?;
    let rotated = crate::test_support::fixture_install(
        &p,
        ProviderRevision {
            version: 2,
            ..bound.revision()
        },
        &c,
        &no_ca,
    )?;
    assert!(matches!(
        p.discover(rotated, upstream_deadline()).await,
        Err(FederationError::Provider(ProviderFailure {
            reason: ProviderReason::TlsRejected,
            ..
        }))
    ));
    assert!(matches!(
        p.discover(bound.clone(), upstream_deadline()).await,
        Err(FederationError::StaleConfiguration)
    ));
    Ok(())
}

#[tokio::test]
async fn version_notification_survives_absent_and_evicted_pools() -> anyhow::Result<()> {
    let peer = Peer::start().await?;
    let (p, c, creds) = setup(
        &peer,
        ReusePolicy {
            max_providers: 1,
            ..reuse_policy()
        },
    );
    let delayed = fixture_provider(&p, tenant(), &c, &creds);
    let v2 = ProviderRevision {
        version: 2,
        ..delayed.revision()
    };
    p.revisions().observe(v2);
    assert!(matches!(
        prepare(&p, delayed).await,
        Err(FederationError::StaleConfiguration)
    ));
    let held = crate::test_support::fixture_install(&p, v2, &c, &creds)?;
    prepare(&p, held.clone()).await?;
    let other = crate::test_support::fixture_install(
        &p,
        ProviderRevision {
            provider: ProviderId::generate(),
            ..v2
        },
        &c,
        &creds,
    )?;
    p.test(other.clone(), upstream_deadline()).await?;
    prepare(&p, held.clone()).await?;
    assert_eq!(peer.counts.snapshot(), [2, 2, 2, 1, 0]);
    prepare(&p, other).await?;
    p.revisions().observe(ProviderRevision { version: 3, ..v2 });
    assert!(matches!(
        prepare(&p, held).await,
        Err(FederationError::StaleConfiguration)
    ));
    assert_eq!(peer.counts.snapshot(), [3, 3, 3, 1, 0]);
    Ok(())
}

#[tokio::test]
async fn cache_headers_control_conditional_and_unshared_reads() -> anyhow::Result<()> {
    use http::header;
    let peer = Peer::start().await?;
    peer.last_modified_only.store(true, SeqCst);
    peer.response_headers
        .lock()
        .unwrap()
        .insert(header::EXPIRES, "Fri, 01 Jan 2021 00:00:00 GMT".parse()?);
    let (p, c, creds) = setup(&peer, reuse_policy());
    let bound = fixture_provider(&p, tenant(), &c, &creds);
    prepare(&p, bound.clone()).await?;
    prepare(&p, bound.clone()).await?;
    assert_eq!(
        peer.headers.lock().unwrap()[1].1.as_deref(),
        Some("Fri, 01 Jan 2021 00:00:00 GMT")
    );
    peer.response_headers
        .lock()
        .unwrap()
        .insert(header::CACHE_CONTROL, "no-store".parse()?);
    peer.hold.store(true, SeqCst);
    let mut first = Box::pin(prepare(&p, bound.clone()));
    tokio::select! { _ = &mut first => panic!("held conditional GET"), _ = peer.entered.notified() => () }
    let mut waiter = Box::pin(prepare(&p, bound.clone()));
    assert!(futures_util::poll!(&mut waiter).is_pending());
    peer.hold.store(false, SeqCst);
    peer.release.add_permits(1);
    tokio::try_join!(first, waiter)?;
    prepare(&p, bound.clone()).await?;
    assert_eq!(peer.counts.discovery.load(SeqCst), 5);
    assert_eq!(peer.headers.lock().unwrap()[4].1, None);
    peer.response_headers.lock().unwrap().clear();
    peer.response_headers
        .lock()
        .unwrap()
        .insert(header::AGE, "600".parse()?);
    assert_eq!(
        exchange(&p, bound.clone(), &peer, "missing", true, None)
            .await
            .err(),
        Some(FederationError::Claims)
    );
    assert_eq!(peer.counts.jwks.load(SeqCst), 1);
    prepare(&p, bound).await?;
    assert_eq!(peer.counts.discovery.load(SeqCst), 7);
    Ok(())
}

#[tokio::test]
async fn rotation_shares_inflight_work_with_a_full_byte_budget() -> anyhow::Result<()> {
    let peer = Peer::start().await?;
    let (initial, c, creds) = setup(&peer, reuse_policy());
    exchange(
        &initial,
        fixture_provider(&initial, tenant(), &c, &creds),
        &peer,
        "entra-a",
        false,
        None,
    )
    .await?;
    let budget = initial.resources.resident_bytes();
    let (p, c, creds) = setup(
        &peer,
        ReusePolicy {
            max_resident_bytes: budget,
            ..reuse_policy()
        },
    );
    let bound = fixture_provider(&p, tenant(), &c, &creds);
    exchange(&p, bound.clone(), &peer, "entra-a", false, None).await?;
    let (_, doc, t) = p.discover(bound.clone(), upstream_deadline()).await?;
    p.resources.advance(p.resources.policy.refresh_cooldown);
    peer.key_b.store(true, SeqCst);
    peer.hold.store(true, SeqCst);
    let mut first = Box::pin(p.signing_keys(&doc, &t, Some("entra-b")));
    tokio::select! { _ = &mut first => panic!("held rotated keys"), _ = peer.entered.notified() => () }
    let (_, doc2, t2) = p.discover(bound.clone(), upstream_deadline()).await?;
    let mut second = Box::pin(p.signing_keys(&doc2, &t2, Some("entra-b")));
    assert!(futures_util::poll!(&mut second).is_pending());
    peer.hold.store(false, SeqCst);
    peer.release.add_permits(1);
    let (first, second) = tokio::try_join!(first, second)?;
    assert_eq!(first.keys[0]["kid"], "entra-b");
    assert_eq!(second.keys[0]["kid"], "entra-b");
    assert_eq!(peer.counts.jwks.load(SeqCst), 3);
    assert!(p.resources.resident_bytes() <= budget);
    let (short, c, creds) = setup(
        &peer,
        ReusePolicy {
            max_resident_bytes: budget - 1,
            ..reuse_policy()
        },
    );
    let bound = fixture_provider(&short, tenant(), &c, &creds);
    prepare(&short, bound.clone()).await?;
    assert!(
        exchange(&short, bound, &peer, "entra-b", true, None)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn unmatched_304_recovers_and_no_store_retry_charges_the_waiter() -> anyhow::Result<()> {
    use http::header;
    let peer = Peer::start().await?;
    peer.response_headers
        .lock()
        .unwrap()
        .insert(header::CACHE_CONTROL, "no-cache".parse()?);
    let (p, c, creds) = setup(&peer, reuse_policy());
    let bound = fixture_provider(&p, tenant(), &c, &creds);
    prepare(&p, bound.clone()).await?;
    peer.response_headers
        .lock()
        .unwrap()
        .insert(header::ETAG, "\"different\"".parse()?);
    prepare(&p, bound.clone()).await?;
    assert_eq!(
        peer.headers
            .lock()
            .unwrap()
            .iter()
            .map(|(_, v)| v.clone())
            .collect::<Vec<_>>(),
        vec![None, Some("\"d1\"".into()), None]
    );

    peer.response_headers
        .lock()
        .unwrap()
        .insert(header::CACHE_CONTROL, "no-store".parse()?);
    peer.hold.store(true, SeqCst);
    let mut first = Box::pin(prepare(&p, bound.clone()));
    tokio::select! { _ = &mut first => panic!("held GET"), _ = peer.entered.notified() => () }
    let t = p.transport(bound, upstream_deadline(), false)?;
    for _ in 0..3 {
        t.charge(ProviderStage::Discovery)?;
    }
    let mut last = Box::pin(t.slot.as_ref().unwrap().discovery.read(
        &p.resources,
        &t,
        discovery::Kind::Discovery {
            issuer: peer.issuer.clone(),
        },
        None,
    ));
    assert!(futures_util::poll!(&mut last).is_pending());
    peer.hold.store(false, SeqCst);
    peer.release.add_permits(1);
    first.await?;
    assert!(last.await.is_err());
    assert_eq!(peer.counts.discovery.load(SeqCst), 4);
    Ok(())
}

#[tokio::test]
async fn changing_keys_uri_releases_old_key_document_before_replacing_discovery()
-> anyhow::Result<()> {
    let peer = Peer::start().await?;
    peer.keys_padding.store(1024, SeqCst);
    let (measure, c, creds) = setup(&peer, reuse_policy());
    exchange(
        &measure,
        fixture_provider(&measure, tenant(), &c, &creds),
        &peer,
        "entra-a",
        false,
        None,
    )
    .await?;
    let policy = ReusePolicy {
        max_resident_bytes: measure.resources.resident_bytes(),
        ..reuse_policy()
    };
    let (p, c, creds) = setup(&peer, policy);
    let bound = fixture_provider(&p, tenant(), &c, &creds);
    exchange(&p, bound.clone(), &peer, "entra-a", false, None).await?;
    p.resources.advance(policy.discovery_ttl);
    peer.alternate_uri.store(true, SeqCst);
    peer.keys_padding.store(0, SeqCst);
    exchange(&p, bound, &peer, "entra-a", false, None).await?;
    assert!(p.resources.resident_bytes() < policy.max_resident_bytes);
    Ok(())
}

#[tokio::test]
async fn retirement_interrupts_pending_connection_before_post() -> anyhow::Result<()> {
    use reqwest::dns::{Addrs, Name, Resolve, Resolving};
    struct HeldDns {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }
    impl Resolve for HeldDns {
        fn resolve(&self, _: Name) -> Resolving {
            let entered = self.entered.clone();
            let release = self.release.clone();
            Box::pin(async move {
                entered.notify_one();
                release.notified().await;
                Ok(Box::new(std::iter::once("127.0.0.1:0".parse().unwrap())) as Addrs)
            })
        }
    }
    let peer = Peer::start().await?;
    let (mut p, _, creds) = setup(&peer, reuse_policy());
    let issuer = peer.issuer.replace("127.0.0.1", "localhost");
    let c = config(&issuer);
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    p.lookup = Some(Arc::new(HeldDns {
        entered: entered.clone(),
        release: release.clone(),
    }));
    let bound = fixture_provider(&p, tenant(), &c, &creds);
    let t = p.transport(bound.clone(), upstream_deadline(), false)?;
    let req = http::Request::post(format!("{issuer}/token")).body(Vec::new())?;
    let mut dispatch = Box::pin(t.call(ProviderStage::Exchange, req));
    tokio::select! { _=&mut dispatch=>panic!("DNS was held"), _=entered.notified()=>() }
    p.revisions().retire(bound.revision());
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), dispatch).await?,
        Err(FederationError::StaleConfiguration)
    ));
    release.notify_one();
    assert_eq!(peer.counts.post.load(SeqCst), 0);
    Ok(())
}
