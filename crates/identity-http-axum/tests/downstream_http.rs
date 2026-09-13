//! Real Hydra code flow through the production bridge and TLS gateway.
#![allow(dead_code)]
mod keycloak_support;
#[path = "../../identity-postgres/tests/support/mod.rs"]
mod support;
use reqwest::{Client, Url};
use rss_identity_client::{ClientConfig, IdentityClient};
use rss_identity_core::downstream::*;
use rss_identity_http_axum::*;
use rss_identity_postgres::*;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use support::*;
use zeroize::Zeroizing;
struct FaultHydra {
    inner: Arc<rss_identity_hydra::Hydra>,
    lose_consent: std::sync::atomic::AtomicBool,
    withheld: std::sync::Mutex<Option<String>>,
}
impl DownstreamProtocol for FaultHydra {
    fn issuer(&self) -> &str {
        self.inner.issuer()
    }
    fn login<'a>(&'a self, c: &'a Secret) -> ProtocolFuture<'a, Challenge> {
        self.inner.login(c)
    }
    fn consent<'a>(&'a self, c: &'a Secret) -> ProtocolFuture<'a, Challenge> {
        self.inner.consent(c)
    }
    fn accept_login<'a>(&'a self, c: &'a Secret, d: LoginDecision) -> ProtocolFuture<'a, Secret> {
        self.inner.accept_login(c, d)
    }
    fn accept_consent<'a>(
        &'a self,
        c: &'a Secret,
        d: ConsentDecision,
    ) -> ProtocolFuture<'a, Secret> {
        Box::pin(async move {
            let result = self.inner.accept_consent(c, d).await?;
            if self.lose_consent.load(std::sync::atomic::Ordering::SeqCst) {
                *self.withheld.lock().unwrap() = Some(result.expose().into());
                return Err(DownstreamError::Unavailable);
            }
            Ok(result)
        })
    }
    fn introspect<'a>(&'a self, c: &'a Secret) -> ProtocolFuture<'a, TokenObservation> {
        self.inner.introspect(c)
    }
    fn revoke<'a>(&'a self, c: Option<&'a str>, s: &'a str) -> ProtocolFuture<'a, ()> {
        self.inner.revoke(c, s)
    }
}
mod downstream_support;
use downstream_support::*;
#[tokio::test]
#[ignore = "make test-downstream"]
async fn real_totp_assurance_reaches_hydra_and_validation_client() -> anyhow::Result<()> {
    use rss_identity_core::federation::*;
    use rss_identity_oidc::{HttpOidc, TrustedAssuranceProfile};
    let issuer = std::env::var("IDENTITY_TEST_DOWNSTREAM_ISSUER")?;
    let origin = issuer.trim_end_matches('/');
    let f = Fixture::with_identity(rss_identity_postgres::DeploymentIdentity::new(
        "fixture".into(),
        1,
        origin.into(),
        "https://product.example.test".into(),
    )?)
    .await?;
    f.bootstrap().await?;
    let ca = std::fs::read(std::env::var("IDENTITY_TEST_DOWNSTREAM_CA")?)?;
    let upstream_issuer = std::env::var("IDENTITY_TEST_FEDERATED_ISSUER")?;
    let callback = format!("{origin}/api/v1/oidc/callback");
    let oidc = HttpOidc::new(vec![TrustedAssuranceProfile {
        tenant: f.key.tenant,
        issuer: upstream_issuer.clone(),
        client_id: "identity-test".into(),
        keycloak_totp: true,
    }])?;
    let federation = Federation::new(
        f.store.clone(),
        Arc::new(oidc),
        StateSigner::new([7; 32], origin)?,
        BTreeMap::from([(("identity".into(), "home".into()), format!("{origin}/done"))]),
    )?;
    let p = federation
        .create_provider(
            session_actor(&f.store, f.candidate().await?).await?,
            ProviderSettingsInput {
                issuer: upstream_issuer,
                client_id: "identity-test".into(),

                redirect_uri: callback,
                scopes: vec!["openid".into()],
                claims: ClaimMapping {
                    email: None,
                    groups: None,
                },
                jit: true,
            }
            .try_into()?,
            rss_identity_core::federation::ProviderCredentials::new(
                "fixture-secret".into(),
                Some(std::fs::read_to_string(std::env::var(
                    "IDENTITY_TEST_FEDERATED_CA",
                )?)?),
            )?,
            deadline(),
        )
        .await?;
    let p = federation
        .enable_provider(
            session_actor(&f.store, f.candidate().await?).await?,
            p.id,
            p.version,
            true,
            deadline(),
        )
        .await?;
    let hydra = Arc::new(rss_identity_hydra::Hydra::new(
        &issuer,
        &issuer,
        vec!["127.0.0.1/32".parse()?, "::1/128".parse()?],
        Secret::new(SERVICE.into())?,
        Some(&ca),
    )?);
    let d = Downstream::new(
        f.store.clone(),
        hydra.clone(),
        vec![Registration::new(RegistrationInput {
            tenant: f.key.tenant,
            client: "mdm".into(),
            audience: "mdm-api".into(),
            issuer: issuer.clone(),
            redirect: "https://mdm.example.test/auth/callback".into(),
            version: 1,
        })?],
        Lifetimes::new(LifetimeLimits {
            request: 300,
            code: 60,
            access_token: 300,
            clock_skew: 30,
        })?,
        Arc::new(PrepareAdmission::new(8, 120, Duration::from_secs(60))?),
    )?;
    let config = HttpConfig::new(origin, Duration::from_secs(30))?;
    let app = federated_router(federation.clone(), config.clone())?.merge(downstream_router(
        d,
        config,
        BTreeMap::from([("mdm".into(), Zeroizing::new(VALIDATION.into()))]),
    )?);
    let listener = tokio::net::TcpListener::bind(format!(
        "127.0.0.1:{}",
        std::env::var("IDENTITY_TEST_BRIDGE_PORT")?
    ))
    .await?;
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.layer(axum::middleware::map_request(
                |mut r: axum::extract::Request| async move {
                    r.extensions_mut()
                        .insert(ClientAddress("127.0.0.1".parse().unwrap()));
                    r
                },
            ))
            .into_make_service(),
        )
        .await
    });
    let c = Client::builder()
        .no_proxy()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
        .timeout(Duration::from_secs(10))
        .build()?;
    let input = json!({"client_id":"identity","return_target":"home"});
    let login = post(
        &c,
        origin,
        &format!("/api/v1/tenants/{A}/oidc/{}/login", p.id),
        input.clone(),
        None,
    )
    .await?;
    let callback =
        keycloak_support::authorize(login["authorization_url"].as_str().unwrap(), "alice", false)
            .await?;
    assert_eq!(
        c.get(callback).send().await?.status(),
        reqwest::StatusCode::SEE_OTHER
    );
    let session: Value = c
        .get(format!("{origin}/api/v1/tenants/{A}/session"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let csrf = session["csrf_token"].as_str().unwrap();
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
    let (old_token, _, _) = flow(
        &c,
        origin,
        &issuer,
        csrf,
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        false,
    )
    .await?;
    let old_proof = sdk.validate(&old_token).await?;
    assert_eq!(old_proof.acr().as_str(), "unspecified");
    let step = post(
        &c,
        origin,
        &format!("/api/v1/tenants/{A}/oidc/{}/step-up", p.id),
        input,
        Some(csrf),
    )
    .await?;
    let callback =
        keycloak_support::authorize(step["authorization_url"].as_str().unwrap(), "alice", true)
            .await?;
    assert_eq!(
        c.get(callback).send().await?.status(),
        reqwest::StatusCode::SEE_OTHER
    );
    let session: Value = c
        .get(format!("{origin}/api/v1/tenants/{A}/session"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let csrf = session["csrf_token"].as_str().unwrap();
    assert!(
        hydra
            .introspect(&Secret::new(old_token.clone())?)
            .await?
            .active
    );
    assert!(
        sdk.validate(&old_token).await.is_err(),
        "old grant must not inherit elevated session"
    );
    // Reusing a real MFA session later must not refresh its upstream authentication time.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (token, _, id_token) = flow(
        &c,
        origin,
        &issuer,
        csrf,
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        false,
    )
    .await?;
    let proof = sdk.validate(&token).await?;
    assert_eq!(proof.acr().as_str(), "mfa");
    assert_eq!(proof.subject(), old_proof.subject());
    assert_ne!(proof.session_id(), old_proof.session_id());
    let facts:Value = sqlx::query_scalar("SELECT auth_facts FROM identity_authority.sessions WHERE tenant_id=$1::uuid AND session_id=$2::uuid")
        .bind(A).bind(proof.session_id()).fetch_one(&f.owner).await?;
    assert_eq!(
        proof.auth_time(),
        facts["assurance"]["auth_time"].as_i64().unwrap()
    );
    // Inspect the actual TLS token response as an output assertion; it never constructs authority.
    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(id_token.split('.').nth(1).unwrap())?;
    let id_claims: Value = serde_json::from_slice(&payload)?;
    assert_eq!(id_claims["acr"], "unspecified");
    assert!(id_claims["auth_time"].as_i64().unwrap() > proof.auth_time());
    let methods: Vec<String> = id_claims
        .get("amr")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()?
        .unwrap_or_default();
    assert!(methods.is_empty());
    federation
        .enable_provider(
            session_actor(&f.store, f.candidate().await?).await?,
            p.id,
            p.version,
            false,
            deadline(),
        )
        .await?;
    assert!(sdk.validate(&token).await.is_err());
    server.abort();
    let _ = server.await;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "make test-downstream"]
async fn real_downstream_code_pkce_and_online_validation() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
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
    let fault = Arc::new(FaultHydra {
        inner: hydra.clone(),
        lose_consent: std::sync::atomic::AtomicBool::new(false),
        withheld: std::sync::Mutex::new(None),
    });
    let d = Downstream::new(
        f.store.clone(),
        fault.clone(),
        vec![
            Registration::new(RegistrationInput {
                tenant: f.key.tenant,
                client: ("mdm").to_owned(),
                audience: ("mdm-api").to_owned(),
                issuer: issuer.clone(),
                redirect: ("https://mdm.example.test/auth/callback").to_owned(),
                version: 1,
            })?,
            Registration::new(RegistrationInput {
                tenant: f.key.tenant,
                client: ("other").to_owned(),
                audience: ("other-api").to_owned(),
                issuer: issuer.clone(),
                redirect: ("https://other.example.test/auth/callback").to_owned(),
                version: 1,
            })?,
        ],
        Lifetimes::new(LifetimeLimits {
            request: 300,
            code: 60,
            access_token: 300,
            clock_skew: 30,
        })?,
        Arc::new(
            rss_identity_postgres::PrepareAdmission::new(
                8,
                120,
                std::time::Duration::from_secs(60),
            )
            .unwrap(),
        ),
    )?;
    let config = HttpConfig::new(origin, Duration::from_secs(30))?;
    let app = router(f.store.clone(), config.clone())?.merge(downstream_router(
        d.clone(),
        config,
        BTreeMap::from([
            ("mdm".into(), Zeroizing::new(VALIDATION.into())),
            (
                "other".into(),
                Zeroizing::new("other-validation-secret-32-characters".into()),
            ),
        ]),
    )?);
    let listener = tokio::net::TcpListener::bind(format!(
        "127.0.0.1:{}",
        std::env::var("IDENTITY_TEST_BRIDGE_PORT")?
    ))
    .await?;
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.layer(axum::middleware::map_request(
                |mut r: axum::extract::Request| async move {
                    if let Some(peer) = r
                        .extensions()
                        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                    {
                        let source = rss_identity_http_axum::ClientAddress(peer.0.ip());
                        r.extensions_mut().insert(source);
                    }
                    r
                },
            ))
            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
    });
    let c = Client::builder()
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
    let (token, handle, _) = flow(
        &c,
        origin,
        &issuer,
        csrf,
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        false,
    )
    .await?;
    let sdk = IdentityClient::new(
        ClientConfig {
            identity_origin: origin.into(),
            issuer: issuer.clone(),
            client_id: "mdm".into(),
            validation_secret: Zeroizing::new(VALIDATION.into()),
            tenant_id: A.into(),
            audience: "mdm-api".into(),
            timeout: Duration::from_secs(10),
            ca_pem: Some(ca.clone()),
        },
        std::sync::Arc::new(rss_identity_client::SystemClock),
    )?;
    let proof = sdk.validate(&token).await?;
    c.post(format!("{origin}/fixture/introspection"))
        .bearer_auth(SERVICE)
        .json(&json!({"unavailable":true}))
        .send()
        .await?
        .error_for_status()?;
    let error = sdk
        .validate(&token)
        .await
        .err()
        .expect("provider outage must reject");
    assert!(error.is_unavailable());
    assert!(error.correlation_id().is_some());
    c.post(format!("{origin}/fixture/introspection"))
        .bearer_auth(SERVICE)
        .json(&json!({"unavailable":false}))
        .send()
        .await?
        .error_for_status()?;
    sdk.validate(&token).await?;
    f.runtime.inject_next_transaction_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    let error = sdk
        .validate(&token)
        .await
        .err()
        .expect("storage failure must reject");
    assert!(error.is_unavailable());
    assert!(error.correlation_id().is_some());
    sdk.validate(&token).await?;

    assert_eq!(
        proof.amr().iter().map(|m| m.as_str()).collect::<Vec<_>>(),
        ["pwd"]
    );
    assert_eq!(proof.acr().as_str(), "unspecified");
    let before:String=sqlx::query_scalar("SELECT row_to_json(g)::text FROM identity_authority.downstream_grants g WHERE grant_id=$1::uuid").bind(handle["grant_id"].as_str().unwrap()).fetch_one(&f.owner).await?;
    sdk.validate(&token).await?;
    let after:String=sqlx::query_scalar("SELECT row_to_json(g)::text FROM identity_authority.downstream_grants g WHERE grant_id=$1::uuid").bind(handle["grant_id"].as_str().unwrap()).fetch_one(&f.owner).await?;
    assert_eq!(before, after);
    for (tenant, audience, client, secret) in [
        (B, "mdm-api", "mdm", VALIDATION),
        (A, "wrong", "mdm", VALIDATION),
        (
            A,
            "mdm-api",
            "other",
            "other-validation-secret-32-characters",
        ),
        (A, "mdm-api", "mdm", "bad"),
    ] {
        let r = c
            .post(format!("{origin}/internal/v1/identity/validate"))
            .basic_auth(client, Some(secret))
            .json(&json!({"credential":token,"tenant_id":tenant,"audience":audience}))
            .send()
            .await?;
        assert!(r.status().is_client_error());
        assert_eq!(r.headers()["cache-control"], "no-store");
    }
    assert!(
        flow(&c, origin, &issuer, csrf, "bad-verifier", false)
            .await
            .is_err()
    );
    flow(
        &c,
        origin,
        &issuer,
        csrf,
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        true,
    )
    .await?;
    for (key, value) in [
        ("code_challenge_method", "plain"),
        ("redirect_uri", "https://evil.example.test/callback"),
    ] {
        let mut url = Url::parse(&format!("{issuer}oauth2/auth"))?;
        url.query_pairs_mut().extend_pairs([
            ("client_id", "mdm"),
            ("response_type", "code"),
            ("scope", "openid"),
            ("audience", "mdm-api"),
            ("state", "test-state"),
            ("nonce", "test-nonce"),
            (
                "code_challenge",
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            ),
        ]);
        if key != "redirect_uri" {
            url.query_pairs_mut()
                .append_pair("redirect_uri", "https://mdm.example.test/auth/callback");
        }
        url.query_pairs_mut().append_pair(key, value);
        let response = c.get(url).send().await?;
        if response.status().is_redirection() {
            let target = location(response)?;
            if let Ok(challenge) = query(&target, "login_challenge") {
                let rejected = c
                    .post(format!("{origin}/api/v1/downstream/login"))
                    .header("Origin", origin)
                    .header("X-Identity-Request", "1")
                    .json(&json!({"challenge":challenge}))
                    .send()
                    .await?;
                assert!(rejected.status().is_client_error());
            }
            assert!(query(&target, "code").is_err());
        } else {
            assert!(response.status().is_client_error());
        }
    }
    let mut url = Url::parse(&format!("{issuer}oauth2/auth"))?;
    url.query_pairs_mut().extend_pairs([
        ("client_id", "mdm"),
        ("response_type", "code"),
        ("scope", "openid"),
        ("audience", "mdm-api"),
        ("redirect_uri", "https://mdm.example.test/auth/callback"),
        ("state", "missing-pkce"),
        ("nonce", "missing-pkce"),
    ]);
    let response = c.get(url).send().await?;
    if response.status().is_redirection() {
        let target = location(response)?;
        if let Ok(challenge) = query(&target, "login_challenge") {
            let rejected = c
                .post(format!("{origin}/api/v1/downstream/login"))
                .header("Origin", origin)
                .header("X-Identity-Request", "1")
                .json(&json!({"challenge":challenge}))
                .send()
                .await?;
            assert!(rejected.status().is_client_error());
        }
    } else {
        assert!(response.status().is_client_error());
    }
    // Real Hydra accepts, but Identity receives no response. First cleanup is a no-op
    // because the withheld verifier has not yet created the protocol grant.
    fault
        .lose_consent
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(
        flow(
            &c,
            origin,
            &issuer,
            csrf,
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            false
        )
        .await
        .is_err()
    );
    let late = fault
        .withheld
        .lock()
        .unwrap()
        .take()
        .expect("real accepted response was withheld");
    sqlx::query("UPDATE identity_authority.downstream_grants SET lease_until=0,next_attempt=created_at WHERE state=5").execute(&f.owner).await?;
    d.cleanup_once(f.key.tenant, 128, deadline()).await?;
    let late_callback = location(c.get(late).send().await?)?;
    let late_code = query(&late_callback, "code")?;
    let late_response = c
        .post(format!("{issuer}oauth2/token"))
        .basic_auth("mdm", Some("fixture-oidc-mdm-secret"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", late_code.as_str()),
            ("redirect_uri", "https://mdm.example.test/auth/callback"),
            (
                "code_verifier",
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            ),
        ])
        .send()
        .await?;
    assert!(late_response.status().is_success());
    let late_token: Value = late_response.json().await?;
    let late_credential = late_token["access_token"].as_str().unwrap();
    assert!(
        hydra
            .introspect(&Secret::new(late_credential.into())?)
            .await?
            .active
    );
    assert!(sdk.validate(late_credential).await.is_err());
    sqlx::query(
        "UPDATE identity_authority.downstream_grants SET next_attempt=created_at WHERE state=5",
    )
    .execute(&f.owner)
    .await?;
    d.cleanup_once(f.key.tenant, 128, deadline()).await?;
    assert!(
        hydra
            .introspect(&Secret::new(late_credential.into())?)
            .await
            .is_err()
    );
    fault
        .lose_consent
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let r = c
        .post(format!("{origin}/api/v1/tenants/{A}/session/logout"))
        .header("Origin", origin)
        .header("X-CSRF-Token", csrf)
        .send()
        .await?;
    assert_eq!(r.status(), 204);
    // Protocol remains active while the local authority already rejects it.
    assert!(hydra.introspect(&Secret::new(token.clone())?).await?.active);
    assert!(sdk.validate(&token).await.is_err());
    sqlx::query("UPDATE identity_authority.downstream_grants SET next_attempt=created_at")
        .execute(&f.owner)
        .await?;
    d.cleanup_once(f.key.tenant, 128, deadline()).await?;
    assert!(
        hydra
            .introspect(&Secret::new(token.clone())?)
            .await
            .is_err()
    );
    for (index, change) in ["password", "disabled", "membership", "all"]
        .into_iter()
        .enumerate()
    {
        f.reset_attempts().await?;
        let login_name = format!("downstream-member-{index}");
        let key = f
            .store
            .create_local_account(
                f.actor().await?,
                support::login(&login_name),
                password(),
                rss_identity_postgres::LocalAccountRole::Member,
                deadline(),
            )
            .await?;
        let logged = post(
            &c,
            origin,
            &format!("/api/v1/tenants/{A}/login"),
            json!({"login":login_name,"password":PASSWORD}),
            None,
        )
        .await?;
        let member_csrf = logged["csrf_token"].as_str().unwrap();
        let (member_token, _, _) = flow(
            &c,
            origin,
            &issuer,
            member_csrf,
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            false,
        )
        .await?;
        sdk.validate(&member_token).await?;
        if change == "all" {
            let result = c
                .post(format!("{origin}/api/v1/tenants/{A}/sessions/logout-all"))
                .header("Origin", origin)
                .header("X-CSRF-Token", member_csrf)
                .send()
                .await?;
            assert_eq!(result.status(), 204);
        } else {
            use rss_identity_core::account::{AccountChange, Password};
            let mutation = match change {
                "password" => AccountChange::Password(Password::new(
                    "changed correct horse battery staple".into(),
                )?),
                "disabled" => AccountChange::Enabled(false),
                _ => AccountChange::Membership(false),
            };
            support::apply_change(&f.store, f.actor().await?, key.key(), mutation, deadline())
                .await?;
        }
        assert!(
            hydra
                .introspect(&Secret::new(member_token.clone())?)
                .await?
                .active
        );
        assert!(
            matches!(
                sdk.validate(&member_token).await,
                Err(rss_identity_client::Error::Server {
                    code: rss_identity_contracts::ValidationFailureCode::IdentityNotActive,
                    ..
                })
            ),
            "revocation {change}"
        );
    }
    f.reset_attempts().await?;
    let consumer = tokio::task::spawn_blocking(|| {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        std::process::Command::new("python3")
            .arg(root.join("hack/consumer.py"))
            .current_dir(root)
            .output()
    })
    .await??;
    anyhow::ensure!(
        consumer.status.success(),
        "independent consumer failed: {}",
        String::from_utf8_lossy(&consumer.stdout)
    );
    server.abort();
    let _ = server.await;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "make test-downstream"]
async fn downstream_body_deadline_and_caller_auth() -> anyhow::Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use tower::ServiceExt;
    let f = Fixture::new().await?;
    let issuer = std::env::var("IDENTITY_TEST_DOWNSTREAM_ISSUER")?;
    let ca = std::fs::read(std::env::var("IDENTITY_TEST_DOWNSTREAM_CA")?)?;
    let protocol = Arc::new(rss_identity_hydra::Hydra::new(
        &issuer,
        &issuer,
        vec!["127.0.0.1/32".parse()?, "::1/128".parse()?],
        Secret::new(SERVICE.into())?,
        Some(&ca),
    )?);
    let d = Downstream::new(
        f.store.clone(),
        protocol,
        vec![Registration::new(RegistrationInput {
            tenant: f.key.tenant,
            client: ("mdm").to_owned(),
            audience: ("mdm-api").to_owned(),
            issuer: issuer.clone(),
            redirect: ("https://mdm.example.test/auth/callback").to_owned(),
            version: 1,
        })?],
        Lifetimes::new(LifetimeLimits {
            request: 300,
            code: 60,
            access_token: 300,
            clock_skew: 30,
        })?,
        Arc::new(
            rss_identity_postgres::PrepareAdmission::new(
                8,
                120,
                std::time::Duration::from_secs(60),
            )
            .unwrap(),
        ),
    )?;
    let app = downstream_router(
        d,
        HttpConfig::new(issuer.trim_end_matches('/'), Duration::from_millis(20))?,
        BTreeMap::from([("mdm".into(), Zeroizing::new(VALIDATION.into()))]),
    )?;
    for authenticated in [false, true] {
        let body = axum::body::Body::from_stream(futures::stream::pending::<
            Result<axum::body::Bytes, std::io::Error>,
        >());
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/internal/v1/identity/validate")
            .header("content-type", "application/json");
        if authenticated {
            request = request.header(
                "authorization",
                format!("Basic {}", STANDARD.encode(format!("mdm:{VALIDATION}"))),
            );
        }
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            app.clone().oneshot(request.body(body)?),
        )
        .await;
        assert!(response.is_ok(), "inbound body must have a deadline");
        let response = response??;
        assert_eq!(
            response.status().as_u16(),
            if authenticated { 503 } else { 401 }
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        let diagnostic = *response
            .extensions()
            .get::<DownstreamDiagnostic>()
            .expect("safe host diagnostic");
        if authenticated {
            assert!(matches!(
                diagnostic.failure,
                Some(HttpFailure::RequestTimeout)
            ));
        }
        let body = axum::body::to_bytes(response.into_body(), 4096).await?;
        let failure: Value = serde_json::from_slice(&body)?;
        assert_eq!(
            failure["correlation_id"].as_str(),
            Some(diagnostic.correlation_id.to_string().as_str())
        );
    }
    f.close().await;
    Ok(())
}
