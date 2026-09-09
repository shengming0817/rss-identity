//! Downstream settlement against real PG; protocol observations are injected here, real Hydra is separate T2.
#![allow(dead_code)]
mod support;
use rss_identity_core::{downstream::*, session::SessionSecret};
use rss_identity_postgres::*;
use rss_transactional_messaging_postgres::PgTransactionFault;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use support::*;
struct Protocol {
    subject: Mutex<String>,
    grant: Mutex<String>,
    unknown: AtomicBool,
    block_consent: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    calls: AtomicUsize,
    cleanup: AtomicUsize,
    prepare_calls: AtomicUsize,
    block_login: AtomicBool,
    fail_revoke: AtomicBool,
    block_revoke: AtomicBool,
    revoked: Mutex<Vec<(Option<String>, String)>>,
    mutation: AtomicUsize,
}
impl Protocol {
    fn new() -> Self {
        Self {
            subject: Mutex::new(String::new()),
            grant: Mutex::new(String::new()),
            unknown: AtomicBool::new(false),
            block_consent: AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            calls: AtomicUsize::new(0),
            cleanup: AtomicUsize::new(0),
            prepare_calls: AtomicUsize::new(0),
            block_login: AtomicBool::new(false),
            fail_revoke: AtomicBool::new(false),
            block_revoke: AtomicBool::new(false),
            revoked: Mutex::new(Vec::new()),
            mutation: AtomicUsize::new(0),
        }
    }
    fn challenge(&self, consent: bool) -> Challenge {
        Challenge {
            client: "mdm".into(),
            redirect: "https://mdm.test/auth/callback".into(),
            audiences: vec!["mdm-api".into()],
            scopes: vec!["openid".into()],
            pkce_s256: true,
            login_session_id: "sid".into(),
            subject: if consent {
                Some(self.subject.lock().unwrap().clone())
            } else {
                None
            },
            consent_request_id: consent.then(|| "consent-id".into()),
            login_binding: consent.then(|| self.grant.lock().unwrap().clone()),
        }
    }
}
impl DownstreamProtocol for Protocol {
    fn issuer(&self) -> &str {
        "https://identity.test"
    }
    fn login<'a>(&'a self, c: &'a Secret) -> ProtocolFuture<'a, Challenge> {
        Box::pin(async move {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            if self.block_login.load(Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
            }
            if c.expose() == "invalid" {
                return Err(DownstreamError::Rejected);
            }
            let mut r = self.challenge(false);
            if c.expose().starts_with("other-") {
                r.client = "other".into();
                r.audiences = vec!["other-api".into()];
                r.redirect = "https://other.test/auth/callback".into();
            }
            Ok(r)
        })
    }
    fn consent<'a>(&'a self, _: &'a Secret) -> ProtocolFuture<'a, Challenge> {
        Box::pin(async { Ok(self.challenge(true)) })
    }
    fn accept_login<'a>(&'a self, _: &'a Secret, d: LoginDecision) -> ProtocolFuture<'a, Secret> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.grant.lock().unwrap() = d.grant_id;
            *self.subject.lock().unwrap() = d.subject;
            if self.unknown.load(Ordering::SeqCst) {
                return Err(DownstreamError::Unavailable);
            }
            Secret::new("https://identity.test/oauth2/auth?login_verifier=x".into())
        })
    }
    fn accept_consent<'a>(
        &'a self,
        _: &'a Secret,
        d: ConsentDecision,
    ) -> ProtocolFuture<'a, Secret> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.grant.lock().unwrap() = d.grant_id;
            if self.block_consent.load(Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
            }
            if self.unknown.load(Ordering::SeqCst) {
                return Err(DownstreamError::Unavailable);
            }
            Secret::new("https://identity.test/oauth2/auth?consent_verifier=x".into())
        })
    }
    fn introspect<'a>(&'a self, _: &'a Secret) -> ProtocolFuture<'a, TokenObservation> {
        Box::pin(async {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let mut observation = TokenObservation {
                active: true,
                issuer: "https://identity.test".into(),
                client: "mdm".into(),
                audiences: vec!["mdm-api".into()],
                subject: self.subject.lock().unwrap().clone(),
                expires_at: now + 300,
                issued_at: now - 1,
                not_before: 0,
                grant_id: self.grant.lock().unwrap().clone(),
                version: 1,
                token_use: "access_token".into(),
                token_type: "Bearer".into(),
                scope: "openid".into(),
            };
            match self.mutation.load(Ordering::SeqCst) {
                1 => observation.issuer = "https://wrong.test".into(),
                2 => observation.client = "other".into(),
                3 => observation.audiences = vec!["other".into()],
                4 => observation.subject = "other".into(),
                5 => observation.grant_id = uuid::Uuid::new_v4().to_string(),
                6 => observation.version = 2,
                7 => observation.token_use = "refresh_token".into(),
                8 => observation.token_type = "MAC".into(),
                9 => observation.scope = "openid profile".into(),
                10 => observation.not_before = now + 31,
                11 => observation.issued_at = now + 31,
                12 => observation.expires_at = now,
                13 => observation.active = false,
                14 => {
                    observation.issued_at = now + 30;
                    observation.not_before = now + 30;
                }
                15 => observation.expires_at = observation.issued_at,
                _ => {}
            }
            Ok(observation)
        })
    }
    fn revoke<'a>(&'a self, consent: Option<&'a str>, sid: &'a str) -> ProtocolFuture<'a, ()> {
        Box::pin(async move {
            self.cleanup.fetch_add(1, Ordering::SeqCst);
            self.revoked
                .lock()
                .unwrap()
                .push((consent.map(String::from), sid.into()));
            if self.block_revoke.load(Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
            }
            if self.fail_revoke.load(Ordering::SeqCst) {
                return Err(DownstreamError::Unavailable);
            }
            Ok(())
        })
    }
}
fn service(f: &Fixture, p: Arc<Protocol>) -> Downstream {
    Downstream::new(
        f.store.clone(),
        p,
        vec![
            Registration::new(RegistrationInput {
                tenant: f.key.tenant,
                client: ("mdm").to_owned(),
                audience: ("mdm-api").to_owned(),
                issuer: ("https://identity.test").to_owned(),
                redirect: ("https://mdm.test/auth/callback").to_owned(),
                version: 1,
            })
            .unwrap(),
        ],
        Lifetimes::new(LifetimeLimits {
            request: 300,
            code: 60,
            access_token: 300,
            clock_skew: 30,
        })
        .unwrap(),
        Arc::new(
            rss_identity_postgres::PrepareAdmission::new(
                8,
                120,
                std::time::Duration::from_secs(60),
            )
            .unwrap(),
        ),
    )
    .unwrap()
}
fn secret(s: &str) -> Secret {
    Secret::new(s.into()).unwrap()
}
fn browser() -> BrowserBindingSecret {
    BrowserBindingSecret::parse("a".repeat(64)).unwrap()
}
async fn actor(f: &Fixture, s: &IssuedSession) -> anyhow::Result<AuthenticatedSession> {
    Ok(f.store
        .inspect_session(
            f.key.tenant,
            SessionSecret::parse(s.secret().expose().into())?,
            deadline(),
        )
        .await?)
}
async fn login(f: &Fixture, s: &IssuedSession, d: &Downstream) -> anyhow::Result<FlowHandle> {
    let h = d
        .begin_login(secret("login"), browser(), deadline())
        .await?;
    d.accept_login(
        h.clone(),
        secret("login"),
        browser(),
        actor(f, s).await?,
        deadline(),
    )
    .await?;
    Ok(h)
}
#[tokio::test]
#[ignore = "make test-downstream"]
async fn downstream_readonly_rotation_and_revocation() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let s = f
        .store
        .create_session(f.actor().await?, None, deadline())
        .await?;
    let p = Arc::new(Protocol::new());
    let d = service(&f, p.clone());
    let h = login(&f, &s, &d).await?;
    d.accept_consent(
        h.clone(),
        secret("consent"),
        browser(),
        actor(&f, &s).await?,
        deadline(),
    )
    .await?;
    let before: String = sqlx::query_scalar(
        "SELECT row_to_json(g)::text FROM identity_authority.downstream_grants g",
    )
    .fetch_one(&f.owner)
    .await?;
    let first = d
        .validate("mdm", f.key.tenant, "mdm-api", secret("token"), deadline())
        .await?;
    assert_eq!(first.amr(), ["pwd"]);
    assert_ne!(first.subject(), f.key.principal.as_uuid().to_string());
    for mutation in (1..=13).chain([15]) {
        p.mutation.store(mutation, Ordering::SeqCst);
        assert!(
            matches!(
                d.validate("mdm", f.key.tenant, "mdm-api", secret("token"), deadline())
                    .await,
                Err(AuthorityError::Downstream(DownstreamError::Rejected))
            ),
            "observation mutation {mutation}"
        );
    }
    p.mutation.store(14, Ordering::SeqCst);
    assert!(
        d.validate("mdm", f.key.tenant, "mdm-api", secret("token"), deadline())
            .await
            .is_ok()
    );
    p.mutation.store(0, Ordering::SeqCst);

    assert!(
        d.validate(
            "other",
            f.key.tenant,
            "mdm-api",
            secret("token"),
            deadline()
        )
        .await
        .is_err()
    );
    assert!(
        d.validate("mdm", f.key.tenant, "other", secret("token"), deadline())
            .await
            .is_err()
    );
    assert!(
        d.validate(
            "mdm",
            rss_request_context::TenantId::parse(B)?,
            "mdm-api",
            secret("token"),
            deadline()
        )
        .await
        .is_err()
    );
    let changed = Downstream::new(
        f.store.clone(),
        p.clone(),
        vec![Registration::new(RegistrationInput {
            tenant: f.key.tenant,
            client: ("mdm").to_owned(),
            audience: ("mdm-api").to_owned(),
            issuer: ("https://identity.test").to_owned(),
            redirect: ("https://mdm.test/changed-callback").to_owned(),
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
    assert!(
        changed
            .validate("mdm", f.key.tenant, "mdm-api", secret("token"), deadline())
            .await
            .is_err()
    );
    let after: String = sqlx::query_scalar(
        "SELECT row_to_json(g)::text FROM identity_authority.downstream_grants g",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(before, after);
    let refreshed = f
        .store
        .refresh_session(
            f.key.tenant,
            SessionSecret::parse(s.secret().expose().into())?,
            deadline(),
        )
        .await?;
    assert!(
        d.validate("mdm", f.key.tenant, "mdm-api", secret("token"), deadline())
            .await
            .is_ok()
    );
    f.store
        .revoke_current_session(actor(&f, &refreshed).await?, deadline())
        .await?;
    assert!(matches!(
        d.validate("mdm", f.key.tenant, "mdm-api", secret("token"), deadline())
            .await,
        Err(AuthorityError::Downstream(DownstreamError::Inactive))
    ));
    // A successful remote DELETE before the horizon must not remove the tombstone.
    sqlx::query("UPDATE identity_authority.downstream_grants SET next_attempt=created_at")
        .execute(&f.owner)
        .await?;
    let before_cleanup = f.events().await?;
    assert_eq!(d.cleanup_once(f.key.tenant, 10, deadline()).await?, 0);
    assert_eq!(f.events().await?, before_cleanup + 1);
    sqlx::query("UPDATE identity_authority.downstream_grants SET next_attempt=created_at")
        .execute(&f.owner)
        .await?;
    d.cleanup_once(f.key.tenant, 10, deadline()).await?;
    assert_eq!(f.events().await?, before_cleanup + 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM identity_authority.downstream_grants WHERE state=5"
        )
        .fetch_one(&f.owner)
        .await?,
        1
    );
    assert_eq!(p.cleanup.load(Ordering::SeqCst), 2);
    sqlx::query("UPDATE identity_authority.downstream_grants SET created_at=created_at-1000,expires_at=expires_at-1000,horizon=horizon-1000,next_attempt=created_at-1000,lease_until=0").execute(&f.owner).await?;
    assert_eq!(d.cleanup_once(f.key.tenant, 10, deadline()).await?, 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identity_authority.product_subjects")
            .fetch_one(&f.owner)
            .await?,
        1
    );
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "make test-downstream"]
async fn downstream_unknown_commit_and_single_accept() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let s = f
        .store
        .create_session(f.actor().await?, None, deadline())
        .await?;
    let p = Arc::new(Protocol::new());
    let d = service(&f, p.clone());
    let h = d
        .begin_login(secret("login"), browser(), deadline())
        .await?;
    let a = actor(&f, &s).await?;
    let b = actor(&f, &s).await?;
    let (x, y) = tokio::join!(
        d.accept_login(h.clone(), secret("login"), browser(), a, deadline()),
        d.accept_login(h.clone(), secret("login"), browser(), b, deadline())
    );
    assert_ne!(x.is_ok(), y.is_ok());
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    let proof = actor(&f, &s).await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        d.accept_consent(h, secret("consent"), browser(), proof, deadline())
            .await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "make test-downstream"]
async fn downstream_remote_unknown_never_returns_authority() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let s = f
        .store
        .create_session(f.actor().await?, None, deadline())
        .await?;
    let p = Arc::new(Protocol::new());
    let d = service(&f, p.clone());
    let h = login(&f, &s, &d).await?;
    p.unknown.store(true, Ordering::SeqCst);
    assert!(
        d.accept_consent(
            h,
            secret("consent"),
            browser(),
            actor(&f, &s).await?,
            deadline()
        )
        .await
        .is_err()
    );
    assert!(
        d.validate("mdm", f.key.tenant, "mdm-api", secret("token"), deadline())
            .await
            .is_err()
    );
    // Recreate the coordinator over the same durable authority and continue cleanup.
    sqlx::query(
        "UPDATE identity_authority.downstream_grants SET lease_until=0,next_attempt=created_at",
    )
    .execute(&f.owner)
    .await?;
    let restarted = service(&f, p.clone());
    restarted.cleanup_once(f.key.tenant, 10, deadline()).await?;
    assert!(p.cleanup.load(Ordering::SeqCst) > 0);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "make test-downstream"]
async fn downstream_accept_rechecks_revocation_and_final_commit() -> anyhow::Result<()> {
    for commit_unknown in [false, true] {
        let f = Fixture::new().await?;
        f.bootstrap().await?;
        let session = f
            .store
            .create_session(f.actor().await?, None, deadline())
            .await?;
        let p = Arc::new(Protocol::new());
        let d = service(&f, p.clone());
        let h = login(&f, &session, &d).await?;
        let accept_actor = actor(&f, &session).await?;
        let revoke_actor = actor(&f, &session).await?;
        p.block_consent.store(true, Ordering::SeqCst);
        let interfere = async {
            p.entered.notified().await;
            if commit_unknown {
                f.runtime
                    .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
            } else {
                f.store
                    .revoke_current_session(revoke_actor, deadline())
                    .await?;
            }
            p.release.notify_one();
            Ok::<(), AuthorityError>(())
        };
        let (result, interference) = tokio::join!(
            d.accept_consent(h, secret("consent"), browser(), accept_actor, deadline()),
            interfere
        );
        interference?;
        if commit_unknown {
            assert!(matches!(result, Err(AuthorityError::CommitUnknown(_))));
        } else {
            assert!(result.is_err());
        }
        assert!(
            d.validate("mdm", f.key.tenant, "mdm-api", secret("token"), deadline())
                .await
                .is_err()
        );
        f.close().await;
    }
    Ok(())
}
#[tokio::test]
#[ignore = "make test-downstream"]
async fn downstream_claim_and_event_roll_back_together() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let session = f
        .store
        .create_session(f.actor().await?, None, deadline())
        .await?;
    let p = Arc::new(Protocol::new());
    let d = service(&f, p.clone());
    let h = d
        .begin_login(secret("login"), browser(), deadline())
        .await?;
    let actor = actor(&f, &session).await?;
    sqlx::raw_sql("CREATE FUNCTION public.reject_downstream_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture event rejection'; END $$; CREATE TRIGGER reject_downstream_event BEFORE INSERT ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.reject_downstream_event();").execute(&f.owner).await?;
    assert!(
        d.accept_login(h, secret("login"), browser(), actor, deadline())
            .await
            .is_err()
    );
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
    let state: i16 = sqlx::query_scalar("SELECT state FROM identity_authority.downstream_grants")
        .fetch_one(&f.owner)
        .await?;
    assert_eq!(state, 0);
    f.close().await;
    Ok(())
}

#[path = "federation_support/mod.rs"]
mod federation_fixture;
#[tokio::test]
#[ignore = "make test-downstream"]
async fn downstream_federated_provider_revocation() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = federation_fixture::ScriptedOidc::new();
    let federation = federation_fixture::service(&f, upstream);
    let provider = federation_fixture::enabled(&f, &federation).await?;
    let state = federation_fixture::begin(&f, &federation, &provider).await?;
    let issued = federation_fixture::issued(
        federation_fixture::finish(&federation, state, "federated-subject").await?,
    );
    let p = Arc::new(Protocol::new());
    let d = service(&f, p);
    let h = login(&f, &issued, &d).await?;
    d.accept_consent(
        h,
        secret("consent"),
        browser(),
        actor(&f, &issued).await?,
        deadline(),
    )
    .await?;
    assert!(
        d.validate("mdm", f.key.tenant, "mdm-api", secret("token"), deadline())
            .await?
            .amr()
            .is_empty()
    );
    let disabled = f
        .store
        .enable_provider(
            federation_fixture::actor(&f).await?,
            provider.id,
            provider.version,
            false,
            deadline(),
        )
        .await?;
    assert!(matches!(
        d.validate("mdm", f.key.tenant, "mdm-api", secret("token"), deadline())
            .await,
        Err(AuthorityError::Downstream(DownstreamError::Inactive))
    ));
    f.store
        .enable_provider(
            federation_fixture::actor(&f).await?,
            provider.id,
            disabled.version,
            true,
            deadline(),
        )
        .await?;
    assert!(
        d.validate("mdm", f.key.tenant, "mdm-api", secret("token"), deadline())
            .await
            .is_err()
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "make test-downstream"]
async fn downstream_prepare_budget_is_per_client_and_releases_expired() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let p = Arc::new(Protocol::new());
    let registration = |client: &str| {
        Registration::new(RegistrationInput {
            tenant: f.key.tenant,
            client: client.into(),
            audience: format!("{client}-api"),
            issuer: "https://identity.test".into(),
            redirect: format!("https://{client}.test/auth/callback"),
            version: 1,
        })
        .unwrap()
    };
    let fingerprint = registration("mdm").fingerprint();
    let wrong = Registration::new(RegistrationInput {
        tenant: f.key.tenant,
        client: "mdm".into(),
        audience: "mdm-api".into(),
        issuer: "https://wrong.test".into(),
        redirect: "https://mdm.test/auth/callback".into(),
        version: 1,
    })?;
    assert!(
        Downstream::new(
            f.store.clone(),
            p.clone(),
            vec![wrong],
            Lifetimes::new(LifetimeLimits {
                request: 300,
                code: 60,
                access_token: 300,
                clock_skew: 30
            })?,
            Arc::new(
                rss_identity_postgres::PrepareAdmission::new(
                    8,
                    120,
                    std::time::Duration::from_secs(60)
                )
                .unwrap()
            ),
        )
        .is_err()
    );

    let d = Downstream::new(
        f.store.clone(),
        p,
        vec![registration("mdm"), registration("other")],
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
    for n in 0..60 {
        d.begin_login(secret(&format!("login-{n}")), browser(), deadline())
            .await?;
    }
    assert!(matches!(
        d.begin_login(secret("limit"), browser(), deadline()).await,
        Err(AuthorityError::RateLimited)
    ));
    d.begin_login(secret("other-first"), browser(), deadline())
        .await?;
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT bool_and(horizon=expires_at) FROM identity_authority.downstream_grants"
        )
        .fetch_one(&f.owner)
        .await?
    );
    sqlx::query("UPDATE identity_authority.downstream_grants SET created_at=created_at-601,expires_at=expires_at-601,horizon=horizon-601,next_attempt=created_at-601 WHERE client_id='mdm'").execute(&f.owner).await?;
    assert_eq!(d.cleanup_once(f.key.tenant, 128, deadline()).await?, 60);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identity_authority.downstream_grants")
            .fetch_one(&f.owner)
            .await?,
        1
    );
    sqlx::query("UPDATE identity_authority.attempts SET expires_at=clock_timestamp()-interval '1 second' WHERE key='downstream:mdm'").execute(&f.owner).await?;
    d.begin_login(secret("new-login"), browser(), deadline())
        .await?;
    sqlx::query("INSERT INTO identity_authority.downstream_grants(tenant_id,grant_id,client_id,config_version,registration_hash,login_hash,browser_hash,hydra_sid,state,created_at,expires_at,horizon,next_attempt) SELECT $1::uuid,gen_random_uuid(),'mdm',1,$2,sha256(convert_to('capacity-'||n::text,'UTF8')),sha256('browser'::bytea),'sid',0,floor(extract(epoch FROM clock_timestamp()))::bigint,floor(extract(epoch FROM clock_timestamp()))::bigint+300,floor(extract(epoch FROM clock_timestamp()))::bigint+300,floor(extract(epoch FROM clock_timestamp()))::bigint FROM generate_series(1,999) n").bind(f.key.tenant.to_string()).bind(fingerprint.as_slice()).execute(&f.owner).await?;
    assert!(matches!(
        d.begin_login(secret("capacity"), browser(), deadline())
            .await,
        Err(AuthorityError::Downstream(DownstreamError::Unavailable))
    ));
    d.begin_login(secret("other-second"), browser(), deadline())
        .await?;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "make test-downstream"]
async fn downstream_prepare_admission_precedes_invalid_protocol_work() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let p = Arc::new(Protocol::new());
    let d = service(&f, p.clone());
    // Invalid challenges consume admission even though no registration or PG write occurs.
    for _ in 0..120 {
        assert!(matches!(
            d.begin_login(secret("invalid"), browser(), deadline())
                .await,
            Err(AuthorityError::Downstream(DownstreamError::Rejected))
        ));
    }
    assert!(matches!(
        d.clone()
            .begin_login(secret("invalid"), browser(), deadline())
            .await,
        Err(AuthorityError::RateLimited)
    ));
    assert_eq!(p.prepare_calls.load(Ordering::SeqCst), 120);
    let d = service(&f, p.clone());
    p.block_login.store(true, Ordering::SeqCst);
    let mut jobs = Vec::new();
    for _ in 0..8 {
        let copy = d.clone();
        jobs.push(tokio::spawn(async move {
            copy.begin_login(secret("invalid"), browser(), deadline())
                .await
        }));
        tokio::time::timeout(std::time::Duration::from_secs(2), p.entered.notified()).await?;
    }
    assert!(matches!(
        d.begin_login(secret("invalid"), browser(), deadline())
            .await,
        Err(AuthorityError::RateLimited)
    ));
    assert_eq!(p.prepare_calls.load(Ordering::SeqCst), 128);
    for job in jobs {
        job.abort();
        let _ = job.await;
    }
    p.block_login.store(false, Ordering::SeqCst);
    assert!(matches!(
        d.begin_login(secret("invalid"), browser(), deadline())
            .await,
        Err(AuthorityError::Downstream(DownstreamError::Rejected))
    ));
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "make test-downstream"]
async fn downstream_cleanup_failure_concurrency_and_unknown_settlement() -> anyhow::Result<()> {
    for unknown in [false, true] {
        let f = Fixture::new().await?;
        f.bootstrap().await?;
        let session = f
            .store
            .create_session(f.actor().await?, None, deadline())
            .await?;
        let p = Arc::new(Protocol::new());
        let d = service(&f, p.clone());
        let h = login(&f, &session, &d).await?;
        d.accept_consent(
            h,
            secret("consent"),
            browser(),
            actor(&f, &session).await?,
            deadline(),
        )
        .await?;
        f.store
            .revoke_current_session(actor(&f, &session).await?, deadline())
            .await?;
        sqlx::query(
            "UPDATE identity_authority.downstream_grants SET next_attempt=created_at,lease_until=0",
        )
        .execute(&f.owner)
        .await?;
        let before = f.events().await?;
        p.block_revoke.store(true, Ordering::SeqCst);
        p.fail_revoke.store(!unknown, Ordering::SeqCst);
        let interfere = async {
            p.entered.notified().await;
            assert_eq!(d.cleanup_once(f.key.tenant, 10, deadline()).await?, 0);
            assert_eq!(p.cleanup.load(Ordering::SeqCst), 1);
            if unknown {
                f.runtime
                    .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
            }
            p.release.notify_one();
            Ok::<(), anyhow::Error>(())
        };
        let (result, other) = tokio::join!(d.cleanup_once(f.key.tenant, 10, deadline()), interfere);
        other?;
        if unknown {
            assert!(matches!(result, Err(AuthorityError::CommitUnknown(_))));
        } else {
            assert!(matches!(
                result,
                Err(AuthorityError::Downstream(DownstreamError::Unavailable))
            ));
        }
        assert_eq!(f.events().await?, before + 1);
        let row:(i16,i64,bool)=sqlx::query_as("SELECT state,lease_until,next_attempt>floor(extract(epoch FROM clock_timestamp()))::bigint FROM identity_authority.downstream_grants").fetch_one(&f.owner).await?;
        assert_eq!(row, (5, 0, true));
        assert!(
            d.validate("mdm", f.key.tenant, "mdm-api", secret("token"), deadline())
                .await
                .is_err()
        );
        p.block_revoke.store(false, Ordering::SeqCst);
        p.fail_revoke.store(false, Ordering::SeqCst);
        sqlx::query("UPDATE identity_authority.downstream_grants SET created_at=created_at-1000,expires_at=expires_at-1000,horizon=horizon-1000,next_attempt=created_at-1000").execute(&f.owner).await?;
        let restarted = service(&f, p.clone());
        assert_eq!(
            restarted.cleanup_once(f.key.tenant, 10, deadline()).await?,
            1
        );
        assert_eq!(
            restarted.cleanup_once(f.key.tenant, 10, deadline()).await?,
            0
        );
        assert_eq!(f.events().await?, before + 2);
        assert_eq!(
            *p.revoked.lock().unwrap(),
            vec![(Some("consent-id".into()), "sid".into()); 2]
        );
        f.close().await;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "make test-downstream"]
async fn downstream_cleanup_claim_rollback_and_final_unknown() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let session = f
        .store
        .create_session(f.actor().await?, None, deadline())
        .await?;
    let p = Arc::new(Protocol::new());
    let d = service(&f, p.clone());
    let h = login(&f, &session, &d).await?;
    d.accept_consent(
        h,
        secret("consent"),
        browser(),
        actor(&f, &session).await?,
        deadline(),
    )
    .await?;
    sqlx::query("UPDATE identity_authority.downstream_grants SET created_at=created_at-1000,expires_at=expires_at-1000,horizon=horizon-1000,next_attempt=created_at-1000,lease_until=0").execute(&f.owner).await?;
    let before = f.events().await?;
    sqlx::raw_sql("CREATE FUNCTION public.reject_cleanup_claim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture claim rejection'; END $$; CREATE TRIGGER reject_cleanup_claim BEFORE UPDATE OF lease_until ON identity_authority.downstream_grants FOR EACH ROW EXECUTE FUNCTION public.reject_cleanup_claim();").execute(&f.owner).await?;
    assert!(d.cleanup_once(f.key.tenant, 10, deadline()).await.is_err());
    assert_eq!(p.cleanup.load(Ordering::SeqCst), 0);
    assert_eq!(f.events().await?, before);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT lease_until FROM identity_authority.downstream_grants"
        )
        .fetch_one(&f.owner)
        .await?,
        0
    );
    sqlx::raw_sql("DROP TRIGGER reject_cleanup_claim ON identity_authority.downstream_grants; DROP FUNCTION public.reject_cleanup_claim();").execute(&f.owner).await?;
    p.block_revoke.store(true, Ordering::SeqCst);
    let inject = async {
        p.entered.notified().await;
        f.runtime
            .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
        p.release.notify_one();
    };
    let (result, ()) = tokio::join!(d.cleanup_once(f.key.tenant, 10, deadline()), inject);
    assert!(matches!(result, Err(AuthorityError::CommitUnknown(_))));
    assert_eq!(f.events().await?, before + 2);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identity_authority.downstream_grants")
            .fetch_one(&f.owner)
            .await?,
        0
    );
    assert_eq!(
        service(&f, p.clone())
            .cleanup_once(f.key.tenant, 10, deadline())
            .await?,
        0
    );
    assert_eq!(p.cleanup.load(Ordering::SeqCst), 1);
    assert_eq!(f.events().await?, before + 2);
    f.close().await;
    Ok(())
}
