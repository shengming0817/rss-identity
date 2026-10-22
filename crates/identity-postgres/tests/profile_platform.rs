mod support;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use rss_identity_core::{assurance::Acr, profile::*, session::AuthenticationSource};
use rss_identity_postgres::{platform::*, *};
use rss_transactional_messaging_postgres::PgTransactionFault;
use serde_json::json;
use sqlx::Row;
use std::sync::Arc;
use support::*;
use uuid::Uuid;

fn local(value: &str) -> LocalProfile {
    LocalProfile {
        display_name: Some(value.into()),
        username: None,
        email: None,
        extensions: Extensions::try_from(json!({"employeeNumber":value,"remote":false})).unwrap(),
        max_age_seconds: 60,
    }
}
async fn proof(
    store: &Authority,
    f: &Fixture,
    s: &IssuedSession,
) -> anyhow::Result<AuthenticatedSession> {
    Ok(store
        .inspect_session(
            f.key.tenant,
            rss_identity_core::session::SessionSecret::parse(s.secret().expose().into())?,
            deadline(),
        )
        .await?)
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn local_profile_observation_receipts_and_revocation() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let first = f.login().await?;
    let first_proof = proof(&f.store, &f, &first).await?;
    let initial = f.store.current_profile(&first_proof, deadline()).await?;
    let snapshot = initial.view()?.snapshot_id;
    let change = ProfileChange {
        operation_id: Uuid::new_v4(),
        expected_revision: 0,
        value: Some(local("E1001")),
    };
    let receipt = f
        .store
        .update_local_profile(
            proof(&f.store, &f, &first).await?,
            f.key,
            change.clone(),
            deadline(),
        )
        .await?;
    assert_eq!(receipt.revision, 1);
    assert_eq!(
        f.store
            .update_local_profile(
                proof(&f.store, &f, &first).await?,
                f.key,
                change.clone(),
                deadline()
            )
            .await?
            .revision,
        1
    );
    assert_eq!(
        f.store
            .local_profile_receipt(&first_proof, f.key, change.operation_id, deadline())
            .await?
            .unwrap()
            .revision,
        1
    );
    let events:Vec<serde_json::Value>=sqlx::query_scalar("SELECT envelope FROM rss_transactional_messaging.outbox WHERE envelope->>'route'='profile.changed'").fetch_all(&f.owner).await?;
    let mut updates = 0;
    for event in events {
        let bytes: Vec<u8> = serde_json::from_value(event["payload"].clone())?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        if value["action"] == "local_updated" {
            updates += 1;
            assert_eq!(value["revision"], 1);
            assert!(
                value["changed_fields"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("extensions"))
            );
        }
        assert!(!String::from_utf8(bytes)?.contains("E1001"));
    }
    assert_eq!(updates, 1);
    let mut different = change.clone();
    different.value = Some(local("changed"));
    assert!(matches!(
        f.store
            .update_local_profile(
                proof(&f.store, &f, &first).await?,
                f.key,
                different,
                deadline()
            )
            .await,
        Err(AuthorityError::OperationConflict)
    ));
    assert_eq!(
        f.store
            .current_profile(&first_proof, deadline())
            .await?
            .view()?
            .snapshot_id,
        snapshot
    );
    let second = f.login().await?;
    let second_proof = proof(&f.store, &f, &second).await?;
    assert_eq!(
        f.store
            .current_profile(&second_proof, deadline())
            .await?
            .view()?
            .profile
            .as_ref()
            .unwrap()
            .display_name
            .value()
            .map(String::as_str),
        Some("E1001")
    );
    assert_eq!(
        f.store
            .current_profile(&first_proof, deadline())
            .await?
            .view()?
            .status,
        ProfileStatus::Unavailable
    );
    let before = f
        .store
        .current_profile(&second_proof, deadline())
        .await?
        .view()?
        .expires_at;
    let refreshed = f
        .store
        .refresh_session(
            f.key.tenant,
            rss_identity_core::session::SessionSecret::parse(second.secret().expose().into())?,
            deadline(),
        )
        .await?;
    let refreshed_proof = proof(&f.store, &f, &refreshed).await?;
    assert_eq!(
        f.store
            .current_profile(&refreshed_proof, deadline())
            .await?
            .view()?
            .expires_at,
        before
    );
    let remove = ProfileChange {
        operation_id: Uuid::new_v4(),
        expected_revision: 1,
        value: None,
    };
    f.store
        .update_local_profile(
            proof(&f.store, &f, &refreshed).await?,
            f.key,
            remove,
            deadline(),
        )
        .await?;
    let third = f.login().await?;
    let third_proof = proof(&f.store, &f, &third).await?;
    assert!(
        f.store
            .current_profile(&third_proof, deadline())
            .await?
            .view()?
            .profile
            .as_ref()
            .unwrap()
            .display_name
            .value()
            .is_none()
    );
    let unknown = ProfileChange {
        operation_id: Uuid::new_v4(),
        expected_revision: 2,
        value: Some(local("E2002")),
    };
    let actor = proof(&f.store, &f, &third).await?;
    f.runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        f.store
            .update_local_profile(actor, f.key, unknown.clone(), deadline())
            .await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    assert_eq!(
        f.store
            .local_profile_receipt(&third_proof, f.key, unknown.operation_id, deadline())
            .await?
            .unwrap()
            .revision,
        3
    );
    let rollback = ProfileChange {
        operation_id: Uuid::new_v4(),
        expected_revision: 3,
        value: Some(local("must-rollback")),
    };
    sqlx::raw_sql("CREATE FUNCTION public.reject_profile_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.envelope->>'route'='profile.changed' THEN RAISE EXCEPTION 'fixture reject'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_profile_event BEFORE INSERT ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.reject_profile_event();").execute(&f.owner).await?;
    assert!(
        f.store
            .update_local_profile(
                proof(&f.store, &f, &third).await?,
                f.key,
                rollback.clone(),
                deadline()
            )
            .await
            .is_err()
    );
    assert_eq!(
        f.store
            .read_local_profile(&third_proof, f.key, deadline())
            .await?
            .revision,
        3
    );
    assert!(
        f.store
            .local_profile_receipt(&third_proof, f.key, rollback.operation_id, deadline())
            .await?
            .is_none()
    );
    sqlx::raw_sql("DROP TRIGGER reject_profile_event ON rss_transactional_messaging.outbox")
        .execute(&f.owner)
        .await?;
    f.policy.revoke(f.key);
    assert!(
        f.store
            .read_local_profile(&third_proof, f.key, deadline())
            .await
            .is_err()
    );
    assert!(
        f.store
            .latest_profile(
                &third_proof,
                f.key,
                ProfileSource::IdentityLocal,
                deadline()
            )
            .await
            .is_err()
    );
    f.policy.allow(f.key);
    f.store
        .set_account_enabled(proof(&f.store, &f, &third).await?, f.key, false, deadline())
        .await?;
    assert!(
        f.store
            .current_profile(&third_proof, deadline())
            .await
            .is_err()
    );
    f.close().await;
    Ok(())
}

struct Verifier {
    binding: PlatformBinding,
    key: Ed25519KeyPair,
    local: bool,
    unavailable: std::sync::atomic::AtomicBool,
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    fault: std::sync::Mutex<Option<PgTransactionFault>>,
}
impl PlatformVerifier for Verifier {
    fn audience(&self) -> &str {
        "rss-mdm-browser"
    }
    fn resolve<'a>(
        &'a self,
        instance: rss_identity_core::InstanceId,
        tenant: rss_request_context::TenantId,
        binding: Uuid,
        c: &'a mut sqlx::PgConnection,
    ) -> futures::future::BoxFuture<'a, Result<PlatformBinding, PlatformError>> {
        Box::pin(async move {
            if instance != self.binding.instance
                || tenant != self.binding.account.tenant
                || binding != self.binding.binding_id
            {
                return Err(PlatformError::Rejected);
            }
            self.recheck(&self.binding, c).await?;
            Ok(self.binding.clone())
        })
    }
    fn verify<'a>(
        &'a self,
        context: &'a PlatformChallengeContext,
        evidence: &'a [u8],
    ) -> futures::future::BoxFuture<'a, Result<PlatformEvidence, PlatformError>> {
        Box::pin(async move {
            if context.audience != self.audience() {
                return Err(PlatformError::Rejected);
            }
            UnparsedPublicKey::new(&ED25519, self.key.public_key().as_ref())
                .verify(context.nonce.as_bytes(), evidence)
                .map_err(|_| PlatformError::Rejected)?;
            if let Some(fault) = self.fault.lock().unwrap().take() {
                self.runtime.inject_next_transaction_fault(fault);
            }
            Ok(PlatformEvidence {
                key_possession: true,
                hardware_key: true,
                user_presence: false,
                user_verification: false,
                authenticated_at: None,
                profile: if self.local {
                    PlatformProfile::IdentityLocal
                } else {
                    PlatformProfile::Unavailable
                },
            })
        })
    }
    fn recheck<'a>(
        &'a self,
        binding: &'a PlatformBinding,
        c: &'a mut sqlx::PgConnection,
    ) -> futures::future::BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            if self.unavailable.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(PlatformError::Unavailable);
            }
            let row = sqlx::query(
                "SELECT enabled,epoch FROM public.platform_binding WHERE id=$1 FOR UPDATE",
            )
            .bind(binding.binding_id)
            .fetch_one(c)
            .await
            .map_err(|_| PlatformError::Unavailable)?;
            if binding != &self.binding
                || !row
                    .try_get::<bool, _>("enabled")
                    .map_err(|_| PlatformError::Unavailable)?
                || row
                    .try_get::<i64, _>("epoch")
                    .map_err(|_| PlatformError::Unavailable)?
                    != binding.binding_epoch
            {
                return Err(PlatformError::Rejected);
            }
            Ok(())
        })
    }
}
async fn platform_host(f: &Fixture, local: bool) -> anyhow::Result<(Authority, Arc<Verifier>)> {
    sqlx::raw_sql("CREATE TABLE public.platform_binding(id uuid PRIMARY KEY,enabled boolean NOT NULL,epoch bigint NOT NULL); GRANT SELECT,UPDATE ON public.platform_binding TO identity_runtime;").execute(&f.owner).await?;
    let binding = PlatformBinding {
        instance: f.instance,
        account: f.key,
        binding_id: Uuid::new_v4(),
        binding_epoch: 1,
        source_id: Uuid::new_v4(),
        source_version: 1,
        external_identity: None,
    };
    sqlx::query("INSERT INTO public.platform_binding VALUES($1,true,1)")
        .bind(binding.binding_id)
        .execute(&f.owner)
        .await?;
    let verifier = Arc::new(Verifier {
        binding: binding.clone(),
        key: Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap(),
        local,
        unavailable: std::sync::atomic::AtomicBool::new(false),
        runtime: f.runtime.clone(),
        fault: std::sync::Mutex::new(None),
    });
    let store = Authority::connect_runtime(
        f.runtime.clone(),
        Arc::new(rss_identity_core::account::PasswordKdf::new()),
        f.config().with_platform(verifier.clone()),
        f.policy.clone(),
        deadline(),
    )
    .await?;
    Ok((store, verifier))
}
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn platform_challenges_are_one_use_and_all_session_paths_recheck() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let (store, verifier) = platform_host(&f, false).await?;
    let binding = verifier.binding.clone();
    let browser = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let challenge = store
        .begin_platform_login(
            f.key.tenant,
            binding.binding_id,
            browser.into(),
            source(),
            deadline(),
        )
        .await?;
    let signature = verifier
        .key
        .sign(challenge.nonce.as_bytes())
        .as_ref()
        .to_vec();
    let (a, b) = tokio::join!(
        store.complete_platform_login(
            f.key.tenant,
            challenge.id,
            challenge.nonce.clone(),
            browser.into(),
            signature.clone(),
            deadline()
        ),
        store.complete_platform_login(
            f.key.tenant,
            challenge.id,
            challenge.nonce,
            browser.into(),
            signature,
            deadline()
        )
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let issued = match (a, b) {
        (Ok(v), _) | (_, Ok(v)) => v,
        _ => unreachable!(),
    };
    let actor = proof(&store, &f, &issued).await?;
    let reference = actor.reference()?;
    assert_eq!(
        actor.authentication_source()?,
        AuthenticationSource::Platform
    );
    assert_eq!(actor.assurance()?.acr(), Acr::Unspecified);
    assert_eq!(actor.assurance()?.auth_time(), None);
    assert_eq!(
        store
            .current_profile(&actor, deadline())
            .await?
            .view()?
            .status,
        ProfileStatus::Unavailable
    );
    assert!(
        f.store
            .inspect_session(
                f.key.tenant,
                rss_identity_core::session::SessionSecret::parse(issued.secret().expose().into())?,
                deadline()
            )
            .await
            .is_err()
    );
    verifier
        .unavailable
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        store
            .inspect_session(
                f.key.tenant,
                rss_identity_core::session::SessionSecret::parse(issued.secret().expose().into())?,
                deadline()
            )
            .await,
        Err(AuthorityError::RolledBack(StorageFailure::Transient))
    ));
    assert!(matches!(
        store
            .recheck_session_reference(f.key.tenant, &reference, deadline())
            .await,
        Err(AuthorityError::RolledBack(StorageFailure::Transient))
    ));
    verifier
        .unavailable
        .store(false, std::sync::atomic::Ordering::SeqCst);
    sqlx::query("UPDATE public.platform_binding SET enabled=false,epoch=2 WHERE id=$1")
        .bind(binding.binding_id)
        .execute(&f.owner)
        .await?;
    assert!(proof(&store, &f, &issued).await.is_err());
    assert!(
        store
            .recheck_session_reference(f.key.tenant, &reference, deadline())
            .await
            .is_err()
    );
    assert!(
        store
            .refresh_session(
                f.key.tenant,
                rss_identity_core::session::SessionSecret::parse(issued.secret().expose().into())?,
                deadline()
            )
            .await
            .is_err()
    );
    assert!(
        store
            .read_local_profile(&actor, f.key, deadline())
            .await
            .is_err()
    );
    let local = store
        .login_local(
            f.key.tenant,
            login("admin"),
            password(),
            source(),
            None,
            deadline(),
        )
        .await?;
    let listed = store
        .list_sessions(proof(&store, &f, &local).await?, None, 100, deadline())
        .await?;
    assert!(!listed.sessions.iter().any(|s| s.id == issued.view().id));
    f.close().await;
    Ok(())
}

mod federation_support;
#[tokio::test]
#[ignore = "requires make test-pg"]
async fn older_oidc_completion_cannot_replace_a_newer_observation() -> anyhow::Result<()> {
    use federation_support::*;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let early = ScriptedOidc::new();
    let later = ScriptedOidc::new();
    *early.profile.lock().unwrap() = Some(local("old").observation()?);
    *later.profile.lock().unwrap() = Some(local("new").observation()?);
    let first_service = service(&f, early);
    let second_service = service(&f, later);
    let p = enabled(&f, &first_service).await?;
    let first_attempt = begin(&f, &first_service, &p).await?;
    let second_attempt = begin(&f, &second_service, &p).await?;
    let second = issued(finish(&second_service, second_attempt, "alice").await?);
    let second_proof = proof(&f.store, &f, &second).await?;
    let current = f.store.current_profile(&second_proof, deadline()).await?;
    let snapshot = current.view()?.snapshot_id;
    assert_eq!(
        current
            .view()?
            .profile
            .as_ref()
            .unwrap()
            .display_name
            .value()
            .map(String::as_str),
        Some("new")
    );
    let first = issued(finish(&first_service, first_attempt, "alice").await?);
    assert_eq!(
        f.store
            .current_profile(&proof(&f.store, &f, &first).await?, deadline())
            .await?
            .view()?
            .status,
        ProfileStatus::Unavailable
    );
    assert_eq!(
        f.store
            .current_profile(&second_proof, deadline())
            .await?
            .view()?
            .snapshot_id,
        snapshot
    );
    let clock = ControlledFactTime::default();
    clock.advance_to(current.view()?.expires_at.unwrap() + 1)?;
    let timed = f.store.clone().with_fact_time(clock);
    let stale = timed
        .current_profile(&proof(&timed, &f, &second).await?, deadline())
        .await?;
    assert_eq!(stale.view()?.status, ProfileStatus::Expired);
    assert!(stale.view()?.profile.is_none());
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn platform_binding_errors_and_uncertain_commit_never_issue_a_secret() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let (store, verifier) = platform_host(&f, true).await?;
    let browser = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
    let begin = store
        .begin_platform_login(
            f.key.tenant,
            verifier.binding.binding_id,
            browser.into(),
            source(),
            deadline(),
        )
        .await?;
    let signature = verifier.key.sign(begin.nonce.as_bytes()).as_ref().to_vec();
    assert!(
        store
            .complete_platform_login(
                f.key.tenant,
                begin.id,
                "x".repeat(43),
                browser.into(),
                signature.clone(),
                deadline()
            )
            .await
            .is_err()
    );
    assert!(
        store
            .complete_platform_login(
                f.key.tenant,
                begin.id,
                begin.nonce.clone(),
                "x".repeat(43),
                signature.clone(),
                deadline()
            )
            .await
            .is_err()
    );
    assert!(
        store
            .complete_platform_login(
                rss_request_context::TenantId::parse(B)?,
                begin.id,
                begin.nonce.clone(),
                browser.into(),
                signature.clone(),
                deadline()
            )
            .await
            .is_err()
    );
    assert!(
        store
            .complete_platform_login(
                f.key.tenant,
                begin.id,
                begin.nonce.clone(),
                browser.into(),
                vec![0; 64],
                deadline()
            )
            .await
            .is_err()
    );
    *verifier.fault.lock().unwrap() = Some(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        store
            .complete_platform_login(
                f.key.tenant,
                begin.id,
                begin.nonce.clone(),
                browser.into(),
                signature.clone(),
                deadline()
            )
            .await,
        Err(AuthorityError::CommitUnknown(_))
    ));
    assert!(
        store
            .complete_platform_login(
                f.key.tenant,
                begin.id,
                begin.nonce,
                browser.into(),
                signature,
                deadline()
            )
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.sessions WHERE authentication_source='platform'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(count, 1);
    let observations: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity_authority.profile_observations")
            .fetch_one(&f.owner)
            .await?;
    assert_eq!(observations, 1);
    let begin = store
        .begin_platform_login(
            f.key.tenant,
            verifier.binding.binding_id,
            browser.into(),
            source(),
            deadline(),
        )
        .await?;
    let signature = verifier.key.sign(begin.nonce.as_bytes()).as_ref().to_vec();
    sqlx::raw_sql("CREATE FUNCTION public.reject_profile() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture rejection'; END $$; CREATE TRIGGER reject_profile BEFORE INSERT OR UPDATE ON identity_authority.profile_observations FOR EACH ROW EXECUTE FUNCTION public.reject_profile();").execute(&f.owner).await?;
    assert!(
        store
            .complete_platform_login(
                f.key.tenant,
                begin.id,
                begin.nonce.clone(),
                browser.into(),
                signature.clone(),
                deadline()
            )
            .await
            .is_err()
    );
    let after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.sessions WHERE authentication_source='platform'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(after, count);
    sqlx::raw_sql("DROP TRIGGER reject_profile ON identity_authority.profile_observations")
        .execute(&f.owner)
        .await?;
    sqlx::query("UPDATE public.platform_binding SET epoch=2 WHERE id=$1")
        .bind(verifier.binding.binding_id)
        .execute(&f.owner)
        .await?;
    assert!(
        store
            .complete_platform_login(
                f.key.tenant,
                begin.id,
                begin.nonce,
                browser.into(),
                signature,
                deadline()
            )
            .await
            .is_err()
    );
    f.close().await;
    Ok(())
}
