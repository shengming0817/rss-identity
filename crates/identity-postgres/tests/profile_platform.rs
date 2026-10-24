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
        personnel_session(&f.store, &second_proof, second.view().id.as_uuid()).await?,
        Some((false, None))
    );
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
    evidence: std::sync::Mutex<(bool, bool, Option<i64>)>,
    idp: std::sync::Mutex<
        Option<(
            rss_identity_core::federation::ProviderId,
            rss_identity_core::federation::UpstreamClaims,
        )>,
    >,
    unavailable: std::sync::atomic::AtomicBool,
    last_backend: std::sync::atomic::AtomicI32,
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    fault: std::sync::Mutex<Option<PgTransactionFault>>,
}
impl PlatformVerifier for Verifier {
    fn authorize_purpose<'a>(
        &'a self,
        _binding: &'a PlatformBinding,
        purpose: &'a PlatformPurpose,
        _c: &'a mut sqlx::PgConnection,
    ) -> futures::future::BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            if *purpose == PlatformPurpose::BrowserLogin {
                Ok(())
            } else {
                Err(PlatformError::Rejected)
            }
        })
    }
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
                .verify(&context.signing_payload()?, evidence)
                .map_err(|_| PlatformError::Rejected)?;
            if let Some(fault) = self.fault.lock().unwrap().take() {
                self.runtime.inject_next_transaction_fault(fault);
            }
            let (key_possession, user_verification, authenticated_at) =
                *self.evidence.lock().unwrap();
            Ok(PlatformEvidence {
                key_possession,
                hardware_key: true,
                user_presence: false,
                user_verification,
                authenticated_at,
                profile: if let Some((provider, claims)) = self.idp.lock().unwrap().clone() {
                    PlatformProfile::Idp {
                        provider,
                        claims: Box::new(claims),
                    }
                } else if self.local {
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
            let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *c)
                .await
                .map_err(|_| PlatformError::Unavailable)?;
            self.last_backend
                .store(pid, std::sync::atomic::Ordering::SeqCst);
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
    platform_host_for(f, local, f.key, None).await
}
async fn platform_host_for(
    f: &Fixture,
    local: bool,
    account: rss_identity_core::account::AccountKey,
    external: Option<ExternalBinding>,
) -> anyhow::Result<(Authority, Arc<Verifier>)> {
    sqlx::raw_sql("CREATE TABLE public.platform_binding(id uuid PRIMARY KEY,enabled boolean NOT NULL,epoch bigint NOT NULL); GRANT SELECT,UPDATE ON public.platform_binding TO identity_runtime;").execute(&f.owner).await?;
    let binding = PlatformBinding {
        instance: f.instance,
        account,
        binding_id: Uuid::new_v4(),
        binding_epoch: 1,
        source_id: Uuid::new_v4(),
        source_version: 1,
        external_identity: external,
    };
    sqlx::query("INSERT INTO public.platform_binding VALUES($1,true,1)")
        .bind(binding.binding_id)
        .execute(&f.owner)
        .await?;
    let verifier = Arc::new(Verifier {
        binding: binding.clone(),
        key: Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap(),
        local,
        evidence: std::sync::Mutex::new((true, false, None)),
        idp: std::sync::Mutex::new(None),
        unavailable: std::sync::atomic::AtomicBool::new(false),
        last_backend: std::sync::atomic::AtomicI32::new(0),
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
            PlatformPurpose::BrowserLogin,
            browser.into(),
            source(),
            deadline(),
        )
        .await?;
    let signature = verifier
        .key
        .sign(&challenge.signing_payload)
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
        (Ok(v), _) | (_, Ok(v)) => v.session,
        _ => unreachable!(),
    };
    let actor = proof(&store, &f, &issued).await?;
    let reference = actor.reference()?;
    assert_eq!(
        personnel_session(&store, &actor, issued.view().id.as_uuid()).await?,
        Some((true, Some(binding.binding_id.to_string())))
    );
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
    assert_eq!(
        personnel_session(&f.store, &second_proof, second.view().id.as_uuid()).await?,
        Some((false, None))
    );
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
            PlatformPurpose::BrowserLogin,
            browser.into(),
            source(),
            deadline(),
        )
        .await?;
    let signature = verifier.key.sign(&begin.signing_payload).as_ref().to_vec();
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
            .map(|outcome| outcome.session)
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
            .map(|outcome| outcome.session)
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
            .map(|outcome| outcome.session)
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
            .map(|outcome| outcome.session)
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
            .await
            .map(|outcome| outcome.session),
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
            .map(|outcome| outcome.session)
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
            PlatformPurpose::BrowserLogin,
            browser.into(),
            source(),
            deadline(),
        )
        .await?;
    let signature = verifier.key.sign(&begin.signing_payload).as_ref().to_vec();
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
            .map(|outcome| outcome.session)
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
            .map(|outcome| outcome.session)
            .is_err()
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn platform_external_identity_and_fresh_profile_are_bound_and_revocable() -> anyhow::Result<()>
{
    use federation_support::*;
    use rss_identity_core::{
        department::UpstreamDepartmentSnapshot, entra::ExternalSubject, federation::*,
        groups::UpstreamGroups,
    };
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let oidc = service(&f, ScriptedOidc::new());
    let provider = enabled(&f, &oidc).await?;
    let login = issued(finish(&oidc, begin(&f, &oidc, &provider).await?, "platform-user").await?);
    let account = proof(&f.store, &f, &login).await?.account();
    let identity: Uuid = sqlx::query_scalar(
        "SELECT identity_id FROM identity_authority.external_identities WHERE principal_id=$1",
    )
    .bind(account.principal.as_uuid())
    .fetch_one(&f.owner)
    .await?;
    let (store, verifier) = platform_host_for(
        &f,
        false,
        account,
        Some(ExternalBinding {
            identity_id: identity,
            provider: provider.id,
            config_version: provider.version,
            revocation_epoch: provider.revocation_epoch,
        }),
    )
    .await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.owner)
            .await?;
    let claims = UpstreamClaims {
        issuer: provider.settings.issuer().as_str().into(),
        subject: ExternalSubject::Oidc("platform-user".into()),
        profile: local("fresh-platform").observation()?,
        groups: UpstreamGroups::present(vec![])?,
        department_snapshot: UpstreamDepartmentSnapshot::NotConfigured,
        issued_at: now,
        expires_at: now + 600,
        assurance: rss_identity_core::assurance::Assurance::new(None, Acr::Unspecified, vec![])?,
    };
    let challenge = store
        .begin_platform_login(
            f.key.tenant,
            verifier.binding.binding_id,
            PlatformPurpose::BrowserLogin,
            BROWSER.into(),
            source(),
            deadline(),
        )
        .await?;
    let signature = verifier
        .key
        .sign(&challenge.signing_payload)
        .as_ref()
        .to_vec();
    // Each rejection must leave the challenge and observation untouched.
    for bad in 0..4 {
        let mut value = claims.clone();
        let mut source = provider.id;
        match bad {
            0 => source = ProviderId::parse(&Uuid::new_v4().to_string())?,
            1 => value.subject = ExternalSubject::Oidc("different-user".into()),
            2 => value.issuer = "https://other.example.test".into(),
            _ => value.issued_at = challenge.expires_at - 120 - 31,
        }
        *verifier.idp.lock().unwrap() = Some((source, value));
        assert!(
            store
                .complete_platform_login(
                    f.key.tenant,
                    challenge.id,
                    challenge.nonce.clone(),
                    BROWSER.into(),
                    signature.clone(),
                    deadline()
                )
                .await
                .map(|outcome| outcome.session)
                .is_err()
        );
    }
    *verifier.idp.lock().unwrap() = Some((provider.id, claims));
    let platform = store
        .complete_platform_login(
            f.key.tenant,
            challenge.id,
            challenge.nonce,
            BROWSER.into(),
            signature,
            deadline(),
        )
        .await
        .map(|outcome| outcome.session)?;
    let actor = proof(&store, &f, &platform).await?;
    assert_eq!(
        personnel_session(&store, &f.actor().await?, platform.view().id.as_uuid()).await?,
        Some((true, Some(verifier.binding.binding_id.to_string())))
    );
    let current = store.current_profile(&actor, deadline()).await?;
    assert_eq!(
        current.view()?.source,
        Some(ProfileSource::Idp {
            provider: provider.id
        })
    );
    assert_eq!(
        current
            .view()?
            .profile
            .as_ref()
            .unwrap()
            .display_name
            .value()
            .map(String::as_str),
        Some("fresh-platform")
    );
    assert!(actor.assurance()?.auth_time().is_none());
    let reference = actor.reference()?;
    f.policy.allow(account);
    assert!(
        store
            .list_sessions(proof(&store, &f, &platform).await?, None, 100, deadline())
            .await?
            .sessions
            .iter()
            .any(|v| v.id == platform.view().id)
    );
    // The host owns association withdrawal. Remove the original OIDC session first,
    // preserving the platform session so the shared loader must detect the missing link.
    sqlx::query("DELETE FROM identity_authority.sessions WHERE session_id=$1")
        .bind(login.view().id.as_uuid())
        .execute(&f.owner)
        .await?;
    let external: serde_json::Value = sqlx::query_scalar(
        "SELECT to_jsonb(e) FROM identity_authority.external_identities e WHERE identity_id=$1",
    )
    .bind(identity)
    .fetch_one(&f.owner)
    .await?;
    let unlinked = store
        .begin_platform_login(
            f.key.tenant,
            verifier.binding.binding_id,
            PlatformPurpose::BrowserLogin,
            BROWSER.into(),
            source(),
            deadline(),
        )
        .await?;
    let signature = verifier
        .key
        .sign(&unlinked.signing_payload)
        .as_ref()
        .to_vec();
    sqlx::query("DELETE FROM identity_authority.external_identities WHERE identity_id=$1")
        .bind(identity)
        .execute(&f.owner)
        .await?;
    assert!(
        store
            .complete_platform_login(
                f.key.tenant,
                unlinked.id,
                unlinked.nonce,
                BROWSER.into(),
                signature,
                deadline()
            )
            .await
            .map(|outcome| outcome.session)
            .is_err()
    );
    assert!(
        personnel_session(&store, &f.actor().await?, platform.view().id.as_uuid())
            .await?
            .is_none()
    );
    assert!(proof(&store, &f, &platform).await.is_err());
    assert!(
        store
            .recheck_session_reference(f.key.tenant, &reference, deadline())
            .await
            .is_err()
    );
    assert!(
        store
            .list_sessions(actor, None, 100, deadline())
            .await
            .is_err()
    );
    sqlx::query("INSERT INTO identity_authority.external_identities SELECT * FROM jsonb_populate_record(NULL::identity_authority.external_identities,$1)").bind(external).execute(&f.owner).await?;
    let actor = proof(&store, &f, &platform).await?;
    let pending = store
        .begin_platform_login(
            f.key.tenant,
            verifier.binding.binding_id,
            PlatformPurpose::BrowserLogin,
            BROWSER.into(),
            source(),
            deadline(),
        )
        .await?;
    let signature = verifier
        .key
        .sign(&pending.signing_payload)
        .as_ref()
        .to_vec();
    // Provider withdrawal invalidates issuance and every existing session consumer.
    oidc.enable_provider(
        f.actor().await?,
        provider.id,
        provider.version,
        false,
        deadline(),
    )
    .await?;
    assert!(
        store
            .complete_platform_login(
                f.key.tenant,
                pending.id,
                pending.nonce,
                BROWSER.into(),
                signature,
                deadline()
            )
            .await
            .map(|outcome| outcome.session)
            .is_err()
    );
    assert!(proof(&store, &f, &platform).await.is_err());
    assert!(
        store
            .refresh_session(f.key.tenant, secret(&platform), deadline())
            .await
            .is_err()
    );
    assert!(
        store
            .recheck_session_reference(f.key.tenant, &reference, deadline())
            .await
            .is_err()
    );
    assert!(
        store
            .read_local_profile(&actor, account, deadline())
            .await
            .is_err()
    );
    assert!(
        store
            .list_sessions(actor, None, 100, deadline())
            .await
            .is_err()
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn source_admission_borrows_transaction_with_no_credential_privileges() -> anyhow::Result<()>
{
    use federation_support::*;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let federation = service(&f, ScriptedOidc::new());
    let provider = enabled(&f, &federation).await?;
    let role = format!("profile_reader_{}", Uuid::new_v4().simple());
    let actor = f.actor().await?;
    let mut owner = f.owner.acquire().await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE ROLE {role} NOLOGIN")))
        .execute(&mut *owner)
        .await?;
    grant_profile_source_admission(&mut owner, &role).await?;
    assert!(
        admit_profile_source_on(
            &mut owner,
            f.instance,
            f.key.tenant,
            ProfileSource::IdentityLocal
        )
        .await
        .is_err()
    );
    use sqlx::Connection;
    let mut stale = owner.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *stale)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(f.key.tenant.to_string())
        .execute(&mut *stale)
        .await?;
    assert!(
        admit_profile_source_on(
            &mut stale,
            f.instance,
            f.key.tenant,
            ProfileSource::IdentityLocal
        )
        .await
        .is_err()
    );
    stale.rollback().await?;

    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "GRANT identity_runtime TO {role} WITH INHERIT FALSE, SET TRUE"
    )))
    .execute(&mut *owner)
    .await?;
    let mut unsafe_tx = owner.begin().await?;
    sqlx::query("SELECT set_config('role',$1,true)")
        .bind(&role)
        .execute(&mut *unsafe_tx)
        .await?;
    assert!(
        verify_profile_source_admission(&mut unsafe_tx, f.instance)
            .await
            .is_err()
    );
    unsafe_tx.rollback().await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "REVOKE identity_runtime FROM {role}"
    )))
    .execute(&mut *owner)
    .await?;

    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('role',$1,true)")
        .bind(&role)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(f.key.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    verify_profile_source_admission(&mut tx, f.instance).await?;
    assert!(
        admit_profile_source_on(
            &mut tx,
            f.instance,
            rss_request_context::TenantId::parse(B)?,
            ProfileSource::IdentityLocal
        )
        .await
        .is_err()
    );
    let source = ProfileSource::Idp {
        provider: provider.id,
    };
    let view = admit_profile_source_on(&mut tx, f.instance, f.key.tenant, source).await?;
    assert_eq!(view.provider_config_version, Some(provider.version));
    assert_eq!(view.max_age_seconds, 14400);
    // No second connection can change provider configuration until the host settles its write.
    let mut disable = Box::pin(federation.enable_provider(
        actor,
        provider.id,
        provider.version,
        false,
        deadline(),
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut disable)
            .await
            .is_err()
    );
    tx.rollback().await?;
    disable.await?;
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('role',$1,true)")
        .bind(&role)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(f.key.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    assert!(
        admit_profile_source_on(&mut tx, f.instance, f.key.tenant, source)
            .await
            .is_err()
    );
    assert_eq!(
        admit_profile_source_on(
            &mut tx,
            f.instance,
            f.key.tenant,
            ProfileSource::IdentityLocal
        )
        .await?
        .source,
        ProfileSource::IdentityLocal
    );
    tx.rollback().await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP OWNED BY {role}; DROP ROLE {role}"
    )))
    .execute(&mut *owner)
    .await?;
    drop(owner);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn malformed_extension_replaces_old_values_without_rejecting_login() -> anyhow::Result<()> {
    use federation_support::*;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let upstream = ScriptedOidc::new();
    *upstream.profile.lock().unwrap() = Some(local("before").observation()?);
    let service = service(&f, upstream.clone());
    let provider = enabled(&f, &service).await?;
    let first = issued(
        finish(
            &service,
            begin(&f, &service, &provider).await?,
            "nul-profile",
        )
        .await?,
    );
    let old = proof(&f.store, &f, &first).await?;
    let invalid = Profile::from_claims(
        json!({"name":"valid name","attributes":{"nested":["\u{0}"]}})
            .as_object()
            .unwrap(),
        &ProfileSettings {
            extensions_claim: Some("attributes".into()),
            max_age_seconds: 60,
        },
    );
    *upstream.profile.lock().unwrap() = Some(invalid);
    let next = issued(
        finish(
            &service,
            begin(&f, &service, &provider).await?,
            "nul-profile",
        )
        .await?,
    );
    let current = f
        .store
        .current_profile(&proof(&f.store, &f, &next).await?, deadline())
        .await?;
    assert_eq!(current.view()?.status, ProfileStatus::Available);
    assert!(matches!(
        current.view()?.profile.as_ref().unwrap().extensions,
        Attribute::Invalid
    ));
    assert_eq!(
        current
            .view()?
            .profile
            .as_ref()
            .unwrap()
            .display_name
            .value()
            .map(String::as_str),
        Some("valid name")
    );
    assert_eq!(
        f.store
            .current_profile(&old, deadline())
            .await?
            .view()?
            .status,
        ProfileStatus::Unavailable
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn latest_source_discovery_is_target_bound_and_policy_checked() -> anyhow::Result<()> {
    use federation_support::*;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let local = f.login().await?;
    let manager = proof(&f.store, &f, &local).await?;
    let oidc = service(&f, ScriptedOidc::new());
    let provider = enabled(&f, &oidc).await?;
    let federated =
        issued(finish(&oidc, begin(&f, &oidc, &provider).await?, "source-target").await?);
    let target = proof(&f.store, &f, &federated).await?.account();
    let page = f
        .store
        .latest_profile_sources(&manager, target, None, deadline())
        .await?;
    assert_eq!(
        page.sources,
        vec![ProfileSource::Idp {
            provider: provider.id
        }]
    );
    assert!(page.next_cursor.is_none());
    assert!(
        f.store
            .latest_profile_sources(&manager, target, page.sources.last().copied(), deadline())
            .await?
            .sources
            .is_empty()
    );
    assert_eq!(
        f.store
            .latest_profile_sources(&manager, f.key, None, deadline())
            .await?
            .sources,
        vec![ProfileSource::IdentityLocal]
    );
    let peer = rss_identity_core::account::AccountKey {
        tenant: rss_request_context::TenantId::parse(B)?,
        principal: target.principal,
    };
    assert!(
        f.store
            .latest_profile_sources(&manager, peer, None, deadline())
            .await
            .is_err()
    );
    f.policy.revoke(f.key);
    assert!(
        f.store
            .latest_profile_sources(&manager, target, None, deadline())
            .await
            .is_err()
    );
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn platform_evidence_admission_preserves_authentication_time() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let (store, verifier) = platform_host(&f, true).await?;
    let browser = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    for (possession, verification, offset) in [
        (false, false, None),
        (true, false, Some(0)),
        (true, true, Some(-120)),
        (true, true, Some(120)),
        (true, true, Some(0)),
    ] {
        let challenge = store
            .begin_platform_login(
                f.key.tenant,
                verifier.binding.binding_id,
                PlatformPurpose::BrowserLogin,
                browser.into(),
                source(),
                deadline(),
            )
            .await?;
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&f.owner)
                .await?;
        let auth_time = offset.map(|offset| now + offset);
        *verifier.evidence.lock().unwrap() = (possession, verification, auth_time);
        let counts = async {
            sqlx::query_as::<_,(i64,i64,i64)>("SELECT (SELECT count(*) FROM identity_authority.sessions),(SELECT count(*) FROM identity_authority.profile_observations),(SELECT count(*) FROM rss_transactional_messaging.outbox)").fetch_one(&f.owner).await
        };
        let before = counts.await?;
        let signature = verifier
            .key
            .sign(&challenge.signing_payload)
            .as_ref()
            .to_vec();
        let result = store
            .complete_platform_login(
                f.key.tenant,
                challenge.id,
                challenge.nonce,
                browser.into(),
                signature,
                deadline(),
            )
            .await
            .map(|outcome| outcome.session);
        if possession && verification && offset == Some(0) {
            let issued = result?;
            let actor = proof(&store, &f, &issued).await?;
            assert_eq!(actor.assurance()?.auth_time(), auth_time);
            assert_eq!(actor.assurance()?.acr(), Acr::Unspecified);
            assert_eq!(
                actor.authentication_source()?,
                AuthenticationSource::Platform
            );
        } else {
            assert!(matches!(result, Err(AuthorityError::Rejected)));
            let after=sqlx::query_as::<_,(i64,i64,i64)>("SELECT (SELECT count(*) FROM identity_authority.sessions),(SELECT count(*) FROM identity_authority.profile_observations),(SELECT count(*) FROM rss_transactional_messaging.outbox)").fetch_one(&f.owner).await?;
            assert_eq!(before, after);
        }
    }
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn local_profile_receipt_capacity_preserves_replay() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let issued = f.login().await?;
    // Fill only the receipt resource, preserving normal account/session preparation.
    sqlx::query("INSERT INTO identity_authority.profile_operations(tenant_id,operation_id,principal_id,actor,digest,revision) SELECT $1::uuid,gen_random_uuid(),$2,$2,decode(repeat('00',32),'hex'),n FROM generate_series(1,4095) n")
        .bind(f.key.tenant.to_string()).bind(f.key.principal.as_uuid()).execute(&f.owner).await?;
    let change = ProfileChange {
        operation_id: Uuid::new_v4(),
        expected_revision: 0,
        value: Some(local("last")),
    };
    let receipt = f
        .store
        .update_local_profile(
            proof(&f.store, &f, &issued).await?,
            f.key,
            change.clone(),
            deadline(),
        )
        .await?;
    assert_eq!(receipt.revision, 1);
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox")
        .fetch_one(&f.owner)
        .await?;
    let result = f
        .store
        .update_local_profile(
            proof(&f.store, &f, &issued).await?,
            f.key,
            ProfileChange {
                operation_id: Uuid::new_v4(),
                expected_revision: 1,
                value: None,
            },
            deadline(),
        )
        .await;
    assert!(matches!(result, Err(AuthorityError::Rejected)));
    let actor = proof(&f.store, &f, &issued).await?;
    let current = f
        .store
        .read_local_profile(&actor, f.key, deadline())
        .await?;
    assert_eq!(current.revision, 1);
    assert!(current.value.is_some());
    assert_eq!(
        f.store
            .local_profile_receipt(&actor, f.key, change.operation_id, deadline())
            .await?
            .unwrap()
            .revision,
        1
    );
    assert_eq!(
        f.store
            .update_local_profile(
                proof(&f.store, &f, &issued).await?,
                f.key,
                change,
                deadline()
            )
            .await?
            .revision,
        1
    );
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox")
        .fetch_one(&f.owner)
        .await?;
    assert_eq!(before, after);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity_authority.profile_operations")
            .fetch_one(&f.owner)
            .await?;
    assert_eq!(count, 4096);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn personnel_query_is_scoped_readonly_and_revision_bound() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let actor = f.actor().await?;
    let (before, count)=f.store.with_personnel_read(&actor,deadline(),|mut read|Box::pin(async move {
        let revision=read.revision()?;
        let rows=read.query("SELECT count(DISTINCT principal_id)::bigint AS count FROM identity_personnel",Default::default(),1).await?;
        Ok((revision,rows[0].get::<i64,_>("count")))
    })).await?;
    assert!(count > 0);
    assert!(before.logins);
    assert_eq!(before.profiles, PersonnelProfileScope::All);
    f.store
        .update_local_profile(
            f.actor().await?,
            f.key,
            ProfileChange {
                operation_id: Uuid::new_v4(),
                expected_revision: 0,
                value: Some(local("Personnel")),
            },
            deadline(),
        )
        .await?;
    let login = f.login().await?;
    let actor = proof(&f.store, &f, &login).await?;
    let expected = f.key.principal.as_uuid();
    let after=f.store.with_personnel_read(&actor,deadline(),move |mut read|Box::pin(async move {
        use sqlx::Arguments;
        let mut args=sqlx::postgres::PgArguments::default();args.add(expected).map_err(|_|AuthorityError::Configuration)?;
        let rows=read.query("SELECT display_name FROM identity_personnel WHERE principal_id=$1 AND source='local'",args,1).await?;
        assert_eq!(rows[0].get::<Option<String>,_>("display_name").as_deref(),Some("Personnel"));
        read.revision()
    })).await?;
    assert!(after.generation > before.generation);
    assert_eq!(
        personnel_session(&f.store, &actor, login.view().id.as_uuid()).await?,
        Some((false, None))
    );
    let other = f
        .store
        .create_local_account(
            f.actor().await?,
            support::login("other-person"),
            password(),
            deadline(),
        )
        .await?;
    let _other_session = f
        .store
        .login_local(
            f.key.tenant,
            support::login("other-person"),
            password(),
            source(),
            None,
            deadline(),
        )
        .await?;
    let own_store = Authority::connect_runtime(
        f.runtime.clone(),
        Arc::new(rss_identity_core::account::PasswordKdf::new()),
        f.config(),
        Arc::new(SelfProfiles),
        deadline(),
    )
    .await?;
    let own_id = f.key.principal.as_uuid();
    own_store.with_personnel_read(&actor,deadline(),move |mut read|Box::pin(async move {
        use sqlx::Arguments;
        assert_eq!(read.revision()?.profiles,PersonnelProfileScope::SelfOnly);
        let mut args=sqlx::postgres::PgArguments::default();args.add(own_id).map_err(|_|AuthorityError::Configuration)?;
        let rows=read.query("SELECT count(*)::bigint AS rows,count(source)::bigint AS sources FROM identity_personnel WHERE principal_id<>$1",args,1).await?;
        assert_eq!(rows[0].get::<i64,_>("sources"),0);
        assert_eq!(rows[0].get::<i64,_>("rows"),1);
        Ok(())
    })).await?;
    let _ = other;
    // A side-effecting SELECT is rejected by PostgreSQL READ ONLY, even though host code installed it.
    sqlx::raw_sql("CREATE FUNCTION public.personnel_write() RETURNS bigint LANGUAGE sql AS 'UPDATE identity_authority.guard SET personnel_revision=personnel_revision+1 RETURNING personnel_revision'").execute(&f.owner).await?;
    assert!(
        f.store
            .with_personnel_read(&actor, deadline(), |mut read| Box::pin(async move {
                read.query("SELECT public.personnel_write()", Default::default(), 1)
                    .await
                    .map(|_| ())
            }))
            .await
            .is_err()
    );
    f.policy.revoke(f.key);
    f.store.with_personnel_read(&actor,deadline(),|mut read|Box::pin(async move {
        assert!(!read.revision()?.logins);
        assert_eq!(read.revision()?.profiles,PersonnelProfileScope::None);
        let rows=read.query("SELECT count(*)::bigint AS leaked FROM identity_personnel WHERE login IS NOT NULL OR display_name IS NOT NULL OR username IS NOT NULL OR source IS NOT NULL",Default::default(),1).await?;
        assert_eq!(rows[0].get::<i64,_>("leaked"),0);
        Ok(())
    })).await?;
    f.policy.allow(f.key);
    // A relation row expiring before the actor also closes the borrowed context.
    sqlx::query("UPDATE identity_authority.profile_observations SET observed_at=floor(extract(epoch FROM clock_timestamp()))::bigint-30,expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint+1 WHERE tenant_id=$1::uuid").bind(f.key.tenant.to_string()).execute(&f.owner).await?;
    assert!(
        f.store
            .with_personnel_read(&actor, deadline(), |mut read| Box::pin(async move {
                tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
                read.query(
                    "SELECT principal_id FROM identity_personnel",
                    Default::default(),
                    100,
                )
                .await
                .map(|_| ())
            }))
            .await
            .is_err()
    );
    f.store
        .revoke_current_session(proof(&f.store, &f, &login).await?, deadline())
        .await?;
    assert!(
        f.store
            .with_personnel_read(&actor, deadline(), |_| Box::pin(async { Ok(()) }))
            .await
            .is_err()
    );
    assert!(
        personnel_session(&f.store, &f.actor().await?, login.view().id.as_uuid())
            .await?
            .is_none()
    );
    f.close().await;
    Ok(())
}

async fn personnel_session(
    store: &Authority,
    actor: &AuthenticatedSession,
    id: Uuid,
) -> anyhow::Result<Option<(bool, Option<String>)>> {
    Ok(store.with_personnel_read(actor,deadline(),move |mut read|Box::pin(async move {
        use sqlx::Arguments;
        let mut args=sqlx::postgres::PgArguments::default(); args.add(id).map_err(|_|AuthorityError::Configuration)?;
        let rows=read.query("SELECT requires_platform_check,platform_binding_id FROM identity_session_references WHERE session_id=$1",args,1).await?;
        Ok(rows.first().map(|row|(row.get("requires_platform_check"),row.get("platform_binding_id"))))
    })).await?)
}
struct SelfProfiles;
impl ManagementPolicy for SelfProfiles {
    fn authorize<'a>(
        &'a self,
        context: &'a ManagementContext<'a>,
        _: &'a mut sqlx::PgConnection,
    ) -> futures::future::BoxFuture<'a, Result<ReauthenticationRequirement, ManagementDenied>> {
        Box::pin(async move {
            if context.operation() == ManagementOperation::ReadLatestProfile
                && context.target() == Some(context.actor())
            {
                Ok(ReauthenticationRequirement::None)
            } else {
                Err(ManagementDenied)
            }
        })
    }
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn trusted_reference_join_preserves_host_only_scope_and_expiry() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let issued = f.login().await?;
    let actor = proof(&f.store, &f, &issued).await?;
    let reference = serde_json::to_value(actor.reference()?)?;
    // The host can retain a locator without possessing a management-capable actor.
    f.policy.revoke(f.key);
    let (before, valid) = trusted_reference(&f.store, f.key.tenant, reference.clone()).await?;
    assert!(valid);
    let mut wrong = reference.clone();
    wrong["principal"] = json!(Uuid::new_v4());
    assert!(!trusted_reference(&f.store, f.key.tenant, wrong).await?.1);
    assert!(
        f.store
            .with_session_references_read(f.key.tenant, deadline(), |mut read| Box::pin(
                async move {
                    read.query(
                        "SELECT login FROM identity_personnel",
                        Default::default(),
                        1,
                    )
                    .await
                    .map(|_| ())
                }
            ))
            .await
            .is_err()
    );
    sqlx::raw_sql("CREATE FUNCTION public.reference_write() RETURNS bigint LANGUAGE sql AS 'UPDATE identity_authority.guard SET personnel_revision=personnel_revision+1 RETURNING personnel_revision'").execute(&f.owner).await?;
    assert!(
        f.store
            .with_session_references_read(f.key.tenant, deadline(), |mut read| Box::pin(
                async move {
                    read.query("SELECT public.reference_write()", Default::default(), 1)
                        .await
                        .map(|_| ())
                }
            ))
            .await
            .is_err()
    );
    let other = rss_request_context::TenantId::parse(&Uuid::new_v4().to_string())?;
    assert!(
        f.store
            .with_session_references_read(other, deadline(), |_| Box::pin(async { Ok(()) }))
            .await
            .is_err()
    );
    assert!(
        f.store
            .with_session_references_read(f.key.tenant, deadline(), |mut read| Box::pin(
                async move {
                    read.query(
                        "SELECT n FROM generate_series(1,2) n",
                        Default::default(),
                        1,
                    )
                    .await
                    .map(|_| ())
                }
            ))
            .await
            .is_err()
    );
    // Session-only reads do not take profile expiry into their relation lifetime.
    f.policy.allow(f.key);
    f.store
        .update_local_profile(
            f.actor().await?,
            f.key,
            ProfileChange {
                operation_id: Uuid::new_v4(),
                expected_revision: 0,
                value: Some(local("Profile")),
            },
            deadline(),
        )
        .await?;
    let _fresh_profile = f.login().await?;
    let changed = sqlx::query("UPDATE identity_authority.profile_observations SET expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint+1 WHERE tenant_id=$1::uuid")
        .bind(f.key.tenant.to_string()).execute(&f.owner).await?;
    assert!(changed.rows_affected() > 0);
    f.store
        .with_session_references_read(f.key.tenant, deadline(), |read| {
            Box::pin(async move {
                tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
                read.revision().map(|_| ())
            })
        })
        .await?;
    sqlx::query("UPDATE identity_authority.sessions SET idle_expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint+1 WHERE tenant_id=$1::uuid AND session_id=$2")
        .bind(f.key.tenant.to_string()).bind(issued.view().id.as_uuid()).execute(&f.owner).await?;
    assert!(
        f.store
            .with_session_references_read(f.key.tenant, deadline(), |read| Box::pin(async move {
                tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
                read.revision().map(|_| ())
            }))
            .await
            .is_err()
    );
    let (after, valid) = trusted_reference(&f.store, f.key.tenant, reference).await?;
    assert!(!valid);
    assert!(after.generation > before.generation);
    f.close().await;
    Ok(())
}

async fn trusted_reference(
    store: &Authority,
    tenant: rss_request_context::TenantId,
    reference: serde_json::Value,
) -> Result<(PersonnelRevision, bool), AuthorityError> {
    store.with_session_references_read(tenant, deadline(), move |mut read| Box::pin(async move {
            use sqlx::Arguments;
            let revision = read.revision()?;
            assert!(!revision.logins);
            assert_eq!(revision.profiles, PersonnelProfileScope::None);
            let mut args = sqlx::postgres::PgArguments::default();
            args.add(reference).map_err(|_| AuthorityError::Configuration)?;
            let rows = read.query("SELECT EXISTS(SELECT FROM identity_session_references s WHERE s.instance_id=($1->>'instance')::uuid AND s.tenant_id=($1->>'tenant')::uuid AND s.principal_id=($1->>'principal')::uuid AND s.session_id=($1->>'session')::uuid AND s.credential_kind=$1->>'credentialKind') AS valid", args, 1).await?;
            Ok((revision, rows[0].get("valid")))
    })).await
}

async fn subject_transaction<'a>(
    c: &'a mut sqlx::PgConnection,
    role: &str,
    tenant: rss_request_context::TenantId,
) -> anyhow::Result<sqlx::Transaction<'a, sqlx::Postgres>> {
    use sqlx::Connection;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('role',$1,true),set_config('rss.tenant_id',$2,true)")
        .bind(role)
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn platform_subject_admission_fences_native_settlement() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let role = format!("subject_reader_{}", Uuid::new_v4().simple());
    let mut owner = f.owner.acquire().await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE ROLE {role} NOLOGIN")))
        .execute(&mut *owner)
        .await?;
    grant_platform_subject_admission(&mut owner, &role).await?;
    let binding = PlatformBinding {
        instance: f.instance,
        account: f.key,
        binding_id: Uuid::new_v4(),
        binding_epoch: 1,
        source_id: Uuid::new_v4(),
        source_version: 1,
        external_identity: None,
    };
    assert!(
        admit_platform_subject_on(&mut owner, f.instance, &binding, None)
            .await
            .is_err()
    );
    let mut tx = subject_transaction(&mut owner, &role, f.key.tenant).await?;
    verify_platform_subject_admission(&mut tx, f.instance).await?;
    assert!(
        verify_profile_source_admission(&mut tx, f.instance)
            .await
            .is_err()
    );
    let version = admit_platform_subject_on(&mut tx, f.instance, &binding, None).await?;
    let mut wrong = binding.clone();
    wrong.account.tenant = rss_request_context::TenantId::parse(B)?;
    assert!(
        admit_platform_subject_on(&mut tx, f.instance, &wrong, None)
            .await
            .is_err()
    );
    wrong = binding.clone();
    wrong.source_id = Uuid::nil();
    assert!(
        admit_platform_subject_on(&mut tx, f.instance, &wrong, None)
            .await
            .is_err()
    );
    // A real account writer must wait until the host has committed its native issuance.
    let mut writer = f.owner.begin().await?;
    let mut guard = Box::pin(
        sqlx::query(
            "SELECT tenant_id FROM identity_authority.guard WHERE tenant_id=$1::uuid FOR UPDATE",
        )
        .bind(f.key.tenant.to_string())
        .execute(&mut *writer),
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut guard)
            .await
            .is_err()
    );
    tx.commit().await?;
    guard.await?;
    sqlx::query("UPDATE identity_authority.accounts SET enabled=false,auth_epoch=auth_epoch+1 WHERE tenant_id=$1::uuid AND principal_id=$2")
        .bind(f.key.tenant.to_string()).bind(f.key.principal.as_uuid()).execute(&mut *writer).await?;
    writer.commit().await?;
    let mut tx = subject_transaction(&mut owner, &role, f.key.tenant).await?;
    assert!(
        admit_platform_subject_on(&mut tx, f.instance, &binding, Some(version))
            .await
            .is_err()
    );
    tx.rollback().await?;
    sqlx::query("UPDATE identity_authority.accounts SET enabled=true,auth_epoch=auth_epoch+1 WHERE tenant_id=$1::uuid AND principal_id=$2")
        .bind(f.key.tenant.to_string()).bind(f.key.principal.as_uuid()).execute(&mut *owner).await?;
    let mut tx = subject_transaction(&mut owner, &role, f.key.tenant).await?;
    assert!(
        admit_platform_subject_on(&mut tx, f.instance, &binding, Some(version))
            .await
            .is_err()
    );
    let renewed = admit_platform_subject_on(&mut tx, f.instance, &binding, None).await?;
    assert_ne!(version, renewed);
    tx.rollback().await?;
    sqlx::query("UPDATE identity_authority.memberships SET active=false,epoch=epoch+1 WHERE tenant_id=$1::uuid AND principal_id=$2")
        .bind(f.key.tenant.to_string()).bind(f.key.principal.as_uuid()).execute(&mut *owner).await?;
    let mut tx = subject_transaction(&mut owner, &role, f.key.tenant).await?;
    assert!(
        admit_platform_subject_on(&mut tx, f.instance, &binding, None)
            .await
            .is_err()
    );
    tx.rollback().await?;
    sqlx::query("UPDATE identity_authority.memberships SET active=true,epoch=epoch+1 WHERE tenant_id=$1::uuid AND principal_id=$2")
        .bind(f.key.tenant.to_string()).bind(f.key.principal.as_uuid()).execute(&mut *owner).await?;
    let mut tx = subject_transaction(&mut owner, &role, f.key.tenant).await?;
    assert!(
        admit_platform_subject_on(&mut tx, f.instance, &binding, Some(renewed))
            .await
            .is_err()
    );
    admit_platform_subject_on(&mut tx, f.instance, &binding, None).await?;
    tx.rollback().await?;
    // A reachable broad role must invalidate startup even when it is NOINHERIT.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "GRANT identity_runtime TO {role} WITH INHERIT FALSE, SET TRUE"
    )))
    .execute(&mut *owner)
    .await?;
    let mut tx = subject_transaction(&mut owner, &role, f.key.tenant).await?;
    assert!(
        verify_platform_subject_admission(&mut tx, f.instance)
            .await
            .is_err()
    );
    tx.rollback().await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP OWNED BY {role}; DROP ROLE {role}"
    )))
    .execute(&mut *owner)
    .await?;
    drop(owner);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn platform_subject_admission_requires_current_external_identity() -> anyhow::Result<()> {
    use federation_support::*;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let oidc = service(&f, ScriptedOidc::new());
    let provider = enabled(&f, &oidc).await?;
    let login = issued(finish(&oidc, begin(&f, &oidc, &provider).await?, "native-user").await?);
    let account = proof(&f.store, &f, &login).await?.account();
    let identity: Uuid = sqlx::query_scalar(
        "SELECT identity_id FROM identity_authority.external_identities WHERE principal_id=$1",
    )
    .bind(account.principal.as_uuid())
    .fetch_one(&f.owner)
    .await?;
    let role = format!("native_reader_{}", Uuid::new_v4().simple());
    let mut owner = f.owner.acquire().await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE ROLE {role} NOLOGIN")))
        .execute(&mut *owner)
        .await?;
    grant_platform_subject_admission(&mut owner, &role).await?;
    let binding = PlatformBinding {
        instance: f.instance,
        account,
        binding_id: Uuid::new_v4(),
        binding_epoch: 1,
        source_id: Uuid::new_v4(),
        source_version: 1,
        external_identity: Some(ExternalBinding {
            identity_id: identity,
            provider: provider.id,
            config_version: provider.version,
            revocation_epoch: provider.revocation_epoch,
        }),
    };
    let mut tx = subject_transaction(&mut owner, &role, account.tenant).await?;
    verify_platform_subject_admission(&mut tx, f.instance).await?;
    let version = admit_platform_subject_on(&mut tx, f.instance, &binding, None).await?;
    let mut wrong = binding.clone();
    wrong.account = f.key;
    assert!(
        admit_platform_subject_on(&mut tx, f.instance, &wrong, None)
            .await
            .is_err()
    );
    wrong = binding.clone();
    wrong.external_identity.as_mut().unwrap().config_version += 1;
    assert!(
        admit_platform_subject_on(&mut tx, f.instance, &wrong, None)
            .await
            .is_err()
    );
    wrong = binding.clone();
    wrong.external_identity.as_mut().unwrap().revocation_epoch += 1;
    assert!(
        admit_platform_subject_on(&mut tx, f.instance, &wrong, None)
            .await
            .is_err()
    );
    tx.rollback().await?;
    use sqlx::Connection;
    let mut tx = owner.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('role',$1,true),set_config('rss.tenant_id',$2,true)")
        .bind(&role)
        .bind(account.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    assert!(
        admit_platform_subject_on(&mut tx, f.instance, &binding, None)
            .await
            .is_err()
    );
    tx.rollback().await?;
    let actor = f.actor().await?;
    let mut tx = subject_transaction(&mut owner, &role, account.tenant).await?;
    admit_platform_subject_on(&mut tx, f.instance, &binding, Some(version)).await?;
    let mut revoke = Box::pin(
        f.store
            .set_account_membership(actor, account, false, deadline()),
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut revoke)
            .await
            .is_err()
    );
    tx.rollback().await?;
    revoke.await?;
    let mut tx = subject_transaction(&mut owner, &role, account.tenant).await?;
    assert!(
        admit_platform_subject_on(&mut tx, f.instance, &binding, Some(version))
            .await
            .is_err()
    );
    tx.rollback().await?;
    f.store
        .set_account_membership(f.actor().await?, account, true, deadline())
        .await?;
    oidc.enable_provider(
        f.actor().await?,
        provider.id,
        provider.version,
        false,
        deadline(),
    )
    .await?;
    let mut tx = subject_transaction(&mut owner, &role, account.tenant).await?;
    assert!(
        admit_platform_subject_on(&mut tx, f.instance, &binding, None)
            .await
            .is_err()
    );
    tx.rollback().await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP OWNED BY {role}; DROP ROLE {role}"
    )))
    .execute(&mut *owner)
    .await?;
    drop(owner);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires make test-pg"]
async fn live_session_admission_retains_platform_source_locks() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let (store, verifier) = platform_host(&f, false).await?;
    let browser = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let challenge = store
        .begin_platform_login(
            f.key.tenant,
            verifier.binding.binding_id,
            PlatformPurpose::BrowserLogin,
            browser.into(),
            source(),
            deadline(),
        )
        .await?;
    let signature = verifier
        .key
        .sign(&challenge.signing_payload)
        .as_ref()
        .to_vec();
    let issued = store
        .complete_platform_login(
            f.key.tenant,
            challenge.id,
            challenge.nonce,
            browser.into(),
            signature,
            deadline(),
        )
        .await?
        .session;
    let actor = proof(&store, &f, &issued).await?;
    let mut tx = f.owner.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(A)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL ROLE identity_runtime")
        .execute(&mut *tx)
        .await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await?;
    recheck_authenticated_session_on(&mut tx, &actor).await?;
    assert_eq!(
        verifier
            .last_backend
            .load(std::sync::atomic::Ordering::SeqCst),
        pid
    );
    let pool = f.owner.clone();
    let revoke = tokio::spawn(async move {
        sqlx::query("UPDATE public.platform_binding SET enabled=false,epoch=epoch+1")
            .execute(&pool)
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%UPDATE public.platform_binding%')").bind(pid).fetch_one(&f.owner).await?;
            if blocked { return Ok::<_,anyhow::Error>(()); }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await??;
    tx.rollback().await?;
    revoke.await??;
    let mut tx = f.owner.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(A)
        .execute(&mut *tx)
        .await?;
    assert!(
        recheck_authenticated_session_on(&mut tx, &actor)
            .await
            .is_err()
    );
    tx.rollback().await?;
    sqlx::query("UPDATE public.platform_binding SET enabled=true,epoch=1")
        .execute(&f.owner)
        .await?;
    verifier
        .unavailable
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut tx = f.owner.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(A)
        .execute(&mut *tx)
        .await?;
    assert!(
        recheck_authenticated_session_on(&mut tx, &actor)
            .await
            .is_err()
    );
    tx.rollback().await?;
    verifier
        .unavailable
        .store(false, std::sync::atomic::Ordering::SeqCst);
    for change in [
        "UPDATE public.platform_binding SET epoch=epoch+1",
        "UPDATE identity_authority.sessions SET platform_authentication=jsonb_set(platform_authentication,'{binding,sourceVersion}','99') WHERE authentication_source='platform'",
    ] {
        let mut tx = f.owner.begin().await?;
        sqlx::query(sqlx::AssertSqlSafe(change))
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(A)
            .execute(&mut *tx)
            .await?;
        assert!(
            recheck_authenticated_session_on(&mut tx, &actor)
                .await
                .is_err()
        );
        tx.rollback().await?;
    }
    f.close().await;
    Ok(())
}
