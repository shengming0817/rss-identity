//! Trusted host platform adapter and Identity-owned one-use browser challenges.
//! The host verifies devices and platform cryptography; Identity alone issues sessions.
//! ref: webauthn-rs 0.5.3 src/lib.rs (server-owned, one-use ceremony state).
use crate::{
    storage::*,
    transaction::{corrupt, reject},
    *,
};
use futures::future::BoxFuture;
use rss_identity_core::{
    assurance::{Acr, Assurance},
    federation::{ProviderId, UpstreamClaims, digest, random_secret},
    session::CredentialKind,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlatformBinding {
    #[serde(with = "instance_codec")]
    pub instance: rss_identity_core::InstanceId,
    #[serde(with = "account_codec")]
    pub account: AccountKey,
    pub binding_id: Uuid,
    pub binding_epoch: i64,
    pub source_id: Uuid,
    pub source_version: i64,
    pub external_identity: Option<ExternalBinding>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalBinding {
    pub identity_id: Uuid,
    pub provider: ProviderId,
    pub config_version: i64,
    pub revocation_epoch: i64,
}
impl PlatformBinding {
    fn valid(&self) -> bool {
        !self.binding_id.is_nil()
            && self.binding_epoch > 0
            && !self.source_id.is_nil()
            && self.source_version > 0
            && self.external_identity.as_ref().is_none_or(|v| {
                !v.identity_id.is_nil() && v.config_version > 0 && v.revocation_epoch > 0
            })
    }
}
/// Only supplied to the verifier installed by trusted composition, never accepted from HTTP JSON.
pub struct PlatformChallengeContext {
    pub binding: PlatformBinding,
    pub audience: String,
    pub nonce: String,
    pub created_at: i64,
    pub expires_at: i64,
}
/// Intermediate adapter output, not a transferable proof or session-issuance input.
pub struct PlatformEvidence {
    pub key_possession: bool,
    pub hardware_key: bool,
    pub user_presence: bool,
    pub user_verification: bool,
    pub authenticated_at: Option<i64>,
    pub profile: PlatformProfile,
}
pub enum PlatformProfile {
    Unavailable,
    IdentityLocal,
    /// Only freshly verified ID-token claims bound to this challenge and external identity.
    Idp {
        provider: ProviderId,
        claims: Box<UpstreamClaims>,
    },
}
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum PlatformError {
    #[error("platform evidence rejected")]
    Rejected,
    #[error("platform verifier unavailable")]
    Unavailable,
}
/// Installed once by trusted composition, like UpstreamOidc. This does not distrust host code.
/// Resolve/recheck borrow the caller's transaction: never commit, change tenant, take another
/// connection, perform network calls or release the authoritative binding locks.
pub trait PlatformVerifier: Send + Sync {
    fn audience(&self) -> &str;
    fn challenge_seconds(&self) -> u32 {
        120
    }
    fn resolve<'a>(
        &'a self,
        instance: rss_identity_core::InstanceId,
        tenant: TenantId,
        binding: Uuid,
        c: &'a mut PgConnection,
    ) -> BoxFuture<'a, Result<PlatformBinding, PlatformError>>;
    fn verify<'a>(
        &'a self,
        challenge: &'a PlatformChallengeContext,
        evidence: &'a [u8],
    ) -> BoxFuture<'a, Result<PlatformEvidence, PlatformError>>;
    fn recheck<'a>(
        &'a self,
        binding: &'a PlatformBinding,
        c: &'a mut PgConnection,
    ) -> BoxFuture<'a, Result<(), PlatformError>>;
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformChallenge {
    pub id: Uuid,
    pub nonce: String,
    pub expires_at: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PlatformAuthentication {
    pub binding: PlatformBinding,
    pub audience: String,
    pub authenticated_at: Option<i64>,
    pub hardware_key: bool,
    pub user_presence: bool,
    pub user_verification: bool,
}
impl PlatformAuthentication {
    pub(crate) fn assurance(
        &self,
    ) -> Result<Assurance, rss_transactional_messaging_postgres::PgError> {
        if !self.binding.valid() || self.authenticated_at.is_some() && !self.user_verification {
            return Err(corrupt());
        }
        Assurance::new(self.authenticated_at, Acr::Unspecified, vec![]).map_err(|_| corrupt())
    }
}
fn failure(error: PlatformError) -> rss_transactional_messaging_postgres::PgError {
    match error {
        PlatformError::Rejected => reject(),
        PlatformError::Unavailable => rss_transactional_messaging_postgres::PgError::from(
            rss_transactional_messaging::error::MessagingError::new(
                rss_transactional_messaging::error::MessagingErrorKind::Transient,
                std::io::Error::other("platform verifier unavailable"),
            ),
        ),
    }
}
pub(crate) async fn recheck(
    c: &mut PgConnection,
    key: AccountKey,
    stored: &PlatformAuthentication,
    checks: &crate::session_checks::SessionChecks,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    let verifier = checks.platform.as_ref().ok_or_else(reject)?;
    if !stored.binding.valid()
        || stored.binding.account != key
        || stored.binding.instance.as_uuid() != authority_id(c).await?
        || verifier.audience() != stored.audience
    {
        return Err(reject());
    }
    verifier
        .recheck(&stored.binding, c)
        .await
        .map_err(failure)?;
    external(c, &stored.binding).await?;
    stored.assurance()?;
    Ok(())
}
async fn external(
    c: &mut PgConnection,
    binding: &PlatformBinding,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    if let Some(external) = &binding.external_identity {
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM identity_authority.external_identities e JOIN identity_authority.providers p USING(tenant_id,provider_id) WHERE e.tenant_id=$1::uuid AND e.principal_id=$2 AND e.identity_id=$3 AND e.provider_id=$4::uuid AND p.enabled AND p.config_version=$5 AND p.revocation_epoch=$6)")
            .bind(binding.account.tenant.to_string()).bind(binding.account.principal.as_uuid()).bind(external.identity_id).bind(external.provider.to_string()).bind(external.config_version).bind(external.revocation_epoch).fetch_one(c).await?;
        if !valid {
            return Err(reject());
        }
    }
    Ok(())
}
impl Authority {
    pub async fn begin_platform_login(
        &self,
        tenant: TenantId,
        binding: Uuid,
        browser: String,
        source: AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<PlatformChallenge, AuthorityError> {
        self.require_runtime()?;
        crate::federation_login::check_browser(&browser)?;
        let verifier = self
            .session_checks
            .platform
            .clone()
            .ok_or(AuthorityError::Configuration)?;
        if verifier.audience().is_empty()
            || verifier.audience().len() > 256
            || !(1..=120).contains(&verifier.challenge_seconds())
            || binding.is_nil()
        {
            return Err(AuthorityError::Configuration);
        }
        let budget = Budget::new(deadline)?;
        self.reserve(
            tenant,
            format!("platform:{binding}"),
            &source,
            budget.remaining(),
        )
        .await?;
        let instance = self.instance;
        self.read_sql(tenant,budget.remaining(),move|c|Box::pin(async move{
            lock_guard(c,tenant).await?;
            let resolved=verifier.resolve(instance,tenant,binding,c).await.map_err(failure)?;
            if !resolved.valid() || resolved.instance!=instance || resolved.account.tenant!=tenant || resolved.binding_id!=binding || !load(c,resolved.account).await?.state.active(){return Err(reject().into());}
            external(c,&resolved).await?;
            let state=load(c,resolved.account).await?.state;
            let now=crate::session_storage::now(c).await?;
            sqlx::query("DELETE FROM identity_authority.platform_challenges WHERE tenant_id=$1::uuid AND challenge_id IN (SELECT challenge_id FROM identity_authority.platform_challenges WHERE tenant_id=$1::uuid AND expires_at<=$2 LIMIT 128)")
                .bind(tenant.to_string()).bind(now).execute(&mut *c).await?;
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM identity_authority.platform_challenges WHERE tenant_id=$1::uuid").bind(tenant.to_string()).fetch_one(&mut *c).await?;
            if count>=10000{return Err(reject().into());}
            let id=Uuid::new_v4();let nonce=random_secret()?;let expires=now+i64::from(verifier.challenge_seconds());
            let sequence=crate::profiles::sequence(c,tenant).await?;
            sqlx::query("INSERT INTO identity_authority.platform_challenges(tenant_id,challenge_id,principal_id,binding,audience,nonce_hash,browser_hash,auth_epoch,membership_epoch,created_at,expires_at,profile_sequence) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
                .bind(tenant.to_string()).bind(id).bind(resolved.account.principal.as_uuid()).bind(serde_json::to_value(&resolved).map_err(|_|corrupt())?).bind(verifier.audience()).bind(digest(&nonce).as_slice()).bind(digest(&browser).as_slice()).bind(state.epoch()).bind(state.membership_epoch()).bind(now).bind(expires).bind(sequence).execute(c).await?;
            Ok(PlatformChallenge{id,nonce:nonce.to_string(),expires_at:expires})
        })).await
    }
    /// No principal/assurance DTO is accepted. Only the installed verifier can supply evidence.
    pub async fn complete_platform_login(
        &self,
        tenant: TenantId,
        id: Uuid,
        nonce: String,
        browser: String,
        evidence: Vec<u8>,
        deadline: OperationDeadline,
    ) -> Result<IssuedSession, AuthorityError> {
        self.require_runtime()?;
        crate::federation_login::check_browser(&browser)?;
        if nonce.len() != 43 || evidence.is_empty() || evidence.len() > 65_536 || id.is_nil() {
            return Err(AuthorityError::InvalidInput);
        }
        let budget = Budget::new(deadline)?;
        let verifier = self
            .session_checks
            .platform
            .clone()
            .ok_or(AuthorityError::Configuration)?;
        let expected_nonce = digest(&nonce);
        let expected_browser = digest(&browser);
        let context = self
            .read_sql(tenant, budget.remaining(), move |c| {
                Box::pin(async move {
                    lock_guard(c, tenant).await?;
                    let row = challenge(c, tenant, id, &expected_nonce, &expected_browser).await?;
                    Ok(PlatformChallengeContext {
                        binding: serde_json::from_value(row.try_get("binding")?)
                            .map_err(|_| corrupt())?,
                        audience: row.try_get("audience")?,
                        nonce,
                        created_at: row.try_get("created_at")?,
                        expires_at: row.try_get("expires_at")?,
                    })
                })
            })
            .await?;
        let verified = tokio::time::timeout(
            budget.remaining().timeout(),
            verifier.verify(&context, &evidence),
        )
        .await
        .map_err(|_| AuthorityError::DeadlineElapsed)?
        .map_err(|e| match e {
            PlatformError::Rejected => AuthorityError::Rejected,
            PlatformError::Unavailable => AuthorityError::Unavailable,
        })?;
        if !verified.key_possession
            || verified.authenticated_at.is_some() && !verified.user_verification
        {
            return Err(AuthorityError::Rejected);
        }
        let stored = PlatformAuthentication {
            binding: context.binding,
            audience: context.audience,
            authenticated_at: verified.authenticated_at,
            hardware_key: verified.hardware_key,
            user_presence: verified.user_presence,
            user_verification: verified.user_verification,
        };
        let checks = self.session_checks.clone();
        let policy = self.session_policy;
        let limits = self.profile_limits;
        self.write_sql(tenant,budget.remaining(),move|c|Box::pin(async move{
            lock_guard(c,tenant).await?;
            let row=challenge(c,tenant,id,&expected_nonce,&expected_browser).await?;
            let actual:PlatformBinding=serde_json::from_value(row.try_get("binding")?).map_err(|_|corrupt())?;
            if actual!=stored.binding || row.try_get::<String,_>("audience")?!=stored.audience {return Err(reject().into());}
            let key=actual.account;let state=load(c,key).await?.state;
            if !state.active() || state.epoch()!=row.try_get::<i64,_>("auth_epoch")? || state.membership_epoch()!=row.try_get::<i64,_>("membership_epoch")? {return Err(reject().into());}
            recheck(c,key,&stored,&checks).await?;
            let now=crate::session_storage::now(c).await?;
            if stored.authenticated_at.is_some_and(|t| t< context.created_at.saturating_sub(30) || t>now) {return Err(reject().into());}
            let sequence=row.try_get("profile_sequence")?;
            let observation=match verified.profile {
                PlatformProfile::Unavailable=>None,
                PlatformProfile::IdentityLocal=>Some(crate::profiles::local_observation(c,key,now).await?),
                PlatformProfile::Idp{provider,claims}=>{
                    let binding=actual.external_identity.as_ref().ok_or_else(reject)?;
                    if provider!=binding.provider || claims.issued_at<context.created_at.saturating_sub(30){return Err(reject().into());}
                    let view=crate::federation_storage::provider(c,tenant,provider).await?;
                    let (_,issuer,subject)=crate::federation_storage::identity(c,tenant,binding.identity_id).await?;
                    if claims.issuer!=issuer || claims.subject.storage_key()!=subject {return Err(reject().into());}
                    Some(crate::profiles::oidc_observation(&claims,&view,sequence))
                }
            };
            let (issued,event)=crate::sessions::insert(c,state,None,crate::sessions::SessionAuthentication::Platform(stored),now,policy,CredentialKind::Cookie).await?;
            let mut events=vec![event];
            if let Some(observation)=observation {events.extend(crate::profiles::accept(c,key,issued.view().id,issued.view().absolute_expires_at,observation,limits).await?);}
            if crate::session_storage::now(c).await?>=row.try_get::<i64,_>("expires_at")? {return Err(reject().into());}
            sqlx::query("DELETE FROM identity_authority.platform_challenges WHERE tenant_id=$1::uuid AND challenge_id=$2").bind(tenant.to_string()).bind(id).execute(c).await?;
            Ok((issued,events))
        })).await
    }
}
async fn challenge(
    c: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
    nonce: &[u8; 32],
    browser: &[u8; 32],
) -> Result<sqlx::postgres::PgRow, transaction::MutationError> {
    let row=sqlx::query("SELECT * FROM identity_authority.platform_challenges WHERE tenant_id=$1::uuid AND challenge_id=$2 FOR UPDATE").bind(tenant.to_string()).bind(id).fetch_optional(&mut *c).await?.ok_or_else(reject)?;
    let now = crate::session_storage::now(c).await?;
    if row.try_get::<Vec<u8>, _>("nonce_hash")? != nonce
        || row.try_get::<Vec<u8>, _>("browser_hash")? != browser
        || now < row.try_get("created_at")?
        || now >= row.try_get("expires_at")?
    {
        return Err(reject().into());
    }
    Ok(row)
}

mod instance_codec {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &rss_identity_core::InstanceId,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<rss_identity_core::InstanceId, D::Error> {
        rss_identity_core::InstanceId::parse(&String::deserialize(d)?)
            .map_err(serde::de::Error::custom)
    }
}
mod account_codec {
    use super::*;
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Coordinates {
        tenant: String,
        principal: String,
    }
    pub fn serialize<S: serde::Serializer>(value: &AccountKey, s: S) -> Result<S::Ok, S::Error> {
        Coordinates {
            tenant: value.tenant.to_string(),
            principal: value.principal.as_uuid().to_string(),
        }
        .serialize(s)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<AccountKey, D::Error> {
        let c = Coordinates::deserialize(d)?;
        Ok(AccountKey {
            tenant: TenantId::parse(&c.tenant).map_err(serde::de::Error::custom)?,
            principal: rss_identity_core::PrincipalId::parse(&c.principal)
                .map_err(serde::de::Error::custom)?,
        })
    }
}
