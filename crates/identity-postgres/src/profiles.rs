//! Latest login observations; session bindings never fall back to another observation.
//! ref: openidconnect-rs src/claims.rs@b639b5d39eac6903238867aeb2b29326502e6b26.
use crate::{
    storage::*,
    transaction::{SecurityEvent, corrupt, reject},
    *,
};
use rss_identity_core::{
    SessionId,
    federation::{ProviderId, ProviderView, UpstreamClaims},
    profile::{LocalProfile, Profile},
};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProfileSource {
    IdentityLocal,
    Idp { provider: ProviderId },
}
impl ProfileSource {
    fn key(self) -> String {
        match self {
            Self::IdentityLocal => "local".into(),
            Self::Idp { provider } => provider.to_string(),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileStatus {
    Available,
    Missing,
    Expired,
    Unavailable,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileView {
    pub instance_id: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub source: Option<ProfileSource>,
    pub status: ProfileStatus,
    pub snapshot_id: Option<Uuid>,
    pub provider_config_version: Option<i64>,
    pub source_revision: Option<i64>,
    pub observed_at: Option<i64>,
    pub collected_at_micros: Option<i64>,
    pub expires_at: Option<i64>,
    pub profile: Option<Profile>,
}
/// A bounded page of sources with an observation for the explicitly authorized target.
/// Locators are not authentication proofs; use latest_profile to recheck each observation.
pub struct ProfileSourcePage {
    pub sources: Vec<ProfileSource>,
    pub next_cursor: Option<ProfileSource>,
}
/// Private construction and a request deadline distinguish this view from a JSON DTO.
pub struct TrustedProfile {
    view: ProfileView,
    expires: Instant,
}
impl TrustedProfile {
    pub fn view(&self) -> Result<&ProfileView, AuthorityError> {
        if Instant::now() >= self.expires {
            return Err(AuthorityError::Rejected);
        }
        Ok(&self.view)
    }
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalProfileView {
    pub revision: i64,
    pub value: Option<LocalProfile>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileChange {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub value: Option<LocalProfile>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileReceipt {
    pub operation_id: Uuid,
    pub revision: i64,
}
#[derive(Serialize)]
pub(crate) struct ProfileEvent {
    pub tenant: String,
    principal: Uuid,
    actor: Option<Uuid>,
    action: &'static str,
    source: ProfileSource,
    snapshot_id: Option<Uuid>,
    revision: Option<i64>,
    changed_fields: Vec<&'static str>,
}
fn event(
    key: AccountKey,
    actor: Option<AccountKey>,
    action: &'static str,
    source: ProfileSource,
    snapshot_id: Option<Uuid>,
    revision: Option<i64>,
    changed_fields: Vec<&'static str>,
) -> SecurityEvent {
    SecurityEvent::Profile(ProfileEvent {
        tenant: key.tenant.to_string(),
        principal: key.principal.as_uuid(),
        actor: actor.map(|v| v.principal.as_uuid()),
        action,
        source,
        snapshot_id,
        revision,
        changed_fields,
    })
}

fn changes(previous: Option<&Profile>, next: &Profile) -> Vec<&'static str> {
    [
        (
            "displayName",
            previous.is_none_or(|p| p.display_name != next.display_name),
        ),
        (
            "username",
            previous.is_none_or(|p| p.username != next.username),
        ),
        ("email", previous.is_none_or(|p| p.email != next.email)),
        (
            "emailVerified",
            previous.is_none_or(|p| p.email_verified != next.email_verified),
        ),
        (
            "extensions",
            previous.is_none_or(|p| p.extensions != next.extensions),
        ),
    ]
    .into_iter()
    .filter_map(|(name, changed)| changed.then_some(name))
    .collect()
}

pub(crate) struct Observation {
    pub source: ProfileSource,
    pub profile: Profile,
    pub source_time: i64,
    pub source_expiry: i64,
    pub max_age: u32,
    pub sequence: i64,
    pub config_version: Option<i64>,
    pub source_epoch: Option<i64>,
    pub revision: Option<i64>,
}
pub(crate) async fn sequence(
    c: &mut PgConnection,
    tenant: TenantId,
) -> Result<i64, transaction::MutationError> {
    Ok(sqlx::query_scalar("UPDATE identity_authority.guard SET profile_sequence=profile_sequence+1 WHERE tenant_id=$1::uuid RETURNING profile_sequence")
        .bind(tenant.to_string()).fetch_one(c).await?)
}
pub(crate) async fn local_observation(
    c: &mut PgConnection,
    key: AccountKey,
    now: i64,
) -> Result<Observation, transaction::MutationError> {
    let row=sqlx::query("SELECT revision,value FROM identity_authority.local_profiles WHERE tenant_id=$1::uuid AND principal_id=$2")
        .bind(key.tenant.to_string()).bind(key.principal.as_uuid()).fetch_optional(&mut *c).await?;
    let (profile, max_age, revision) = match row {
        Some(row) => {
            let value: Option<serde_json::Value> = row.try_get("value")?;
            let revision = row.try_get("revision")?;
            match value {
                Some(value) => {
                    let local: LocalProfile =
                        serde_json::from_value(value).map_err(|_| corrupt())?;
                    (
                        local.observation().map_err(|_| corrupt())?,
                        local.max_age_seconds,
                        Some(revision),
                    )
                }
                None => (Profile::missing(), 14_400, Some(revision)),
            }
        }
        None => (Profile::missing(), 14_400, None),
    };
    Ok(Observation {
        source: ProfileSource::IdentityLocal,
        profile,
        source_time: now,
        source_expiry: i64::MAX,
        max_age,
        sequence: sequence(c, key.tenant).await?,
        config_version: None,
        source_epoch: None,
        revision,
    })
}
pub(crate) fn oidc_observation(
    claims: &UpstreamClaims,
    view: &ProviderView,
    sequence: i64,
) -> Observation {
    Observation {
        source: ProfileSource::Idp { provider: view.id },
        profile: claims.profile.clone(),
        source_time: claims.issued_at,
        source_expiry: claims.expires_at,
        max_age: view.settings.claims().profile.max_age_seconds,
        sequence,
        config_version: Some(view.version),
        source_epoch: Some(view.revocation_epoch),
        revision: None,
    }
}
/// Accepted profile, its session locator and its redacted event settle in the login transaction.
pub(crate) async fn accept(
    c: &mut PgConnection,
    key: AccountKey,
    session: SessionId,
    absolute: i64,
    mut observation: Observation,
    limits: rss_identity_core::profile::ProfileLimits,
) -> Result<Option<SecurityEvent>, transaction::MutationError> {
    observation.profile.validate().map_err(|_| corrupt())?;
    observation.profile.apply_limits(limits);
    observation.max_age = observation.max_age.min(limits.max_age_seconds());
    let now = crate::session_storage::now(c).await?;
    let expiry = observation
        .source_time
        .checked_add(i64::from(observation.max_age))
        .ok_or_else(corrupt)?
        .min(observation.source_expiry)
        .min(absolute);
    if observation.source_time > now || expiry <= now {
        return Ok(None);
    }
    let snapshot = Uuid::new_v4();
    let source = observation.source.key();
    let provider = match observation.source {
        ProfileSource::IdentityLocal => None,
        ProfileSource::Idp { provider } => Some(provider.to_string()),
    };
    let previous:Option<serde_json::Value>=sqlx::query_scalar("SELECT value FROM identity_authority.profile_observations WHERE tenant_id=$1::uuid AND principal_id=$2 AND source=$3")
        .bind(key.tenant.to_string()).bind(key.principal.as_uuid()).bind(&source).fetch_optional(&mut *c).await?;
    let previous: Option<Profile> = previous
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| corrupt())?;
    let changed_fields = changes(previous.as_ref(), &observation.profile);
    let accepted=sqlx::query("INSERT INTO identity_authority.profile_observations(tenant_id,principal_id,source,provider_id,config_version,source_epoch,source_revision,snapshot_id,sequence,observed_at,collected_at,expires_at,value) VALUES($1::uuid,$2,$3,$4::uuid,$5,$6,$7,$8,$9,$10,floor(extract(epoch FROM clock_timestamp())*1000000)::bigint,$11,$12) ON CONFLICT(tenant_id,principal_id,source) DO UPDATE SET provider_id=excluded.provider_id,config_version=excluded.config_version,source_epoch=excluded.source_epoch,source_revision=excluded.source_revision,snapshot_id=excluded.snapshot_id,sequence=excluded.sequence,observed_at=excluded.observed_at,collected_at=excluded.collected_at,expires_at=excluded.expires_at,value=excluded.value WHERE profile_observations.sequence < excluded.sequence AND (profile_observations.config_version IS DISTINCT FROM excluded.config_version OR profile_observations.observed_at <= excluded.observed_at)")
        .bind(key.tenant.to_string()).bind(key.principal.as_uuid()).bind(&source).bind(provider).bind(observation.config_version).bind(observation.source_epoch).bind(observation.revision).bind(snapshot).bind(observation.sequence).bind(observation.source_time).bind(expiry).bind(serde_json::to_value(&observation.profile).map_err(|_|corrupt())?).execute(&mut *c).await?.rows_affected();
    if accepted == 0 {
        return Ok(None);
    }
    sqlx::query("UPDATE identity_authority.sessions SET profile_source=$3,profile_snapshot=$4 WHERE tenant_id=$1::uuid AND session_id=$2")
        .bind(key.tenant.to_string()).bind(session.as_uuid()).bind(source).bind(snapshot).execute(c).await?;
    Ok(Some(event(
        key,
        None,
        "observed",
        observation.source,
        Some(snapshot),
        observation.revision,
        changed_fields,
    )))
}

/// Linking changes a credential association, not the accepted login observation. Copy only
/// its locator; current reads still enforce snapshot replacement, source revocation and expiry.
pub(crate) async fn retain_binding(
    c: &mut PgConnection,
    key: AccountKey,
    old: SessionId,
    new: SessionId,
) -> Result<(), transaction::MutationError> {
    let rows=sqlx::query("UPDATE identity_authority.sessions n SET profile_source=o.profile_source,profile_snapshot=o.profile_snapshot FROM identity_authority.sessions o WHERE n.tenant_id=$1::uuid AND n.principal_id=$2 AND n.session_id=$3 AND o.tenant_id=n.tenant_id AND o.principal_id=n.principal_id AND o.session_id=$4")
        .bind(key.tenant.to_string()).bind(key.principal.as_uuid()).bind(new.as_uuid()).bind(old.as_uuid()).execute(c).await?.rows_affected();
    if rows != 1 {
        return Err(corrupt().into());
    }
    Ok(())
}

struct Reader {
    key: AccountKey,
    digest: [u8; 32],
    session: SessionId,
    kind: rss_identity_core::session::CredentialKind,
    instance: Uuid,
    expires: Instant,
    checks: crate::session_checks::SessionChecks,
}
impl Reader {
    fn new(actor: &AuthenticatedSession) -> Result<Self, AuthorityError> {
        actor.assurance()?;
        Ok(Self {
            key: actor.key,
            digest: actor.digest,
            session: actor.view.id,
            kind: actor.view.credential_kind,
            instance: actor.authority,
            expires: actor.expires,
            checks: actor.session_checks.clone(),
        })
    }
    async fn recheck(
        &self,
        c: &mut PgConnection,
    ) -> Result<crate::session_storage::Loaded, transaction::MutationError> {
        if Instant::now() >= self.expires || authority_id(c).await? != self.instance {
            return Err(reject().into());
        }
        let loaded = crate::session_storage::lookup(
            c,
            self.key.tenant,
            &self.digest,
            self.kind,
            &self.checks,
        )
        .await?;
        if loaded.view.id != self.session || loaded.state.key() != self.key {
            return Err(reject().into());
        }
        Ok(loaded)
    }
}
impl Authority {
    pub async fn current_profile(
        &self,
        actor: &AuthenticatedSession,
        deadline: OperationDeadline,
    ) -> Result<TrustedProfile, AuthorityError> {
        self.read_profile(actor, None, deadline).await
    }
    /// Explicit latest-observation view; host policy authorizes even a self history read.
    pub async fn latest_profile(
        &self,
        actor: &AuthenticatedSession,
        target: AccountKey,
        source: ProfileSource,
        deadline: OperationDeadline,
    ) -> Result<TrustedProfile, AuthorityError> {
        self.read_profile(actor, Some((target, source)), deadline)
            .await
    }
    /// Discover the target's observations independently of the caller's login source or any
    /// host mapping. Each page uses the same ReadLatestProfile policy as reading values.
    pub async fn latest_profile_sources(
        &self,
        actor: &AuthenticatedSession,
        target: AccountKey,
        after: Option<ProfileSource>,
        deadline: OperationDeadline,
    ) -> Result<ProfileSourcePage, AuthorityError> {
        self.require_runtime()?;
        let reader = Reader::new(actor)?;
        if target.tenant != reader.key.tenant {
            return Err(AuthorityError::Rejected);
        }
        let policy = self.policy.clone();
        let instance = self.instance;
        self.read_sql(target.tenant,deadline,move|c|Box::pin(async move {
            let loaded=reader.recheck(c).await?;
            crate::management::authorize(policy.as_ref(),instance,&loaded,ManagementOperation::ReadLatestProfile,Some(target),c).await?;
            if !load(c,target).await?.state.active(){return Err(reject().into());}
            let rows:Vec<String>=sqlx::query_scalar("SELECT source FROM identity_authority.profile_observations WHERE tenant_id=$1::uuid AND principal_id=$2 AND ($3::text IS NULL OR source>$3) ORDER BY source LIMIT 101")
                .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(after.map(ProfileSource::key)).fetch_all(c).await?;
            let more=rows.len()>100;
            let sources=rows.into_iter().take(100).map(|source| if source=="local" {Ok(ProfileSource::IdentityLocal)} else {ProviderId::parse(&source).map(|provider|ProfileSource::Idp{provider}).map_err(|_|corrupt())}).collect::<Result<Vec<_>,_>>()?;
            let next_cursor=if more {sources.last().copied()} else {None};
            Ok(ProfileSourcePage{sources,next_cursor})
        })).await
    }
    async fn read_profile(
        &self,
        actor: &AuthenticatedSession,
        latest: Option<(AccountKey, ProfileSource)>,
        deadline: OperationDeadline,
    ) -> Result<TrustedProfile, AuthorityError> {
        self.require_runtime()?;
        let reader = Reader::new(actor)?;
        let instance = self.instance;
        let policy = self.policy.clone();
        let budget = Budget::new(deadline)?;
        let limits = self.profile_limits;
        if latest.is_some_and(|(target, _)| target.tenant != reader.key.tenant) {
            return Err(AuthorityError::Rejected);
        }
        self.read_sql(reader.key.tenant,budget.remaining(),move|c|Box::pin(async move {
            let loaded=reader.recheck(c).await?;
            let mut expires=crate::sessions::checked_expiry(&loaded,budget.0.min(reader.expires)).map_err(transaction::MutationError::from)?;
            let (target,source,bound)=match latest {
                Some((target,source))=>{
                    crate::management::authorize(policy.as_ref(),instance,&loaded,ManagementOperation::ReadLatestProfile,Some(target),c).await?;
                    (target,source,None)
                },
                None=>{
                    let row=sqlx::query("SELECT profile_source,profile_snapshot FROM identity_authority.sessions WHERE tenant_id=$1::uuid AND session_id=$2")
                        .bind(reader.key.tenant.to_string()).bind(reader.session.as_uuid()).fetch_one(&mut *c).await?;
                    let source:Option<String>=row.try_get("profile_source")?;let snapshot:Option<Uuid>=row.try_get("profile_snapshot")?;
                    let source=match source.as_deref(){Some("local")=>ProfileSource::IdentityLocal,Some(id)=>ProfileSource::Idp{provider:ProviderId::parse(id)?},None=>ProfileSource::IdentityLocal};
                    (reader.key,source,Some(snapshot))
                }
            };
            if !load(c,target).await?.state.active(){return Err(reject().into());}
            let mut view=ProfileView {instance_id:instance.to_string(),tenant_id:target.tenant.to_string(),principal_id:target.principal.as_uuid().to_string(),source:Some(source),status:ProfileStatus::Unavailable,snapshot_id:None,provider_config_version:None,source_revision:None,observed_at:None,collected_at_micros:None,expires_at:None,profile:None};
            if bound==Some(None){view.source=None;return Ok(TrustedProfile{view,expires});}
            let row=sqlx::query("SELECT * FROM identity_authority.profile_observations WHERE tenant_id=$1::uuid AND principal_id=$2 AND source=$3")
                .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(source.key()).fetch_optional(&mut *c).await?;
            let Some(row)=row else {view.status=ProfileStatus::Missing;return Ok(TrustedProfile{view,expires})};
            let snapshot:Uuid=row.try_get("snapshot_id")?;
            if bound.flatten().is_some_and(|id|id!=snapshot){return Ok(TrustedProfile{view,expires});}
            if let ProfileSource::Idp{provider}=source {
                let provider=crate::federation_storage::provider(c,target.tenant,provider).await?;
                let linked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM identity_authority.external_identities WHERE tenant_id=$1::uuid AND principal_id=$2 AND provider_id=$3::uuid)")
                    .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(provider.id.to_string()).fetch_one(&mut *c).await?;
                if !linked || !provider.enabled || Some(provider.version)!=row.try_get("config_version")? || Some(provider.revocation_epoch)!=row.try_get("source_epoch")? {return Ok(TrustedProfile{view,expires});}
            }
            let end:i64=row.try_get("expires_at")?;let end=end.min(loaded.view.absolute_expires_at).min(row.try_get::<i64,_>("observed_at")?.saturating_add(i64::from(limits.max_age_seconds())));
            let sampled=Instant::now();
            let micros:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint").fetch_one(&mut *c).await?;
            let now=reader.checks.seconds(micros/1_000_000);
            view.status=if now>=end {ProfileStatus::Expired}else{ProfileStatus::Available};
            if view.status==ProfileStatus::Available {
                let remaining=end.saturating_mul(1_000_000).saturating_sub(micros).saturating_sub(1).max(0) as u64;
                expires=expires.min(sampled.checked_add(std::time::Duration::from_micros(remaining)).ok_or_else(corrupt)?);
            }
            view.snapshot_id=Some(snapshot);view.provider_config_version=row.try_get("config_version")?;view.source_revision=row.try_get("source_revision")?;
            view.observed_at=Some(row.try_get("observed_at")?);view.collected_at_micros=Some(row.try_get("collected_at")?);view.expires_at=Some(end);
            if latest.is_some() || view.status==ProfileStatus::Available {
                let mut profile:Profile=serde_json::from_value(row.try_get("value")?).map_err(|_|corrupt())?;profile.validate().map_err(|_|corrupt())?;profile.apply_limits(limits);view.profile=Some(profile);
            }
            Ok(TrustedProfile{view,expires})
        })).await
    }
    pub async fn read_local_profile(
        &self,
        actor: &AuthenticatedSession,
        target: AccountKey,
        deadline: OperationDeadline,
    ) -> Result<LocalProfileView, AuthorityError> {
        self.require_runtime()?;
        let reader = Reader::new(actor)?;
        let policy = self.policy.clone();
        let instance = self.instance;
        if target.tenant != reader.key.tenant {
            return Err(AuthorityError::Rejected);
        }
        self.read_sql(target.tenant, deadline, move |c| {
            Box::pin(async move {
                let loaded = reader.recheck(c).await?;
                crate::management::authorize(
                    policy.as_ref(),
                    instance,
                    &loaded,
                    ManagementOperation::ReadLocalProfile,
                    Some(target),
                    c,
                )
                .await?;
                if !load(c, target).await?.state.active() {
                    return Err(reject().into());
                }
                local_view(c, target).await
            })
        })
        .await
    }
    pub async fn update_local_profile(
        &self,
        actor: AuthenticatedSession,
        target: AccountKey,
        change: ProfileChange,
        deadline: OperationDeadline,
    ) -> Result<ProfileReceipt, AuthorityError> {
        self.require_runtime()?;
        if target.tenant != actor.key.tenant
            || change.operation_id.is_nil()
            || change.expected_revision < 0
            || change
                .value
                .as_ref()
                .is_some_and(|v| v.observation().is_err())
        {
            return Err(AuthorityError::InvalidInput);
        }
        let policy = self.policy.clone();
        let instance = self.instance;
        let digest = rss_identity_core::federation::digest(
            &serde_json::to_string(&change).map_err(|_| AuthorityError::InvalidInput)?,
        );
        self.conditional_write_sql(target.tenant,deadline,move|c|Box::pin(async move{
            let loaded=crate::session_storage::recheck(c,&actor).await?;
            crate::management::authorize(policy.as_ref(),instance,&loaded,ManagementOperation::UpdateLocalProfile,Some(target),c).await?;
            if !load(c,target).await?.state.active(){return Err(reject().into());}
            if let Some(row)=sqlx::query("SELECT principal_id,actor,digest,revision FROM identity_authority.profile_operations WHERE tenant_id=$1::uuid AND operation_id=$2")
                .bind(target.tenant.to_string()).bind(change.operation_id).fetch_optional(&mut *c).await? {
                if row.try_get::<Uuid,_>("principal_id")?!=target.principal.as_uuid() || row.try_get::<Uuid,_>("actor")?!=actor.key.principal.as_uuid() || row.try_get::<Vec<u8>,_>("digest")?!=digest {return Err(transaction::MutationError::OperationConflict);}
                return Ok((ProfileReceipt{operation_id:change.operation_id,revision:row.try_get("revision")?},vec![]));
            }
            let old=local_view(c,target).await?;
            if old.revision!=change.expected_revision{return Err(transaction::MutationError::RevisionConflict);}
            let revision=old.revision.checked_add(1).ok_or_else(corrupt)?;
            let before=old.value.as_ref().map(LocalProfile::observation).transpose().map_err(|_|corrupt())?;
            let after=change.value.as_ref().map(LocalProfile::observation).transpose().map_err(|_|corrupt())?.unwrap_or_else(Profile::missing);
            let mut changed_fields=changes(before.as_ref(),&after);
            if old.value.as_ref().map(|v|v.max_age_seconds)!=change.value.as_ref().map(|v|v.max_age_seconds){changed_fields.push("maxAgeSeconds");}
            let value=change.value.map(serde_json::to_value).transpose().map_err(|_|corrupt())?;
            sqlx::query("INSERT INTO identity_authority.local_profiles(tenant_id,principal_id,revision,value) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,principal_id) DO UPDATE SET revision=excluded.revision,value=excluded.value")
                .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(revision).bind(value).execute(&mut *c).await?;
            sqlx::query("INSERT INTO identity_authority.profile_operations(tenant_id,operation_id,principal_id,actor,digest,revision) VALUES($1::uuid,$2,$3,$4,$5,$6)")
                .bind(target.tenant.to_string()).bind(change.operation_id).bind(target.principal.as_uuid()).bind(actor.key.principal.as_uuid()).bind(digest.as_slice()).bind(revision).execute(c).await?;
            Ok((ProfileReceipt{operation_id:change.operation_id,revision},vec![event(target,Some(actor.key),"local_updated",ProfileSource::IdentityLocal,None,Some(revision),changed_fields)]))
        })).await
    }
    pub async fn local_profile_receipt(
        &self,
        actor: &AuthenticatedSession,
        target: AccountKey,
        operation: Uuid,
        deadline: OperationDeadline,
    ) -> Result<Option<ProfileReceipt>, AuthorityError> {
        self.require_runtime()?;
        let reader = Reader::new(actor)?;
        let policy = self.policy.clone();
        let instance = self.instance;
        if target.tenant != reader.key.tenant {
            return Err(AuthorityError::Rejected);
        }
        self.read_sql(target.tenant,deadline,move|c|Box::pin(async move{
            let loaded=reader.recheck(c).await?;
            crate::management::authorize(policy.as_ref(),instance,&loaded,ManagementOperation::UpdateLocalProfile,Some(target),c).await?;
            let revision:Option<i64>=sqlx::query_scalar("SELECT revision FROM identity_authority.profile_operations WHERE tenant_id=$1::uuid AND principal_id=$2 AND actor=$3 AND operation_id=$4")
                .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(reader.key.principal.as_uuid()).bind(operation).fetch_optional(c).await?;
            Ok(revision.map(|revision|ProfileReceipt{operation_id:operation,revision}))
        })).await
    }
}
async fn local_view(
    c: &mut PgConnection,
    key: AccountKey,
) -> Result<LocalProfileView, transaction::MutationError> {
    let row=sqlx::query("SELECT revision,value FROM identity_authority.local_profiles WHERE tenant_id=$1::uuid AND principal_id=$2")
        .bind(key.tenant.to_string()).bind(key.principal.as_uuid()).fetch_optional(c).await?;
    match row {
        None => Ok(LocalProfileView {
            revision: 0,
            value: None,
        }),
        Some(row) => {
            let value: Option<serde_json::Value> = row.try_get("value")?;
            Ok(LocalProfileView {
                revision: row.try_get("revision")?,
                value: value
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|_| corrupt())?,
            })
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSourceView {
    pub source: ProfileSource,
    pub provider_config_version: Option<i64>,
    pub extensions_root: Option<String>,
    pub max_age_seconds: u32,
}
impl Authority {
    /// Non-secret publication metadata. Does not imply permission to read any person's values.
    pub async fn profile_sources(
        &self,
        actor: &AuthenticatedSession,
        deadline: OperationDeadline,
    ) -> Result<Vec<ProfileSourceView>, AuthorityError> {
        self.require_runtime()?;
        let reader = Reader::new(actor)?;
        let policy = self.policy.clone();
        let instance = self.instance;
        self.read_sql(reader.key.tenant,deadline,move|c|Box::pin(async move{
            let loaded=reader.recheck(c).await?;
            crate::management::authorize(policy.as_ref(),instance,&loaded,ManagementOperation::ReadProfileSources,None,c).await?;
            let rows=sqlx::query("SELECT provider_id,config_version,settings FROM identity_authority.providers WHERE tenant_id=$1::uuid AND enabled ORDER BY provider_id LIMIT 101")
                .bind(reader.key.tenant.to_string()).fetch_all(c).await?;
            if rows.len()>100{return Err(reject().into());}
            let mut sources=vec![ProfileSourceView{source:ProfileSource::IdentityLocal,provider_config_version:None,extensions_root:Some("extensions".into()),max_age_seconds:14400}];
            for row in rows {
                let settings:rss_identity_core::federation::ProviderSettings=serde_json::from_value(row.try_get("settings")?).map_err(|_|corrupt())?;
                sources.push(ProfileSourceView{source:ProfileSource::Idp{provider:ProviderId::parse(&row.try_get::<Uuid,_>("provider_id")?.to_string())?},provider_config_version:Some(row.try_get("config_version")?),extensions_root:settings.claims().profile.extensions_claim.clone(),max_age_seconds:settings.claims().profile.max_age_seconds});
            }
            Ok(sources)
        })).await
    }
}
