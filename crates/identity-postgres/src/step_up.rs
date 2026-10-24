//! One-use operation proofs. Host business effects and consumption share one transaction.
use crate::{
    storage::lock_guard,
    transaction::{MutationError, corrupt, reject},
    *,
};
use rss_identity_core::{
    federation::{digest, random_secret},
    step_up::StepUpContext,
};
use serde::{Deserialize, Serialize};
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Opaque, session-bound handle. Possession without the original live actor proves nothing.
pub struct StepUpGrant {
    secret: Zeroizing<String>,
    pub expires_at: i64,
}
impl StepUpGrant {
    pub fn expose(&self) -> &str {
        &self.secret
    }
}
/// Returned only inside the transaction consuming the proof. Not a session or reusable permission.
pub struct ConsumedStepUp {
    pub authenticated_at: i64,
    pub(crate) source: GrantSource,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum GrantSource {
    Oidc {
        identity: Uuid,
        provider: Uuid,
        version: i64,
        epoch: i64,
    },
    Webauthn {
        credential: Uuid,
        epoch: i64,
        rp: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthenticationEvent {
    pub tenant: String,
    pub principal: Uuid,
    pub action: AuthenticationAction,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuthenticationAction {
    Registered,
    Removed,
    Recovered,
    Verified,
}
pub(crate) fn event(key: AccountKey, action: AuthenticationAction) -> transaction::SecurityEvent {
    transaction::SecurityEvent::Authentication(AuthenticationEvent {
        tenant: key.tenant.to_string(),
        principal: key.principal.as_uuid(),
        action,
    })
}
pub(crate) async fn issue(
    c: &mut PgConnection,
    loaded: &session_storage::Loaded,
    context: &StepUpContext,
    source: GrantSource,
    authenticated_at: i64,
) -> Result<StepUpGrant, MutationError> {
    let now = session_storage::now(c).await?;
    if authenticated_at <= 0 || authenticated_at > now || now - authenticated_at >= 300 {
        return Err(reject().into());
    }
    let key = loaded.state.key();
    let expires_at = (authenticated_at + 300)
        .min(loaded.view.idle_expires_at)
        .min(loaded.view.absolute_expires_at);
    if expires_at <= now {
        return Err(reject().into());
    }
    sqlx::query("DELETE FROM identity_authority.step_up_grants WHERE tenant_id=$1::uuid AND token_hash IN (SELECT token_hash FROM identity_authority.step_up_grants WHERE tenant_id=$1::uuid AND expires_at <= $2 ORDER BY expires_at LIMIT 128)").bind(key.tenant.to_string()).bind(now).execute(&mut *c).await?;
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM identity_authority.step_up_grants WHERE tenant_id=$1::uuid AND principal_id=$2").bind(key.tenant.to_string()).bind(key.principal.as_uuid()).fetch_one(&mut *c).await?;
    if count >= 32 {
        return Err(reject().into());
    }
    let secret = random_secret()?;
    sqlx::query("INSERT INTO identity_authority.step_up_grants(tenant_id,token_hash,principal_id,session_id,auth_epoch,membership_epoch,context,source,authenticated_at,expires_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(key.tenant.to_string()).bind(digest(&secret).as_slice()).bind(key.principal.as_uuid()).bind(loaded.view.id.as_uuid()).bind(loaded.state.epoch()).bind(loaded.state.membership_epoch()).bind(serde_json::to_value(context).map_err(|_|corrupt())?).bind(serde_json::to_value(source).map_err(|_|corrupt())?).bind(authenticated_at).bind(expires_at).execute(c).await?;
    Ok(StepUpGrant { secret, expires_at })
}
/// Borrow the host's READ COMMITTED transaction, already bound to the actor's tenant.
/// Call before host business locks. On error the caller MUST roll back the transaction.
/// The host checks product authorization and commits its operation with this consumption.
pub async fn consume_step_up_on(
    c: &mut PgConnection,
    actor: &AuthenticatedSession,
    expected: &StepUpContext,
    handle: &str,
) -> Result<ConsumedStepUp, rss_transactional_messaging_postgres::PgError> {
    if !c.is_in_transaction() || handle.len() != 43 {
        return Err(reject());
    }
    let (scope, isolation): (Option<String>, String) = sqlx::query_as(
        "SELECT current_setting('rss.tenant_id',true),current_setting('transaction_isolation')",
    )
    .fetch_one(&mut *c)
    .await?;
    if scope.as_deref() != Some(actor.key.tenant.to_string().as_str())
        || isolation != "read committed"
    {
        return Err(reject());
    }
    lock_guard(c, actor.key.tenant).await?;
    let loaded = session_storage::recheck(c, actor).await?;
    let row=sqlx::query("SELECT * FROM identity_authority.step_up_grants WHERE tenant_id=$1::uuid AND token_hash=$2 FOR UPDATE").bind(actor.key.tenant.to_string()).bind(digest(handle).as_slice()).fetch_optional(&mut *c).await?.ok_or_else(reject)?;
    let context: StepUpContext =
        serde_json::from_value(row.try_get("context")?).map_err(|_| corrupt())?;
    let now = session_storage::now(c).await?;
    if context != *expected
        || row.try_get::<Uuid, _>("principal_id")? != actor.key.principal.as_uuid()
        || row.try_get::<Uuid, _>("session_id")? != loaded.view.id.as_uuid()
        || row.try_get::<i64, _>("auth_epoch")? != loaded.state.epoch()
        || row.try_get::<i64, _>("membership_epoch")? != loaded.state.membership_epoch()
        || now >= row.try_get::<i64, _>("expires_at")?
        || now < row.try_get::<i64, _>("authenticated_at")?
    {
        return Err(reject());
    }
    let source: GrantSource =
        serde_json::from_value(row.try_get("source")?).map_err(|_| corrupt())?;
    validate_source(c, actor.key, &source).await?;
    session_storage::recheck(c, actor).await?;
    if session_storage::now(c).await? >= row.try_get::<i64, _>("expires_at")? {
        return Err(reject());
    }
    sqlx::query(
        "DELETE FROM identity_authority.step_up_grants WHERE tenant_id=$1::uuid AND token_hash=$2",
    )
    .bind(actor.key.tenant.to_string())
    .bind(digest(handle).as_slice())
    .execute(c)
    .await?;
    Ok(ConsumedStepUp {
        authenticated_at: row.try_get("authenticated_at")?,
        source,
    })
}

pub(crate) async fn validate_source(
    c: &mut PgConnection,
    key: AccountKey,
    source: &GrantSource,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    let valid:bool=match source.clone() {
        GrantSource::Oidc{identity,provider,version,epoch}=>sqlx::query_scalar("SELECT EXISTS(SELECT FROM identity_authority.external_identities e JOIN identity_authority.providers p USING(tenant_id,provider_id) WHERE e.tenant_id=$1::uuid AND e.principal_id=$2 AND e.identity_id=$3 AND p.provider_id=$4 AND p.enabled AND p.config_version=$5 AND p.revocation_epoch=$6)").bind(key.tenant.to_string()).bind(key.principal.as_uuid()).bind(identity).bind(provider).bind(version).bind(epoch).fetch_one(&mut *c).await?,
        GrantSource::Webauthn{credential,epoch,rp}=>sqlx::query_scalar("SELECT EXISTS(SELECT FROM identity_authority.webauthn_credentials WHERE tenant_id=$1::uuid AND principal_id=$2 AND id=$3 AND epoch=$4 AND rp=$5 AND NOT revoked)").bind(key.tenant.to_string()).bind(key.principal.as_uuid()).bind(credential).bind(epoch).bind(rp).fetch_one(&mut *c).await?,
    };
    if !valid {
        return Err(reject());
    }
    Ok(())
}
