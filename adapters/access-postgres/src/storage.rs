use crate::{
    AccountKey, AccountState, AuthenticationCandidate,
    transaction::{corrupt, reject},
};
use access_core::PrincipalId;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgError;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub(crate) async fn guard(c: &mut PgConnection, tenant: TenantId) -> Result<(), PgError> {
    sqlx::query("INSERT INTO access_authority.guard VALUES($1::uuid) ON CONFLICT DO NOTHING")
        .bind(tenant.to_string())
        .execute(&mut *c)
        .await?;
    sqlx::query("SELECT tenant_id FROM access_authority.guard WHERE tenant_id=$1::uuid FOR UPDATE")
        .bind(tenant.to_string())
        .fetch_one(c)
        .await?;
    Ok(())
}
pub(crate) struct Stored {
    pub state: AccountState,
    pub hash: access_core::account::PasswordEncoding,
}
pub(crate) async fn load(c: &mut PgConnection, key: AccountKey) -> Result<Stored, PgError> {
    let r=sqlx::query("SELECT a.enabled,a.administrator,a.emergency,a.auth_epoch,a.credential_version,a.password_hash,m.active,m.epoch FROM access_authority.accounts a JOIN access_authority.memberships m USING(tenant_id,principal_id) WHERE a.tenant_id=$1::uuid AND a.principal_id=$2::uuid FOR UPDATE OF a,m")
        .bind(key.tenant.to_string()).bind(key.principal.as_uuid().to_string()).fetch_optional(c).await?.ok_or_else(reject)?;
    Ok(Stored {
        state: AccountState::restore(
            key,
            r.try_get("enabled")?,
            r.try_get("administrator")?,
            r.try_get("emergency")?,
            r.try_get("active")?,
            r.try_get("auth_epoch")?,
            r.try_get("credential_version")?,
            r.try_get("epoch")?,
        )
        .map_err(|_| corrupt())?,
        hash: access_core::account::PasswordEncoding::from_storage(r.try_get("password_hash")?)
            .map_err(|_| corrupt())?,
    })
}
pub(crate) async fn authority_id(c: &mut PgConnection) -> Result<Uuid, PgError> {
    let id: String =
        sqlx::query_scalar("SELECT authority_id::text FROM access_authority.deployment")
            .fetch_one(c)
            .await?;
    Uuid::parse_str(&id).map_err(|_| corrupt())
}
pub(crate) async fn current(
    c: &mut PgConnection,
    candidate: &AuthenticationCandidate,
    admin: bool,
) -> Result<AccountState, PgError> {
    if candidate.expires <= std::time::Instant::now()
        || authority_id(c).await? != candidate.authority
    {
        return Err(reject());
    }
    let now = load(c, candidate.state.key()).await?.state;
    if !now.matches_verification(candidate.state)
        || (admin
            && now
                .authorize_administration(candidate.state.key().tenant)
                .is_err())
    {
        return Err(reject());
    }
    Ok(now)
}
pub(crate) async fn insert_account(
    c: &mut PgConnection,
    key: AccountKey,
    login: &str,
    hash: &str,
    admin: bool,
    emergency: bool,
) -> Result<(), PgError> {
    AccountState::new_local(key, admin, emergency).map_err(|_| reject())?;
    sqlx::query("INSERT INTO access_authority.accounts(tenant_id,principal_id,login_key,password_hash,administrator,emergency) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6)").bind(key.tenant.to_string()).bind(key.principal.as_uuid().to_string()).bind(login).bind(hash).bind(admin).bind(emergency).execute(&mut *c).await?;
    sqlx::query("INSERT INTO access_authority.memberships(tenant_id,principal_id) VALUES($1::uuid,$2::uuid)").bind(key.tenant.to_string()).bind(key.principal.as_uuid().to_string()).execute(c).await?;
    Ok(())
}
pub(crate) async fn admin_count(c: &mut PgConnection, tenant: TenantId) -> Result<i64, PgError> {
    let n:i64=sqlx::query_scalar("SELECT count(*) FROM access_authority.accounts a JOIN access_authority.memberships m USING(tenant_id,principal_id) WHERE a.tenant_id=$1::uuid AND a.enabled AND a.administrator AND m.active")
        .bind(tenant.to_string()).fetch_one(c).await?;
    Ok(n)
}
pub(crate) fn principal(s: &str) -> Result<PrincipalId, PgError> {
    PrincipalId::parse(s).map_err(|_| corrupt())
}
