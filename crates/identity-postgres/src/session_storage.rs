//! All session paths share guard → account/membership → session and a post-lock clock.
use crate::{
    AccountKey, AccountState, session_storage,
    sessions::*,
    storage::*,
    transaction::{corrupt, reject},
};
use rss_identity_core::SessionId;
use rss_identity_core::session::SessionLifetime;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgError;
use sqlx::{PgConnection, Row};

pub(crate) async fn now(c: &mut PgConnection) -> Result<i64, PgError> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(c)
            .await?,
    )
}
pub(crate) fn session_id(value: &str) -> Result<SessionId, PgError> {
    SessionId::parse(value).map_err(|_| corrupt())
}

pub(crate) struct Loaded {
    pub state: AccountState,
    pub view: SessionView,
    pub lifetime: SessionLifetime,
    pub now: i64,
}
pub(crate) async fn lookup(
    c: &mut PgConnection,
    tenant: TenantId,
    digest: &[u8; 32],
) -> Result<Loaded, PgError> {
    lock_guard(c, tenant).await?;
    let locator = sqlx::query(concat!(
        "SELECT principal_id::text,session_id::text FROM identity_authority.sessions WHER",
        "E tenant_id=$1::uuid AND token_hash=$2"
    ))
    .bind(tenant.to_string())
    .bind(digest.as_slice())
    .fetch_optional(&mut *c)
    .await?
    .ok_or_else(reject)?;
    let key = AccountKey {
        tenant,
        principal: principal(&locator.try_get::<String, _>("principal_id")?)?,
    };
    let id: String = locator.try_get("session_id")?;
    let loaded = by_id(c, key, session_id(&id)?).await?;
    let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM identity_authority.sessions WHERE tenant_id=$1::uuid AND session_id=$2::uuid")
        .bind(tenant.to_string()).bind(&id).fetch_one(c).await?;
    if stored != digest.as_slice() {
        return Err(reject());
    }
    Ok(loaded)
}
/// Private shared authority check, only called after cookie or grant ownership was established.
pub(crate) async fn by_id(
    c: &mut PgConnection,
    key: AccountKey,
    sid: SessionId,
) -> Result<Loaded, PgError> {
    let tenant = key.tenant;
    let id = sid.to_string();
    let state = load(c, key).await?.state;
    let row = sqlx::query(concat!(
        "SELECT principal_id,auth_epoch,membership_epoch,auth_time,idle_expires_at,absolute_expires_at",
        ",revoked_at,token_hash FROM identity_authority.sessions WHERE tenant_id=$1::uuid",
        " AND session_id=$2::uuid FOR UPDATE"
    ))
    .bind(tenant.to_string())
    .bind(&id)
    .fetch_optional(&mut *c)
    .await?
    .ok_or_else(reject)?;
    if row.try_get::<uuid::Uuid, _>("principal_id")? != key.principal.as_uuid()
        || !state.active()
        || row.try_get::<i64, _>("auth_epoch")? != state.epoch()
        || row.try_get::<i64, _>("membership_epoch")? != state.membership_epoch()
        || row.try_get::<Option<i64>, _>("revoked_at")?.is_some()
    {
        return Err(reject());
    }
    let origin = crate::federation_storage::origin(c, tenant, session_id(&id)?).await?;
    if let Some(origin) = &origin {
        crate::federation_storage::check_origin(c, tenant, origin).await?;
    }
    let lifetime = SessionLifetime::restore(
        row.try_get("auth_time")?,
        row.try_get("idle_expires_at")?,
        row.try_get("absolute_expires_at")?,
        state.administrator(),
    )
    .map_err(|_| corrupt())?;
    let now = session_storage::now(c).await?;
    if !lifetime.valid_at(now) {
        return Err(reject());
    }
    Ok(Loaded {
        state,
        view: SessionView::new(session_id(&id)?, lifetime),
        lifetime,
        now,
    })
}
pub(crate) async fn recheck(
    c: &mut PgConnection,
    proof: &AuthenticatedSession,
) -> Result<Loaded, PgError> {
    if std::time::Instant::now() >= proof.expires || authority_id(c).await? != proof.authority {
        return Err(reject());
    }
    let loaded = lookup(c, proof.key.tenant, &proof.digest).await?;
    if loaded.state.key() != proof.key
        || loaded.view.id != proof.view.id
        || std::time::Instant::now() >= proof.expires
    {
        return Err(reject());
    }
    Ok(loaded)
}
pub(crate) async fn touch(c: &mut PgConnection, loaded: &mut Loaded) -> Result<(), PgError> {
    loaded.lifetime.renew(loaded.now).map_err(|_| reject())?;
    loaded.view = SessionView::new(loaded.view.id, loaded.lifetime);
    sqlx::query(concat!(
        "UPDATE identity_authority.sessions SET idle_expires_at=$3 WHERE tenant_id=$1::uu",
        "id AND session_id=$2::uuid"
    ))
    .bind(loaded.state.key().tenant.to_string())
    .bind(loaded.view.id.to_string())
    .bind(loaded.lifetime.idle_expires_at())
    .execute(c)
    .await?;
    Ok(())
}
pub(crate) async fn close(
    c: &mut PgConnection,
    key: AccountKey,
    id: SessionId,
    now: i64,
) -> Result<(), PgError> {
    sqlx::query(concat!(
        "UPDATE identity_authority.sessions SET revoked_at=$3 WHERE tenant_id=$1::uuid AN",
        "D session_id=$2::uuid"
    ))
    .bind(key.tenant.to_string())
    .bind(id.to_string())
    .bind(now)
    .execute(c)
    .await?;
    Ok(())
}
