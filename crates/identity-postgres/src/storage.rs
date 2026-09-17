use crate::{
    AccountKey, AccountState, AuthenticationCandidate,
    transaction::{corrupt, reject},
};
use rss_identity_core::PrincipalId;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgError;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

/// Lock a provisioned tenant without attempting INSERT, even on a missing credential.
pub(crate) async fn lock_guard(c: &mut PgConnection, tenant: TenantId) -> Result<(), PgError> {
    sqlx::query(
        "SELECT tenant_id FROM identity_authority.guard WHERE tenant_id=$1::uuid FOR UPDATE",
    )
    .bind(tenant.to_string())
    .fetch_optional(c)
    .await?
    .ok_or_else(reject)?;
    Ok(())
}
pub(crate) struct Stored {
    pub state: AccountState,
    pub hash: Option<rss_identity_core::account::PasswordEncoding>,
}
pub(crate) async fn load(c: &mut PgConnection, key: AccountKey) -> Result<Stored, PgError> {
    // Serialize the account/membership/local-credential snapshot with every credential writer.
    lock_guard(c, key.tenant).await?;
    let r = sqlx::query(concat!(
        "SELECT a.enabled,a.auth_epoch,(l.principal_id IS NOT",
        " NULL) AS has_local_password,l.password_hash,m.active,m.epoch FROM identity_auth",
        "ority.accounts a JOIN identity_authority.memberships m USING(tenant_id,principal",
        "_id) LEFT JOIN identity_authority.local_credentials l USING(tenant_id,principal_",
        "id) WHERE a.tenant_id=$1::uuid AND a.principal_id=$2::uuid FOR UPDATE OF a,m"
    ))
    .bind(key.tenant.to_string())
    .bind(key.principal.as_uuid().to_string())
    .fetch_optional(c)
    .await?
    .ok_or_else(reject)?;
    decode(key, &r)
}

/// Caller must hold the tenant guard. All business writers serialize on that guard;
/// maintenance does not need UPDATE privileges on membership rows merely to read them.
pub(crate) async fn load_for_maintenance(
    c: &mut PgConnection,
    key: AccountKey,
) -> Result<Stored, PgError> {
    let row = sqlx::query(concat!(
        "SELECT a.enabled,a.auth_epoch,(l.principal_id IS NOT",
        " NULL) AS has_local_password,l.password_hash,m.active,m.epoch FROM identity_auth",
        "ority.accounts a JOIN identity_authority.memberships m USING(tenant_id,principal",
        "_id) LEFT JOIN identity_authority.local_credentials l USING(tenant_id,principal_",
        "id) WHERE a.tenant_id=$1::uuid AND a.principal_id=$2::uuid"
    ))
    .bind(key.tenant.to_string())
    .bind(key.principal.as_uuid().to_string())
    .fetch_optional(c)
    .await?
    .ok_or_else(reject)?;
    decode(key, &row)
}

fn decode(key: AccountKey, r: &sqlx::postgres::PgRow) -> Result<Stored, PgError> {
    Ok(Stored {
        state: AccountState::restore(
            key,
            r.try_get("enabled")?,
            r.try_get("active")?,
            r.try_get("auth_epoch")?,
            r.try_get("has_local_password")?,
            r.try_get("epoch")?,
        )
        .map_err(|_| corrupt())?,
        hash: r
            .try_get::<Option<String>, _>("password_hash")?
            .map(rss_identity_core::account::PasswordEncoding::from_storage)
            .transpose()
            .map_err(|_| corrupt())?,
    })
}
pub(crate) async fn authority_id(c: &mut PgConnection) -> Result<Uuid, PgError> {
    let id: String =
        sqlx::query_scalar("SELECT authority_id::text FROM identity_authority.deployment")
            .fetch_one(c)
            .await?;
    Uuid::parse_str(&id).map_err(|_| corrupt())
}
pub(crate) async fn current(
    c: &mut PgConnection,
    candidate: &AuthenticationCandidate,
) -> Result<AccountState, PgError> {
    if candidate.expires <= std::time::Instant::now()
        || authority_id(c).await? != candidate.authority
    {
        return Err(reject());
    }
    let now = load(c, candidate.state.key()).await?.state;
    if !now.matches_verification(candidate.state) {
        return Err(reject());
    }
    Ok(now)
}
pub(crate) async fn insert_account(
    c: &mut PgConnection,
    key: AccountKey,
    login: &str,
    hash: &str,
) -> Result<(), crate::transaction::MutationError> {
    AccountState::new_local(key).map_err(|_| reject())?;
    sqlx::query(
        "INSERT INTO identity_authority.accounts(tenant_id,principal_id) VALUES($1::uuid,$2::uuid)",
    )
    .bind(key.tenant.to_string())
    .bind(key.principal.as_uuid())
    .execute(&mut *c)
    .await?;
    sqlx::query("INSERT INTO identity_authority.local_credentials VALUES($1::uuid,$2::uuid,$3,$4)")
        .bind(key.tenant.to_string())
        .bind(key.principal.as_uuid().to_string())
        .bind(login)
        .bind(hash)
        .execute(&mut *c)
        .await
        .map_err(|error| {
            if error.as_database_error().is_some_and(|db| {
                db.code().as_deref() == Some("23505")
                    && db.constraint() == Some("local_credentials_tenant_id_login_key_key")
            }) {
                crate::transaction::MutationError::Rule(
                    rss_identity_core::account::AccountRuleError::AlreadyExists,
                )
            } else {
                error.into()
            }
        })?;
    sqlx::query("INSERT INTO identity_authority.memberships(tenant_id,principal_id) VALUES($1::uuid,$2::uuid)").bind(key.tenant.to_string()).bind(key.principal.as_uuid().to_string()).execute(c).await?;
    Ok(())
}
pub(crate) fn principal(s: &str) -> Result<PrincipalId, PgError> {
    PrincipalId::parse(s).map_err(|_| corrupt())
}

pub(crate) async fn insert_federated_account(
    c: &mut PgConnection,
    key: AccountKey,
) -> Result<(), PgError> {
    let state = AccountState::new_federated(key).map_err(|_| corrupt())?;
    sqlx::query("INSERT INTO identity_authority.accounts(tenant_id,principal_id,enabled,auth_epoch) VALUES($1::uuid,$2,$3,$4)").bind(key.tenant.to_string()).bind(key.principal.as_uuid()).bind(state.enabled()).bind(state.epoch()).execute(&mut *c).await?;
    sqlx::query("INSERT INTO identity_authority.memberships(tenant_id,principal_id,active,epoch) VALUES($1::uuid,$2,$3,$4)").bind(key.tenant.to_string()).bind(key.principal.as_uuid()).bind(state.member_active()).bind(state.membership_epoch()).execute(c).await?;
    Ok(())
}
