use crate::{
    storage::*,
    transaction::{corrupt, reject},
    *,
};
use rss_identity_core::federation::*;
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use uuid::Uuid;
pub(crate) async fn provider(
    c: &mut PgConnection,
    tenant: TenantId,
    id: ProviderId,
) -> Result<ProviderView, rss_transactional_messaging_postgres::PgError> {
    let r = sqlx::query(concat!(
        "SELECT config_version,revocation_epoch,enabled,settings FROM identity_authority.",
        "providers WHERE tenant_id=$1::uuid AND provider_id=$2::uuid FOR UPDATE"
    ))
    .bind(tenant.to_string())
    .bind(id.to_string())
    .fetch_optional(c)
    .await?
    .ok_or_else(reject)?;
    let settings: ProviderSettings =
        serde_json::from_value(r.try_get("settings")?).map_err(|_| corrupt())?;

    let version = r.try_get("config_version")?;
    let epoch = r.try_get("revocation_epoch")?;
    if version < 1 || epoch < 1 {
        return Err(corrupt());
    }
    Ok(ProviderView {
        id,
        version,
        revocation_epoch: epoch,
        enabled: r.try_get("enabled")?,
        settings,
    })
}
pub(crate) fn exact(view: &ProviderView, version: i64) -> Result<(), FederationError> {
    if !view.enabled {
        Err(FederationError::Rejected)
    } else if view.version != version {
        Err(FederationError::StaleConfiguration)
    } else {
        Ok(())
    }
}
pub(crate) async fn read_provider(
    authority: &Authority,
    tenant: TenantId,
    id: ProviderId,
    d: rss_transactional_messaging::policy::OperationDeadline,
) -> Result<ProviderView, AuthorityError> {
    authority
        .read_sql(tenant, d, move |c| {
            Box::pin(async move {
                lock_guard(c, tenant).await?;
                Ok(provider(c, tenant, id).await?)
            })
        })
        .await
}
#[derive(Clone)]
pub(crate) struct Origin {
    pub identity: Uuid,
    pub epoch: i64,
    pub facts: serde_json::Value,
}
pub(crate) async fn origin(
    c: &mut PgConnection,
    tenant: TenantId,
    session: rss_identity_core::SessionId,
) -> Result<Option<Origin>, rss_transactional_messaging_postgres::PgError> {
    let r = sqlx::query(concat!(
        "SELECT external_identity_id,provider_epoch,auth_facts FROM identity_authority.se",
        "ssions WHERE tenant_id=$1::uuid AND session_id=$2::uuid"
    ))
    .bind(tenant.to_string())
    .bind(session.to_string())
    .fetch_one(c)
    .await?;
    let id: Option<Uuid> = r.try_get("external_identity_id")?;
    match id {
        Some(identity) => Ok(Some(Origin {
            identity,
            epoch: r.try_get("provider_epoch")?,
            facts: r.try_get("auth_facts")?,
        })),
        None => {
            if r.try_get::<Option<i64>, _>("provider_epoch")?.is_some()
                || r.try_get::<Option<serde_json::Value>, _>("auth_facts")?
                    .is_some()
            {
                return Err(corrupt());
            }
            Ok(None)
        }
    }
}
pub(crate) async fn check_origin(
    c: &mut PgConnection,
    tenant: TenantId,
    origin: &Origin,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    let valid: bool = sqlx::query_scalar(concat!(
        "SELECT EXISTS(SELECT FROM identity_authority.external_identities e JOIN identity",
        "_authority.providers p USING(tenant_id,provider_id) WHERE e.tenant_id=$1::uuid A",
        "ND e.identity_id=$2 AND p.enabled AND p.revocation_epoch=$3)"
    ))
    .bind(tenant.to_string())
    .bind(origin.identity)
    .bind(origin.epoch)
    .fetch_one(c)
    .await?;
    if !valid {
        return Err(reject());
    }
    Ok(())
}
pub(crate) async fn identity(
    c: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> Result<(ProviderId, String, String), rss_transactional_messaging_postgres::PgError> {
    let r = sqlx::query(concat!(
        "SELECT provider_id::text,issuer,subject FROM identity_authority.external_identit",
        "ies WHERE tenant_id=$1::uuid AND identity_id=$2"
    ))
    .bind(tenant.to_string())
    .bind(id)
    .fetch_one(c)
    .await?;
    Ok((
        ProviderId::parse(&r.try_get::<String, _>("provider_id")?).map_err(|_| corrupt())?,
        r.try_get("issuer")?,
        r.try_get("subject")?,
    ))
}
pub(crate) struct Attempt {
    pub browser: [u8; 32],
    pub provider: ProviderId,
    pub version: i64,
    pub purpose: Purpose,
    pub expiry: i64,
    pub created: i64,
    pub client: String,
    pub return_url: String,
    pub link: Option<Uuid>,
    pub replacement: Option<rss_identity_core::SessionId>,
}
pub(crate) async fn attempt(
    c: &mut PgConnection,
    locator: &StateLocator,
    state: &str,
    browser: &str,
    claimed: bool,
) -> Result<(Attempt, Option<(String, String)>), rss_transactional_messaging_postgres::PgError> {
    let tenant = locator.tenant();
    let r = sqlx::query(concat!(
        "SELECT * FROM identity_authority.oidc_transactions WHERE tenant_id=$1::uuid AND ",
        "attempt_id=$2 FOR UPDATE"
    ))
    .bind(tenant.to_string())
    .bind(locator.id().as_slice())
    .fetch_optional(&mut *c)
    .await?
    .ok_or_else(reject)?;
    let now = crate::session_storage::now(c).await?;
    if r.try_get::<Vec<u8>, _>("state_hash")? != digest(state)
        || r.try_get::<Vec<u8>, _>("browser_hash")? != digest(browser)
        || r.try_get::<bool, _>("claimed")? != claimed
        || r.try_get::<i16, _>("purpose")? != i16::from(locator.purpose().code())
        || now < r.try_get("created_at")?
        || now >= r.try_get("expires_at")?
    {
        return Err(reject());
    }
    let secrets = if claimed {
        None
    } else {
        Some((r.try_get("nonce")?, r.try_get("verifier")?))
    };
    Ok((
        Attempt {
            browser: digest(browser),
            provider: ProviderId::parse(&r.try_get::<Uuid, _>("provider_id")?.to_string())
                .map_err(|_| corrupt())?,
            version: r.try_get("config_version")?,
            purpose: locator.purpose(),
            expiry: r.try_get("expires_at")?,
            created: r.try_get("created_at")?,
            client: r.try_get("target_client")?,
            return_url: r.try_get("return_url")?,
            link: r.try_get("link_intent")?,
            replacement: r
                .try_get::<Option<Uuid>, _>("replacement_session")?
                .map(|id| {
                    rss_identity_core::SessionId::parse(&id.to_string()).map_err(|_| corrupt())
                })
                .transpose()?,
        },
        secrets,
    ))
}
pub(crate) struct NewAttempt {
    pub locator: StateLocator,
    pub material: ProtocolMaterial,
    pub provider: ProviderView,
    pub browser: String,
    pub client: String,
    pub return_url: String,
    pub link: Option<Uuid>,
    pub replacement: Option<rss_identity_core::SessionId>,
    pub expiry: Option<i64>,
}
pub(crate) async fn insert_attempt(
    c: &mut PgConnection,
    input: NewAttempt,
) -> Result<(), transaction::MutationError> {
    let tenant = input.locator.tenant();
    let current = provider(c, tenant, input.provider.id).await?;
    exact(&current, input.provider.version)?;
    let now = crate::session_storage::now(c).await?;
    let expiry = input.expiry.unwrap_or(now + 300);
    if now >= expiry {
        return Err(reject().into());
    }
    sqlx::query(concat!(
        "DELETE FROM identity_authority.oidc_transactions WHERE (tenant_id,attempt_id) IN",
        " (SELECT tenant_id,attempt_id FROM identity_authority.oidc_transactions WHERE te",
        "nant_id=$1::uuid AND expires_at<=$2 ORDER BY expires_at LIMIT 128)"
    ))
    .bind(tenant.to_string())
    .bind(now)
    .execute(&mut *c)
    .await?;
    sqlx::query(concat!(
        "DELETE FROM identity_authority.link_intents l WHERE l.tenant_id=$1::uuid AND l.i",
        "ntent_id IN (SELECT i.intent_id FROM identity_authority.link_intents i WHERE i.t",
        "enant_id=$1::uuid AND i.expires_at<=$2 AND NOT EXISTS(SELECT FROM identity_autho",
        "rity.oidc_transactions t WHERE t.tenant_id=i.tenant_id AND t.link_intent=i.inten",
        "t_id) LIMIT 128)"
    ))
    .bind(tenant.to_string())
    .bind(now)
    .execute(&mut *c)
    .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.oidc_transactions WHERE tenant_id=$1::uuid",
    )
    .bind(tenant.to_string())
    .fetch_one(&mut *c)
    .await?;
    if count >= 10000 {
        return Err(reject().into());
    }
    sqlx::query(concat!(
        "INSERT INTO identity_authority.oidc_transactions(tenant_id,attempt_id,provider_i",
        "d,config_version,state_hash,browser_hash,purpose,nonce,verifier,created_at,expir",
        "es_at,target_client,return_url,link_intent,replacement_session) VALUES($1::uuid,",
        "$2,$3::uuid,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::uuid)"
    ))
    .bind(tenant.to_string())
    .bind(input.locator.id().as_slice())
    .bind(input.provider.id.to_string())
    .bind(input.provider.version)
    .bind(digest(&input.material.state).as_slice())
    .bind(digest(&input.browser).as_slice())
    .bind(i16::from(input.locator.purpose().code()))
    .bind(input.material.nonce.as_str())
    .bind(input.material.verifier.as_str())
    .bind(now)
    .bind(expiry)
    .bind(input.client)
    .bind(input.return_url)
    .bind(input.link)
    .bind(input.replacement.map(|v| v.to_string()))
    .execute(c)
    .await?;
    Ok(())
}
pub(crate) async fn consume(
    c: &mut PgConnection,
    locator: &StateLocator,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    sqlx::query("DELETE FROM identity_authority.oidc_transactions WHERE tenant_id=$1::uuid AND attempt_id=$2").bind(locator.tenant().to_string()).bind(locator.id().as_slice()).execute(c).await?;
    Ok(())
}
