use crate::{
    storage::*,
    transaction::{MutationError, corrupt},
    *,
};
use rss_identity_core::{SessionId, downstream::*};
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub(crate) struct Grant {
    pub fingerprint: Vec<u8>,
    pub id: Uuid,
    pub client: String,
    pub version: i64,
    pub key: Option<AccountKey>,
    pub session: Option<SessionId>,
    pub subject: Option<String>,
    pub login_hash: Vec<u8>,
    pub browser_hash: Vec<u8>,
    pub sid: String,
    pub consent: Option<String>,
    pub state: FlowState,
    pub expiry: i64,
    pub horizon: i64,
    pub lease: i64,
}
pub(crate) fn decode(r: sqlx::postgres::PgRow, tenant: TenantId) -> Result<Grant, MutationError> {
    let principal_id: Option<Uuid> = r.try_get("principal_id")?;
    let session_id: Option<Uuid> = r.try_get("session_id")?;
    Ok(Grant {
        fingerprint: r.try_get("registration_hash")?,
        id: r.try_get("grant_id")?,
        client: r.try_get("client_id")?,
        version: r.try_get("config_version")?,
        key: principal_id
            .map(|p| principal(&p.to_string()).map(|principal| AccountKey { tenant, principal }))
            .transpose()?,
        session: session_id
            .map(|s| SessionId::parse(&s.to_string()).map_err(|_| corrupt()))
            .transpose()?,
        subject: r.try_get("subject")?,
        login_hash: r.try_get("login_hash")?,
        browser_hash: r.try_get("browser_hash")?,
        sid: r.try_get("hydra_sid")?,
        consent: r.try_get("consent_id")?,
        state: FlowState::from_storage(r.try_get("state")?)?,
        expiry: r.try_get("expires_at")?,
        horizon: r.try_get("horizon")?,
        lease: r.try_get("lease_until")?,
    })
}
pub(crate) async fn load_grant(
    c: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> Result<Grant, MutationError> {
    lock_guard(c, tenant).await?;
    let r=sqlx::query("SELECT * FROM identity_authority.downstream_grants WHERE tenant_id=$1::uuid AND grant_id=$2 FOR UPDATE")
        .bind(tenant.to_string()).bind(id).fetch_optional(c).await?.ok_or(DownstreamError::Rejected)?;
    decode(r, tenant)
}
pub(crate) async fn state(
    c: &mut PgConnection,
    tenant: TenantId,
    g: &Grant,
    to: FlowState,
    now: i64,
) -> Result<(), MutationError> {
    g.state.advance(to)?;
    sqlx::query("UPDATE identity_authority.downstream_grants SET state=$3,lease_until=CASE WHEN $3=5 THEN lease_until ELSE $4 END,next_attempt=$5 WHERE tenant_id=$1::uuid AND grant_id=$2")
        .bind(tenant.to_string()).bind(g.id).bind(to as i16)
        .bind(if matches!(to,FlowState::LoginAccepting|FlowState::ConsentAccepting){now+60}else{0})
        .bind(if to==FlowState::Revoking {now}else{now+30}).execute(c).await?;
    Ok(())
}
pub(crate) fn binding(g: &Grant, r: &Registration) -> Result<(), DownstreamError> {
    if g.client != r.client() || g.version != r.version() || g.fingerprint != r.fingerprint() {
        Err(DownstreamError::Rejected)
    } else {
        Ok(())
    }
}
pub(crate) async fn session(
    c: &mut PgConnection,
    g: &Grant,
) -> Result<crate::session_storage::Loaded, MutationError> {
    let key = g.key.ok_or(DownstreamError::Rejected)?;
    let sid = g.session.ok_or(DownstreamError::Rejected)?;
    crate::session_storage::by_id(c, key, sid)
        .await
        .map_err(|e| {
            if e.kind() == rss_transactional_messaging::error::MessagingErrorKind::Conflict {
                DownstreamError::Inactive.into()
            } else {
                e.into()
            }
        })
}
/// Public pairwise identifier with its own 256-bit canonical hexadecimal encoding.
/// It is never a bearer credential and deliberately does not use SessionSecret.
pub(crate) struct ProductSubject(String);
impl ProductSubject {
    pub fn generate() -> Result<Self, DownstreamError> {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| DownstreamError::Unavailable)?;
        Ok(Self(bytes.iter().map(|b| format!("{b:02x}")).collect()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
