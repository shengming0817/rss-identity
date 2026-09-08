//! Central session authority. ref: RSS auth_grant_lifecycle.rs @ 5b63e10a1b396b0ff70b7d1e6e55db296cd7a891.
use crate::{
    session_storage as db,
    storage::*,
    transaction::{SecurityEvent, connection, corrupt, reject},
    *,
};
use rss_identity_core::SessionId;
use rss_identity_core::session::{SessionLifetime, SessionSecret};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use serde::Serialize;
use sqlx::Row;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    pub id: SessionId,
    pub auth_time: i64,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
}
impl SessionView {
    pub(crate) fn new(id: SessionId, lifetime: SessionLifetime) -> Self {
        Self {
            id,
            auth_time: lifetime.auth_time(),
            idle_expires_at: lifetime.idle_expires_at(),
            absolute_expires_at: lifetime.absolute_expires_at(),
        }
    }
}
#[derive(Debug, Serialize)]
pub struct SessionPage {
    pub sessions: Vec<SessionView>,
    pub next_cursor: Option<SessionId>,
}

/// Only returned after confirmed commit. Secret is explicitly exposed by the HTTP adapter.
#[derive(Debug)]
pub struct IssuedSession {
    secret: SessionSecret,
    view: SessionView,
    remaining: Duration,
    observed: Instant,
}
impl IssuedSession {
    pub fn secret(&self) -> &SessionSecret {
        &self.secret
    }
    pub fn view(&self) -> &SessionView {
        &self.view
    }
    pub fn cookie_max_age(&self) -> u64 {
        self.remaining
            .saturating_sub(self.observed.elapsed())
            .as_secs()
    }
    fn new(secret: SessionSecret, view: SessionView, now: i64) -> Self {
        Self {
            remaining: Duration::from_secs(
                view.absolute_expires_at.saturating_sub(now).max(0) as u64
            ),
            observed: Instant::now(),
            secret,
            view,
        }
    }
}
/// Request-scoped proof, bound to this database and current credential. Every write rechecks it.
/// ```compile_fail
/// fn copy(p: rss_identity_postgres::AuthenticatedSession) { let _ = p.clone(); }
/// ```
pub struct AuthenticatedSession {
    pub(crate) key: AccountKey,
    pub(crate) digest: [u8; 32],
    pub(crate) authority: Uuid,
    pub(crate) expires: Instant,
    pub(crate) view: SessionView,
}
impl AuthenticatedSession {
    pub fn account(&self) -> AccountKey {
        self.key
    }
    pub fn view(&self) -> &SessionView {
        &self.view
    }
}
impl std::fmt::Debug for AuthenticatedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthenticatedSession(<private>)")
    }
}
#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum SessionAction {
    Created,
    Refreshed,
    Revoked,
    AllRevoked,
}
#[derive(Serialize)]
pub(crate) struct SessionEvent {
    action: SessionAction,
    pub tenant: String,
    principal: Uuid,
    session_id: SessionId,
    replaced_session_id: Option<SessionId>,
    epoch: i64,
}
fn event(
    action: SessionAction,
    state: AccountState,
    id: SessionId,
    replaced: Option<SessionId>,
) -> SecurityEvent {
    SecurityEvent::Session(SessionEvent {
        action,
        tenant: state.key().tenant.to_string(),
        principal: state.key().principal.as_uuid(),
        session_id: id,
        replaced_session_id: replaced,
        epoch: state.epoch(),
    })
}
impl Authority {
    pub async fn create_session(
        &self,
        candidate: AuthenticationCandidate,
        replacement: Option<AuthenticatedSession>,
        deadline: OperationDeadline,
    ) -> Result<IssuedSession, AuthorityError> {
        self.require_runtime()?;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(candidate.expires);
        if let Some(old) = &replacement {
            if old.key != candidate.state.key() {
                return Err(AuthorityError::Rejected);
            }
            budget.0 = budget.0.min(old.expires);
        }
        let key = candidate.state.key();
        let secret = SessionSecret::generate().map_err(|_| AuthorityError::Unavailable)?;
        self.mutate(key.tenant,budget.remaining(),move|tx|Box::pin(async move {
            connection(tx,move|c|Box::pin(async move {
                lock_guard(c,key.tenant).await?;
                let state = current(c,&candidate,false).await?;
                let replaced = match replacement {
                    Some(proof) => Some(db::recheck(c,&proof).await?.view.id), None => None,
                };
                let now = db::now(c).await?;
                // current() checks before waiting on account locks; recheck its original deadline.
                if Instant::now() >= candidate.expires { return Err(reject().into()); }
                let lifetime = SessionLifetime::new(now,state.administrator()).map_err(|_|corrupt())?;
                if let Some(id) = replaced { db::close(c,key,id,now).await?; }
                let id = SessionId::generate();
                sqlx::query("INSERT INTO identity_authority.sessions(tenant_id,principal_id,session_id,token_hash,auth_epoch,membership_epoch,auth_time,idle_expires_at,absolute_expires_at) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9)")
                    .bind(key.tenant.to_string()).bind(key.principal.as_uuid().to_string()).bind(id.to_string()).bind(secret.digest().as_slice()).bind(state.epoch()).bind(state.membership_epoch())
                    .bind(now).bind(lifetime.idle_expires_at()).bind(lifetime.absolute_expires_at()).execute(c).await?;
                Ok((IssuedSession::new(secret,SessionView::new(id,lifetime),now),event(SessionAction::Created,state,id,replaced)))
            })).await
        })).await
    }
    /// Validate without extending idle, for login replacement before its CSRF check.
    pub async fn inspect_session(
        &self,
        tenant: TenantId,
        secret: SessionSecret,
        deadline: OperationDeadline,
    ) -> Result<AuthenticatedSession, AuthorityError> {
        self.session_proof(tenant, secret, deadline, false).await
    }
    pub async fn authenticate_session(
        &self,
        tenant: TenantId,
        secret: SessionSecret,
        deadline: OperationDeadline,
    ) -> Result<AuthenticatedSession, AuthorityError> {
        self.session_proof(tenant, secret, deadline, true).await
    }
    async fn session_proof(
        &self,
        tenant: TenantId,
        secret: SessionSecret,
        deadline: OperationDeadline,
        touch: bool,
    ) -> Result<AuthenticatedSession, AuthorityError> {
        self.require_runtime()?;
        let budget = Budget::new(deadline)?;
        let digest = secret.digest();
        self.read(tenant, budget.remaining(), move |tx| {
            Box::pin(async move {
                connection(tx, move |c| {
                    Box::pin(async move {
                        let mut loaded = db::lookup(c, tenant, &digest).await?;
                        if touch {
                            db::touch(c, &mut loaded).await?;
                        }
                        let authority = authority_id(c).await?;
                        let expires = budget.0.min(
                            Instant::now()
                                + Duration::from_secs(
                                    (loaded.view.idle_expires_at - loaded.now) as u64,
                                ),
                        );
                        Ok(AuthenticatedSession {
                            key: loaded.state.key(),
                            digest,
                            authority,
                            expires,
                            view: loaded.view,
                        })
                    })
                })
                .await
            })
        })
        .await
    }
    pub async fn refresh_session(
        &self,
        tenant: TenantId,
        old: SessionSecret,
        deadline: OperationDeadline,
    ) -> Result<IssuedSession, AuthorityError> {
        self.require_runtime()?;
        let secret = SessionSecret::generate().map_err(|_| AuthorityError::Unavailable)?;
        self.mutate(tenant,deadline,move|tx|Box::pin(async move {
            connection(tx,move|c|Box::pin(async move {
                let mut loaded = db::lookup(c,tenant,&old.digest()).await?;
                db::touch(c,&mut loaded).await?;
                sqlx::query("UPDATE identity_authority.sessions SET token_hash=$3 WHERE tenant_id=$1::uuid AND session_id=$2::uuid")
                    .bind(tenant.to_string()).bind(loaded.view.id.to_string()).bind(secret.digest().as_slice()).execute(c).await?;
                let fact = event(SessionAction::Refreshed,loaded.state,loaded.view.id,None);
                Ok((IssuedSession::new(secret,loaded.view,loaded.now),fact))
            })).await
        })).await
    }
    pub async fn revoke_current_session(
        &self,
        actor: AuthenticatedSession,
        deadline: OperationDeadline,
    ) -> Result<(), AuthorityError> {
        self.revoke_session(actor, deadline, false).await
    }
    pub async fn revoke_all_sessions(
        &self,
        actor: AuthenticatedSession,
        deadline: OperationDeadline,
    ) -> Result<(), AuthorityError> {
        self.revoke_session(actor, deadline, true).await
    }
    async fn revoke_session(
        &self,
        actor: AuthenticatedSession,
        deadline: OperationDeadline,
        all: bool,
    ) -> Result<(), AuthorityError> {
        self.require_runtime()?;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        self.mutate(actor.key.tenant,budget.remaining(),move|tx|Box::pin(async move {
            connection(tx,move|c|Box::pin(async move {
                let loaded = db::recheck(c,&actor).await?;
                let state = if all {
                    let next = loaded.state.revoke_sessions()?;
                    sqlx::query("UPDATE identity_authority.accounts SET auth_epoch=$3 WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
                        .bind(actor.key.tenant.to_string()).bind(actor.key.principal.as_uuid().to_string()).bind(next.epoch()).execute(c).await?;
                    next
                } else { db::close(c,actor.key,actor.view.id,loaded.now).await?; loaded.state };
                Ok(((),event(if all {SessionAction::AllRevoked} else {SessionAction::Revoked},state,actor.view.id,None)))
            })).await
        })).await
    }
    pub async fn list_sessions(
        &self,
        actor: AuthenticatedSession,
        cursor: Option<SessionId>,
        limit: u16,
        deadline: OperationDeadline,
    ) -> Result<SessionPage, AuthorityError> {
        self.require_runtime()?;
        if !(1..=100).contains(&limit) {
            return Err(AuthorityError::Invalid);
        }
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        self.read(actor.key.tenant,budget.remaining(),move|tx|Box::pin(async move {
            connection(tx,move|c|Box::pin(async move {
                let loaded = db::recheck(c,&actor).await?;
                let rows = sqlx::query("SELECT session_id::text,auth_time,idle_expires_at,absolute_expires_at FROM identity_authority.sessions WHERE tenant_id=$1::uuid AND principal_id=$2::uuid AND auth_epoch=$3 AND membership_epoch=$4 AND revoked_at IS NULL AND auth_time <= $5 AND idle_expires_at > $5 AND absolute_expires_at > $5 AND ($6::uuid IS NULL OR session_id > $6::uuid) ORDER BY session_id LIMIT $7")
                    .bind(actor.key.tenant.to_string()).bind(actor.key.principal.as_uuid().to_string()).bind(loaded.state.epoch()).bind(loaded.state.membership_epoch()).bind(loaded.now).bind(cursor.map(|v|v.to_string())).bind(i64::from(limit)+1).fetch_all(c).await?;
                let mut sessions = Vec::with_capacity(rows.len());
                for row in rows {
                    let lifetime = SessionLifetime::restore(row.try_get("auth_time")?,row.try_get("idle_expires_at")?,row.try_get("absolute_expires_at")?,loaded.state.administrator()).map_err(|_|corrupt())?;
                    sessions.push(SessionView::new(db::session_id(&row.try_get::<String,_>("session_id")?)?,lifetime));
                }
                let next_cursor = if sessions.len() > usize::from(limit) { sessions.pop(); sessions.last().map(|v|v.id) } else { None };
                Ok(SessionPage {sessions,next_cursor})
            })).await
        })).await
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    #[test]
    fn session_action_vocabulary_matches_declared_schema() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("session-security-event-v1.json")).unwrap();
        let actions = [
            SessionAction::Created,
            SessionAction::Refreshed,
            SessionAction::Revoked,
            SessionAction::AllRevoked,
        ];
        assert_eq!(
            serde_json::to_value(actions).unwrap(),
            schema["properties"]["action"]["enum"]
        );
        let mut required: Vec<_> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        required.sort();
        assert_eq!(
            required,
            [
                "action",
                "epoch",
                "principal",
                "replaced_session_id",
                "session_id",
                "tenant"
            ]
        );
        assert_eq!(schema["additionalProperties"], false);
    }
}
