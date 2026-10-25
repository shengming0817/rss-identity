//! Instance-bound session authority. ref: RSS auth_grant_lifecycle.rs @ 5b63e10a1b396b0ff70b7d1e6e55db296cd7a891.
use crate::{
    session_storage as db,
    storage::*,
    transaction::{SecurityEvent, connection, corrupt, reject},
    *,
};
use rss_identity_core::SessionId;
use rss_identity_core::session::{CredentialKind, SessionLifetime, SessionPolicy, SessionSecret};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use serde::Serialize;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Recheck the current credential in the host's tenant-bound READ COMMITTED transaction.
/// Call after Audit/Ledger locks and before host authorization/business locks. Identity's
/// guard and any platform verifier locks remain held until the host settles this transaction.
/// Platform source writers must honor the verifier's authoritative locks on this same connection.
/// On any error the host MUST roll back. The host owns fencing, budgets, resource authorization
/// and commit/rollback outcomes; successful admission is not a successful business commit.
/// Does not renew the session, consume step-up, or extend the actor's original lifetime.
/// Natural expiry still applies: do not cache this result or treat it as a transferable permit.
pub async fn recheck_authenticated_session_on(
    connection: &mut sqlx::PgConnection,
    actor: &AuthenticatedSession,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    db::recheck_on(connection, actor).await.map(|_| ())
}

#[derive(Debug, Clone)]
pub struct SessionView {
    pub credential_kind: CredentialKind,
    pub id: SessionId,
    pub issued_at: i64,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
}
impl SessionView {
    pub(crate) fn new(
        id: SessionId,
        lifetime: SessionLifetime,
        credential_kind: CredentialKind,
    ) -> Self {
        Self {
            id,
            credential_kind,
            issued_at: lifetime.issued_at(),
            idle_expires_at: lifetime.idle_expires_at(),
            absolute_expires_at: lifetime.absolute_expires_at(),
        }
    }
}
#[derive(Debug)]
pub struct SessionPage {
    pub sessions: Vec<SessionView>,
    pub next_cursor: Option<SessionId>,
}

/// Only returned after confirmed commit. Secret is explicitly exposed by the HTTP adapter.
#[derive(Debug)]
pub struct IssuedSession {
    identity: SessionIdentity,
    secret: SessionSecret,
    view: SessionView,
    remaining: Duration,
    observed: Instant,
}
impl IssuedSession {
    pub fn identity(&self) -> &SessionIdentity {
        &self.identity
    }
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
    pub(crate) fn new(
        secret: SessionSecret,
        view: SessionView,
        now: i64,
        state: AccountState,
    ) -> Self {
        Self {
            identity: SessionIdentity::from_state(state),
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
    pub(crate) session_checks: crate::session_checks::SessionChecks,
    pub(crate) key: AccountKey,
    pub(crate) digest: [u8; 32],
    pub(crate) authority: Uuid,
    pub(crate) expires: Instant,
    pub(crate) view: SessionView,
    pub(crate) identity: SessionIdentity,
    assurance: rss_identity_core::assurance::Assurance,
    source: rss_identity_core::session::AuthenticationSource,
    groups: crate::groups::GroupFacts,
    department_snapshot: Box<crate::department::DepartmentFacts>,
}
impl AuthenticatedSession {
    pub fn authentication_source(
        &self,
    ) -> Result<rss_identity_core::session::AuthenticationSource, AuthorityError> {
        self.check_live()?;
        Ok(self.source)
    }
    pub fn instance(&self) -> rss_identity_core::InstanceId {
        rss_identity_core::InstanceId::parse(&self.authority.to_string())
            .expect("validated instance")
    }
    pub fn assurance(&self) -> Result<&rss_identity_core::assurance::Assurance, AuthorityError> {
        self.check_live()?;
        Ok(&self.assurance)
    }
    fn check_live(&self) -> Result<(), AuthorityError> {
        if Instant::now() >= self.expires {
            return Err(AuthorityError::Rejected);
        }
        Ok(())
    }
    pub fn department_snapshot(
        &self,
    ) -> Result<VerifiedDepartmentSnapshot<'_>, DepartmentAccessError> {
        self.department_snapshot
            .view(self.instance(), self.account(), self.expires)
    }
    pub fn groups(&self) -> Result<VerifiedGroups<'_>, GroupAccessError> {
        self.groups.view(self.expires)
    }
    pub fn identity(&self) -> &SessionIdentity {
        &self.identity
    }
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
pub(crate) enum SessionAction {
    Created,
    Refreshed,
    Revoked,
    AllRevoked,
}
// Both authentication and rotation must account for every database wait before success.
pub(crate) fn checked_expiry(
    loaded: &db::Loaded,
    budget: Instant,
) -> Result<Instant, rss_transactional_messaging_postgres::PgError> {
    let expires = budget.min(loaded.expires);
    if Instant::now() >= expires {
        return Err(reject());
    }
    Ok(expires)
}
#[derive(Serialize)]
pub(crate) struct SessionEvent {
    pub(crate) action: SessionAction,
    pub tenant: String,
    pub(crate) principal: Uuid,
    pub(crate) source: rss_identity_core::session::AuthenticationSource,
    pub(crate) session_id: SessionId,
    pub(crate) replaced_session_id: Option<SessionId>,
    pub(crate) epoch: i64,
}
fn event(
    action: SessionAction,
    state: AccountState,
    id: SessionId,
    replaced: Option<SessionId>,
    source: rss_identity_core::session::AuthenticationSource,
) -> SecurityEvent {
    SecurityEvent::Session(SessionEvent {
        action,
        tenant: state.key().tenant.to_string(),
        principal: state.key().principal.as_uuid(),
        source,
        session_id: id,
        replaced_session_id: replaced,
        epoch: state.epoch(),
    })
}
pub(crate) enum SessionAuthentication {
    LocalPassword(i64),
    Oidc(crate::federation_storage::Origin),
    Platform(crate::platform::PlatformAuthentication),
}
pub(crate) async fn insert(
    c: &mut sqlx::PgConnection,
    state: AccountState,
    replaced: Option<SessionId>,
    authentication: SessionAuthentication,
    now: i64,
    policy: SessionPolicy,
    kind: CredentialKind,
) -> Result<(IssuedSession, SecurityEvent), transaction::MutationError> {
    let key = state.key();
    let (source, local_authenticated_at, origin, platform) = match authentication {
        SessionAuthentication::LocalPassword(time) if time > 0 && time <= now => {
            ("local_password", Some(time), None, None)
        }
        SessionAuthentication::Oidc(origin) if kind == CredentialKind::Cookie => {
            ("oidc", None, Some(origin), None)
        }
        SessionAuthentication::Platform(platform) if kind == CredentialKind::Cookie => {
            platform.assurance()?;
            (
                "platform",
                None,
                None,
                Some(serde_json::to_value(platform).map_err(|_| corrupt())?),
            )
        }
        _ => return Err(reject().into()),
    };
    let secret = SessionSecret::generate().map_err(|_| corrupt())?;
    let lifetime = SessionLifetime::new(now, policy).map_err(|_| corrupt())?;
    if let Some(id) = replaced {
        db::close(c, key, id, now).await?;
    }
    let id = SessionId::generate();
    let facts = match &origin {
        Some(o) => Some(o.facts.encode(c).await?),
        None => None,
    };
    sqlx::query(concat!(
        "INSERT INTO identity_authority.sessions(tenant_id,principal_id,session_id,token_",
        "hash,auth_epoch,membership_epoch,issued_at,idle_expires_at,absolute_expires_at,e",
        "xternal_identity_id,provider_epoch,auth_facts,idle_timeout,absolute_timeout,credential_kind,authentication_source,local_authenticated_at,platform_authentication) VALUES($1::uuid,$2::uuid,$3::uuid",
        ",$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)"
    ))
    .bind(key.tenant.to_string())
    .bind(key.principal.as_uuid().to_string())
    .bind(id.to_string())
    .bind(secret.digest().as_slice())
    .bind(state.epoch())
    .bind(state.membership_epoch())
    .bind(now)
    .bind(lifetime.idle_expires_at())
    .bind(lifetime.absolute_expires_at())
    .bind(origin.as_ref().map(|o| o.identity))
    .bind(origin.as_ref().map(|o| o.epoch))
    .bind(facts)
    .bind(policy.idle_seconds())
    .bind(policy.absolute_seconds())
    .bind(kind.as_str())
    .bind(source)
    .bind(local_authenticated_at)
    .bind(platform)
    .execute(c)
    .await?;
    Ok((
        IssuedSession::new(secret, SessionView::new(id, lifetime, kind), now, state),
        event(
            SessionAction::Created,
            state,
            id,
            replaced,
            match source {
                "local_password" => rss_identity_core::session::AuthenticationSource::LocalPassword,
                "oidc" => rss_identity_core::session::AuthenticationSource::Oidc,
                _ => rss_identity_core::session::AuthenticationSource::Platform,
            },
        ),
    ))
}
impl Authority {
    pub(crate) async fn create_session(
        &self,
        candidate: AuthenticationCandidate,
        replacement: Option<AuthenticatedSession>,
        deadline: OperationDeadline,
    ) -> Result<IssuedSession, AuthorityError> {
        self.create_session_for(candidate, replacement, CredentialKind::Cookie, deadline)
            .await
    }
    pub(crate) async fn create_session_for(
        &self,
        candidate: AuthenticationCandidate,
        replacement: Option<AuthenticatedSession>,
        kind: CredentialKind,
        deadline: OperationDeadline,
    ) -> Result<IssuedSession, AuthorityError> {
        self.require_runtime()?;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(candidate.expires);
        if let Some(old) = &replacement {
            if old.key != candidate.state.key() || old.view.credential_kind != kind {
                return Err(AuthorityError::Rejected);
            }
            budget.0 = budget.0.min(old.expires);
        }
        let policy = self.session_policy;
        let limits = self.profile_limits;
        let key = candidate.state.key();
        self.mutate_events(key.tenant, budget.remaining(), move |tx| {
            Box::pin(async move {
                connection(tx, move |c| {
                    Box::pin(async move {
                        lock_guard(c, key.tenant).await?;
                        let state = current(c, &candidate).await?;
                        let replaced = match replacement {
                            Some(proof) => Some(db::recheck(c, &proof).await?.view.id),
                            None => None,
                        };
                        let now = db::now(c).await?;
                        // current() checks before waiting on account locks; recheck its original deadline.
                        if Instant::now() >= candidate.expires {
                            return Err(reject().into());
                        }
                        let (issued, fact) = insert(
                            c,
                            state,
                            replaced,
                            SessionAuthentication::LocalPassword(candidate.authenticated_at),
                            now,
                            policy,
                            kind,
                        )
                        .await?;
                        let observation = crate::profiles::local_observation(c, key, now).await?;
                        let profile_event = crate::profiles::accept(
                            c,
                            key,
                            issued.view().id,
                            issued.view().absolute_expires_at,
                            observation,
                            limits,
                        )
                        .await?;
                        let mut events = vec![fact];
                        events.extend(profile_event);
                        Ok((issued, events))
                    })
                })
                .await
            })
        })
        .await
    }
    /// Validate without extending idle, for login replacement before its CSRF check.
    pub async fn inspect_session(
        &self,
        tenant: TenantId,
        secret: SessionSecret,
        deadline: OperationDeadline,
    ) -> Result<AuthenticatedSession, AuthorityError> {
        self.session_proof(
            tenant,
            secret.digest(),
            CredentialKind::Cookie,
            deadline,
            false,
        )
        .await
    }
    /// Authenticate a host-designated activity request and renew idle within the original absolute limit.
    /// The host must apply its request/CSRF policy first; passive checks use `inspect_session`.
    /// This does not rotate the credential. `refresh_session` performs explicit rotation.
    pub async fn authenticate_session(
        &self,
        tenant: TenantId,
        secret: SessionSecret,
        deadline: OperationDeadline,
    ) -> Result<AuthenticatedSession, AuthorityError> {
        self.session_proof(
            tenant,
            secret.digest(),
            CredentialKind::Cookie,
            deadline,
            true,
        )
        .await
    }
    pub(crate) async fn session_proof(
        &self,
        tenant: TenantId,
        digest: [u8; 32],
        kind: CredentialKind,
        deadline: OperationDeadline,
        touch: bool,
    ) -> Result<AuthenticatedSession, AuthorityError> {
        self.require_runtime()?;
        let budget = Budget::new(deadline)?;
        let session_checks = self.session_checks.clone();
        self.read(tenant, budget.remaining(), move |tx| {
            Box::pin(async move {
                connection(tx, move |c| {
                    Box::pin(async move {
                        let mut loaded =
                            db::lookup(c, tenant, &digest, kind, &session_checks).await?;
                        if touch {
                            db::touch(c, &mut loaded).await?;
                        }
                        let authority = authority_id(c).await?;
                        let expires = checked_expiry(&loaded, budget.0)?;
                        Ok(AuthenticatedSession {
                            session_checks,
                            identity: SessionIdentity::from_state(loaded.state),
                            assurance: loaded.assurance,
                            source: loaded.source,
                            groups: loaded.groups,
                            department_snapshot: loaded.department_snapshot,
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
        let budget = Budget::new(deadline)?;
        let secret = SessionSecret::generate().map_err(|_| AuthorityError::Unavailable)?;
        let session_checks = self.session_checks.clone();
        self.mutate(tenant,budget.remaining(),move|tx|Box::pin(async move {
            connection(tx,move|c|Box::pin(async move {
                let mut loaded = db::lookup(c,tenant,&old.digest(), CredentialKind::Cookie, &session_checks).await?;
                db::touch(c,&mut loaded).await?;
                sqlx::query(concat!("UPDATE identity_authority.sessions SET token_hash=$3 WHERE tenant_id=$1::uuid AN","D session_id=$2::uuid"))
                    .bind(tenant.to_string()).bind(loaded.view.id.to_string()).bind(secret.digest().as_slice()).execute(c).await?;
                checked_expiry(&loaded, budget.0)?;
                let fact = event(SessionAction::Refreshed,loaded.state,loaded.view.id,None,loaded.source);
                Ok((IssuedSession::new(secret,loaded.view,loaded.now,loaded.state),fact))
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
                    sqlx::query(concat!("UPDATE identity_authority.accounts SET auth_epoch=$3 WHERE tenant_id=$1::uuid AN","D principal_id=$2::uuid"))
                        .bind(actor.key.tenant.to_string()).bind(actor.key.principal.as_uuid().to_string()).bind(next.epoch()).execute(c).await?;
                    next
                } else { db::close(c,actor.key,actor.view.id,loaded.now).await?; loaded.state };
                Ok(((),event(if all {SessionAction::AllRevoked} else {SessionAction::Revoked},state,actor.view.id,None,loaded.source)))
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
            return Err(AuthorityError::InvalidInput);
        }
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        self.read(actor.key.tenant,budget.remaining(),move|tx|Box::pin(async move {
            connection(tx,move|c|Box::pin(async move {
                let loaded = db::recheck(c,&actor).await?;
                let ids: Vec<uuid::Uuid> = sqlx::query_scalar("SELECT session_id FROM identity_authority.sessions WHERE tenant_id=$1::uuid AND principal_id=$2 AND auth_epoch=$3 AND membership_epoch=$4 AND revoked_at IS NULL AND issued_at<=$5 AND idle_expires_at>$5 AND absolute_expires_at>$5 AND ($6::uuid IS NULL OR session_id>$6::uuid) ORDER BY session_id LIMIT $7")
                    .bind(actor.key.tenant.to_string()).bind(actor.key.principal.as_uuid()).bind(loaded.state.epoch()).bind(loaded.state.membership_epoch()).bind(loaded.now).bind(cursor.map(|v|v.to_string())).bind(i64::from(limit)+1).fetch_all(&mut *c).await?;
                let more=ids.len()>usize::from(limit);
                let mut sessions=Vec::new();
                let mut scanned=None;
                for id in ids.into_iter().take(usize::from(limit)) {
                    let id=db::session_id(&id.to_string())?;
                    scanned=Some(id);
                    match db::by_id(c,actor.key,id,&actor.session_checks).await {
                        Ok(current)=>sessions.push(current.view),
                        Err(error) if error.kind()==rss_transactional_messaging::error::MessagingErrorKind::Conflict => {},
                        Err(error)=>return Err(error),
                    }
                }
                let next_cursor=if more {scanned}else{None};
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
                "source",
                "tenant"
            ]
        );
        assert_eq!(schema["additionalProperties"], false);
    }
}

#[derive(Debug, Clone)]
pub struct SessionIdentity {
    pub principal_id: rss_identity_core::PrincipalId,
    pub has_local_password: bool,
}
impl SessionIdentity {
    pub(crate) fn from_state(state: AccountState) -> Self {
        Self {
            principal_id: state.key().principal,
            has_local_password: state.has_local_password(),
        }
    }
}
