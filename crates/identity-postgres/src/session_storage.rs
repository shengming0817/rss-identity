//! All session paths share guard → account/membership → session and a post-lock clock.
use crate::{
    AccountKey, AccountState,
    groups::GroupFacts,
    sessions::*,
    storage::*,
    transaction::{corrupt, reject},
};
use rss_identity_core::SessionId;
use rss_identity_core::assurance::{Assurance, AuthenticationMode};
use rss_identity_core::session::{CredentialKind, SessionLifetime, SessionPolicy};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgError;
use sqlx::{PgConnection, Row};
use std::time::{Duration, Instant};

/// Anchor before the query: all database and post-sample latency consumes the deadline.
pub(crate) struct TimeSample {
    started: Instant,
    micros: i64,
}
impl TimeSample {
    async fn read(c: &mut PgConnection) -> Result<Self, PgError> {
        let started = Instant::now();
        let micros = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000000)::bigint",
        )
        .fetch_one(c)
        .await?;
        if micros <= 0 {
            return Err(corrupt());
        }
        Ok(Self { started, micros })
    }
    fn for_facts(&self, time: &crate::session_checks::SessionChecks) -> Self {
        let seconds = time.seconds(self.seconds());
        Self {
            started: self.started,
            micros: self.micros.max(seconds.saturating_mul(1_000_000)),
        }
    }
    fn within_age(&self, authenticated: i64, max_age: Duration, now: Instant) -> bool {
        if max_age.is_zero() {
            return false;
        }
        i64::try_from(max_age.as_secs())
            .ok()
            .and_then(|age| authenticated.checked_add(age))
            .and_then(|end| self.deadline(end).ok())
            .is_some_and(|deadline| now < deadline)
    }
    pub(crate) fn seconds(&self) -> i64 {
        self.micros / 1_000_000
    }
    pub(crate) fn started(&self) -> Instant {
        self.started
    }
    pub(crate) fn deadline(&self, seconds: i64) -> Result<Instant, PgError> {
        if seconds <= 0 {
            return Err(corrupt());
        }
        // PostgreSQL floors to microseconds; discard the remaining fractional microsecond.
        let remaining = i128::from(seconds) * 1_000_000 - i128::from(self.micros) - 1;
        if remaining <= 0 {
            return Ok(self.started);
        }
        let micros = u64::try_from(remaining).map_err(|_| corrupt())?;
        self.started
            .checked_add(Duration::from_micros(micros))
            .ok_or_else(corrupt)
    }
}

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
    pub source: rss_identity_core::session::AuthenticationSource,
    pub assurance: Assurance,
    pub groups: GroupFacts,
    pub department_snapshot: Box<crate::department::DepartmentFacts>,
    sample: TimeSample,
    pub expires: Instant,
    pub state: AccountState,
    pub view: SessionView,
    pub lifetime: SessionLifetime,
    pub now: i64,
}
impl Loaded {
    /// The post-lock sample includes all time spent awaiting the host policy.
    pub(crate) fn recently_authenticated(&self, max_age: Duration) -> bool {
        self.assurance.auth_time().is_some_and(|authenticated| {
            authenticated <= self.now
                && self
                    .sample
                    .within_age(authenticated, max_age, Instant::now())
        })
    }
}
pub(crate) async fn lookup(
    c: &mut PgConnection,
    tenant: TenantId,
    digest: &[u8; 32],
    kind: CredentialKind,
    session_checks: &crate::session_checks::SessionChecks,
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
    let loaded = by_id(c, key, session_id(&id)?, session_checks).await?;
    let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM identity_authority.sessions WHERE tenant_id=$1::uuid AND session_id=$2::uuid")
        .bind(tenant.to_string()).bind(&id).fetch_one(c).await?;
    if stored != digest.as_slice() || loaded.view.credential_kind != kind {
        return Err(reject());
    }
    Ok(loaded)
}
/// Private shared authority check, only called after cookie or grant ownership was established.
pub(crate) async fn by_id(
    c: &mut PgConnection,
    key: AccountKey,
    sid: SessionId,
    session_checks: &crate::session_checks::SessionChecks,
) -> Result<Loaded, PgError> {
    let tenant = key.tenant;
    let id = sid.to_string();
    let state = load(c, key).await?.state;
    let row = sqlx::query(concat!(
        "SELECT credential_kind,principal_id,auth_epoch,membership_epoch,issued_at,idle_timeout,absolute_timeout,idle_expires_at,absolute_expires_at",
        ",authentication_source,local_authenticated_at,platform_authentication,revoked_at,token_hash FROM identity_authority.sessions WHERE tenant_id=$1::uuid",
        " AND session_id=$2::uuid"
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
    let source = match &origin {
        Some(origin) => Some(crate::federation_storage::check_origin(c, key, origin).await?),
        None => None,
    };
    let lifetime = SessionLifetime::restore(
        row.try_get("issued_at")?,
        row.try_get("idle_expires_at")?,
        row.try_get("absolute_expires_at")?,
        lifetime_policy(&row)?,
    )
    .map_err(|_| corrupt())?;
    let sample = TimeSample::read(c).await?;
    let now = sample.seconds();
    if !lifetime.valid_at(now) {
        return Err(reject());
    }
    let fact_sample = sample.for_facts(session_checks);
    let source_kind: String = row.try_get("authentication_source")?;
    let department = match (&origin, &source) {
        (Some(origin), Some(source)) => crate::department::DepartmentFacts::new(
            *origin.facts.department_snapshot.clone(),
            source.clone(),
            origin.facts.provider_config_version,
            &fact_sample,
        )?,
        (None, None) => {
            crate::department::DepartmentFacts::Unavailable(if source_kind == "platform" {
                rss_identity_core::department::DepartmentUnavailableReason::NotConfigured
            } else {
                rss_identity_core::department::DepartmentUnavailableReason::LocalIdentity
            })
        }
        _ => return Err(corrupt()),
    };
    let (assurance, groups) = match (source_kind.as_str(), origin, source) {
        ("oidc", Some(origin), Some(source)) => (
            origin.facts.assurance.clone(),
            origin.facts.project(source, fact_sample.seconds())?,
        ),
        ("local_password", None, None) => (
            Assurance::password(row.try_get("local_authenticated_at")?).map_err(|_| corrupt())?,
            rss_identity_core::groups::Groups::unavailable(
                rss_identity_core::facts::FactUnavailableReason::LocalIdentity,
            ),
        ),
        ("platform", None, None) => {
            let platform: crate::platform::PlatformAuthentication =
                serde_json::from_value(row.try_get("platform_authentication")?)
                    .map_err(|_| corrupt())?;
            crate::platform::recheck(c, key, &platform, session_checks).await?;
            (
                platform.assurance()?,
                rss_identity_core::groups::Groups::unavailable(
                    rss_identity_core::facts::FactUnavailableReason::NotConfigured,
                ),
            )
        }
        _ => return Err(corrupt()),
    };
    let source = match source_kind.as_str() {
        "local_password" => rss_identity_core::session::AuthenticationSource::LocalPassword,
        "oidc" => rss_identity_core::session::AuthenticationSource::Oidc,
        "platform" => rss_identity_core::session::AuthenticationSource::Platform,
        _ => return Err(corrupt()),
    };
    assurance
        .check(AuthenticationMode::Login, lifetime.issued_at(), now)
        .map_err(|_| reject())?;
    Ok(Loaded {
        source,
        assurance,
        groups: GroupFacts::new(groups, &fact_sample)?,
        department_snapshot: Box::new(department),
        expires: sample.deadline(lifetime.idle_expires_at())?,
        sample,
        state,
        view: SessionView::new(session_id(&id)?, lifetime, credential_kind(&row)?),
        lifetime,
        now,
    })
}
/// Borrowed host transaction admission shared by live-session and step-up operations.
/// ref: sqlx v0.9.0 sqlx-core/src/connection.rs (transaction detection).
pub(crate) async fn recheck_on(
    c: &mut PgConnection,
    actor: &AuthenticatedSession,
) -> Result<Loaded, PgError> {
    use sqlx::Connection;
    if !c.is_in_transaction() {
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
    recheck(c, actor).await
}

pub(crate) async fn recheck(
    c: &mut PgConnection,
    proof: &AuthenticatedSession,
) -> Result<Loaded, PgError> {
    if std::time::Instant::now() >= proof.expires || authority_id(c).await? != proof.authority {
        return Err(reject());
    }
    let mut loaded = lookup(
        c,
        proof.key.tenant,
        &proof.digest,
        proof.view.credential_kind,
        &proof.session_checks,
    )
    .await?;
    loaded.expires = loaded.expires.min(proof.expires);
    if loaded.state.key() != proof.key
        || loaded.view.id != proof.view.id
        || Instant::now() >= loaded.expires
    {
        return Err(reject());
    }
    Ok(loaded)
}
pub(crate) async fn touch(c: &mut PgConnection, loaded: &mut Loaded) -> Result<(), PgError> {
    loaded.lifetime.renew(loaded.now).map_err(|_| reject())?;
    loaded.view = SessionView::new(loaded.view.id, loaded.lifetime, loaded.view.credential_kind);
    loaded.expires = loaded.sample.deadline(loaded.lifetime.idle_expires_at())?;
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

pub(crate) fn lifetime_policy(row: &sqlx::postgres::PgRow) -> Result<SessionPolicy, PgError> {
    SessionPolicy::new(
        row.try_get("idle_timeout")?,
        row.try_get("absolute_timeout")?,
    )
    .map_err(|_| corrupt())
}

pub(crate) fn credential_kind(row: &sqlx::postgres::PgRow) -> Result<CredentialKind, PgError> {
    match row.try_get::<&str, _>("credential_kind")? {
        "cookie" => Ok(CredentialKind::Cookie),
        "bearer" => Ok(CredentialKind::Bearer),
        _ => Err(corrupt()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_wait_cannot_extend_recent_authentication() {
        let start = Instant::now();
        let sample = TimeSample {
            started: start,
            micros: 399_000_000,
        };
        let age = Duration::from_secs(300);
        assert!(sample.within_age(100, age, start));
        assert!(!sample.within_age(100, age, start + Duration::from_secs(2)));
        assert!(!sample.within_age(100, Duration::ZERO, start));
    }
    #[test]
    fn database_fraction_and_all_later_latency_consume_deadline() {
        let start = Instant::now();
        let sample = TimeSample {
            started: start,
            micros: 100_750_000,
        };
        assert_eq!(sample.seconds(), 100);
        assert_eq!(
            sample.deadline(101).unwrap(),
            start + Duration::from_micros(249_999)
        );
        assert_eq!(sample.deadline(100).unwrap(), start);
        assert!(sample.deadline(0).is_err());
        assert!(sample.deadline(i64::MAX).is_err());
        let exact = TimeSample {
            started: start,
            micros: 101_000_000,
        };
        assert_eq!(exact.deadline(101).unwrap(), start);
        let edge = TimeSample {
            started: start,
            micros: 100_999_999,
        };
        assert_eq!(edge.deadline(101).unwrap(), start);
    }
}
