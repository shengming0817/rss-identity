//! Source admission counts successful and unsuccessful authentication alike.
//! ref: vaultwarden src/ratelimit.rs@b71cb7a832080d9fdfdd97bcccf065307cf73236.
use crate::{AttemptSource, Authority, AuthorityError, storage::lock_guard};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::PgError;
use sqlx::{PgConnection, Row};
/// Maximum attempts from one source within its window.
pub const ATTEMPT_SOURCE_LIMIT: i32 = 30;
/// Source attempt window in seconds.
pub const ATTEMPT_SOURCE_SECONDS: i32 = 300;
/// Maximum OIDC/platform attempts for one scope within its window.
pub const ATTEMPT_SCOPE_LIMIT: i32 = 5;
/// OIDC/platform scope attempt window in seconds.
pub const ATTEMPT_SCOPE_SECONDS: i32 = 900;
pub(crate) const MAX_ATTEMPT_ROWS: i64 = 10_000;

pub(crate) struct Attempt {
    key: String,
    count: i32,
    seconds: i32,
    pub exists: bool,
    pub retry: i64,
}
impl Attempt {
    pub async fn consume(self, c: &mut PgConnection, tenant: TenantId) -> Result<(), PgError> {
        sqlx::query("INSERT INTO identity_authority.attempts VALUES($1::uuid,$2,1,clock_timestamp()+make_interval(secs=>$3)) ON CONFLICT(tenant_id,key) DO UPDATE SET count=$4,expires_at=CASE WHEN $4=1 THEN excluded.expires_at ELSE attempts.expires_at END")
            .bind(tenant.to_string()).bind(self.key).bind(f64::from(self.seconds)).bind(self.count+1).execute(c).await?;
        Ok(())
    }
}
pub(crate) async fn attempt(
    c: &mut PgConnection,
    tenant: TenantId,
    key: String,
    limit: i32,
    seconds: i32,
) -> Result<Attempt, PgError> {
    let row = sqlx::query("SELECT CASE WHEN expires_at>clock_timestamp() THEN count ELSE 0 END AS count,CASE WHEN count>=$3 AND expires_at>clock_timestamp() THEN greatest(1,ceil(extract(epoch FROM expires_at-clock_timestamp())))::bigint ELSE 0 END AS retry FROM identity_authority.attempts WHERE tenant_id=$1::uuid AND key=$2")
        .bind(tenant.to_string()).bind(&key).bind(limit).fetch_optional(c).await?;
    Ok(Attempt {
        key,
        seconds,
        exists: row.is_some(),
        count: row
            .as_ref()
            .map(|r| r.try_get("count"))
            .transpose()?
            .unwrap_or(0),
        retry: row
            .as_ref()
            .map(|r| r.try_get("retry"))
            .transpose()?
            .unwrap_or(0),
    })
}
pub(crate) fn rate_limited(seconds: i64) -> Result<AuthorityError, PgError> {
    let seconds = u32::try_from(seconds)
        .ok()
        .and_then(std::num::NonZeroU32::new)
        .ok_or_else(crate::transaction::corrupt)?;
    Ok(AuthorityError::RateLimited {
        retry_after_seconds: seconds,
    })
}
pub(crate) async fn total(c: &mut PgConnection, tenant: TenantId) -> Result<i64, PgError> {
    Ok(sqlx::query_scalar("SELECT (SELECT count(*) FROM identity_authority.attempts WHERE tenant_id=$1::uuid)+(SELECT count(*) FROM identity_authority.password_attempts WHERE tenant_id=$1::uuid)")
        .bind(tenant.to_string()).fetch_one(c).await?)
}
pub(crate) async fn cleanup(c: &mut PgConnection, tenant: TenantId) -> Result<(), PgError> {
    let removed=sqlx::query("DELETE FROM identity_authority.attempts WHERE (tenant_id,key) IN (SELECT tenant_id,key FROM identity_authority.attempts WHERE tenant_id=$1::uuid AND expires_at<=clock_timestamp() ORDER BY expires_at LIMIT 128)")
        .bind(tenant.to_string()).execute(&mut *c).await?.rows_affected();
    sqlx::query("DELETE FROM identity_authority.password_attempts WHERE (tenant_id,login_digest) IN (SELECT tenant_id,login_digest FROM identity_authority.password_attempts WHERE tenant_id=$1::uuid AND (window_until IS NULL OR window_until<=clock_timestamp()) AND (claim_until IS NULL OR claim_until<=clock_timestamp()) ORDER BY window_until NULLS FIRST LIMIT $2)")
        .bind(tenant.to_string()).bind(128_i64-i64::try_from(removed).map_err(|_|crate::transaction::corrupt())?).execute(c).await?;
    Ok(())
}
impl Authority {
    /// OIDC/platform reservation commits independently and is never refunded.
    pub(crate) async fn reserve(
        &self,
        tenant: TenantId,
        scope: String,
        source: &AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<(), AuthorityError> {
        let source = format!("s:{}", source.value());
        self.read(tenant, deadline, move |tx| {
            Box::pin(async move {
                crate::transaction::connection(tx, move |c| {
                    Box::pin(async move {
                        lock_guard(c, tenant).await?;
                        cleanup(c, tenant).await?;
                        let source = attempt(
                            c,
                            tenant,
                            source,
                            ATTEMPT_SOURCE_LIMIT,
                            ATTEMPT_SOURCE_SECONDS,
                        )
                        .await?;
                        let scope =
                            attempt(c, tenant, scope, ATTEMPT_SCOPE_LIMIT, ATTEMPT_SCOPE_SECONDS)
                                .await?;
                        let retry = source.retry.max(scope.retry);
                        if retry > 0 {
                            return Ok(Err(rate_limited(retry)?));
                        }
                        if total(c, tenant).await?
                            + i64::from(!source.exists)
                            + i64::from(!scope.exists)
                            > MAX_ATTEMPT_ROWS
                        {
                            return Ok(Err(AuthorityError::Busy));
                        }
                        source.consume(c, tenant).await?;
                        scope.consume(c, tenant).await?;
                        Ok(Ok(()))
                    })
                })
                .await
            })
        })
        .await?
    }
}
