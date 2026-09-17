use crate::{AttemptSource, Authority, AuthorityError, storage::lock_guard};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use sqlx::Row;
impl Authority {
    /// Reservation commits independently; rejected authentication never refunds it.
    pub(crate) async fn reserve(
        &self,
        tenant: TenantId,
        scope: String,
        source: &AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<(), AuthorityError> {
        // Keep the shared database future out of composed authentication stack frames.
        Box::pin(self.reserve_attempt(tenant, Some(scope), source, deadline)).await
    }
    async fn reserve_attempt(
        &self,
        tenant: TenantId,
        scope: Option<String>,
        source: &AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<(), AuthorityError> {
        let mut keys = vec![(format!("s:{}", source.value()), 30_i32, 300_i32)];
        if let Some(scope) = scope {
            keys.push((scope, 5, 900));
        }
        let allowed=self.read(tenant,deadline,move|tx|Box::pin(async move {
            crate::transaction::connection(tx,move|c|Box::pin(async move {
                lock_guard(c,tenant).await?;
                sqlx::query(concat!("DELETE FROM identity_authority.attempts WHERE (tenant_id,key) IN (SELECT tenant_","id,key FROM identity_authority.attempts WHERE tenant_id=$1::uuid AND expires_at<","=clock_timestamp() ORDER BY expires_at LIMIT 128)"))
                    .bind(tenant.to_string()).execute(&mut *c).await?;
                let total:i64=sqlx::query_scalar("SELECT count(*) FROM identity_authority.attempts WHERE tenant_id=$1::uuid").bind(tenant.to_string()).fetch_one(&mut *c).await?;
                let mut values=Vec::new(); let mut missing=0;
                for (key,limit,window) in keys {
                    let r=sqlx::query(concat!("SELECT count,expires_at>clock_timestamp() AS active FROM identity_authority.atte","mpts WHERE tenant_id=$1::uuid AND key=$2")).bind(tenant.to_string()).bind(&key).fetch_optional(&mut *c).await?;
                    if r.is_none() {missing+=1;}
                    let count=match r {Some(r) if r.try_get::<bool,_>("active")?=>r.try_get::<i32,_>("count")?,_=>0};
                    values.push((key,limit,window,count));
                }
                if total+missing>10000 {return Ok(false);}
                for (key,limit,window,count) in values {
                    if count>=limit {return Ok(false);}
                    sqlx::query(concat!("INSERT INTO identity_authority.attempts VALUES($1::uuid,$2,1,clock_timestamp()+m","ake_interval(secs=>$3)) ON CONFLICT(tenant_id,key) DO UPDATE SET count=$4,expire","s_at=CASE WHEN $4=1 THEN excluded.expires_at ELSE identity_authority.attempts.ex","pires_at END"))
                        .bind(tenant.to_string()).bind(key).bind(f64::from(window)).bind(count+1).execute(&mut *c).await?;
                }
                Ok(true)
            })).await
        })).await?;
        if allowed {
            Ok(())
        } else {
            Err(AuthorityError::RateLimited)
        }
    }
}
