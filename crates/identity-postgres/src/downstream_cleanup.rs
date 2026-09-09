use crate::{
    downstream::{Downstream, event},
    downstream_storage as db,
    transaction::MutationError,
    *,
};
use rss_identity_core::downstream::*;
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use sqlx::Row;
use uuid::Uuid;
impl Downstream {
    /// One bounded tenant-scoped recovery pass. Composition owns scheduling and tenant selection.
    pub async fn cleanup_once(
        &self,
        t: TenantId,
        limit: u16,
        deadline: OperationDeadline,
    ) -> Result<u16, AuthorityError> {
        if !(1..=128).contains(&limit) {
            return Err(AuthorityError::Invalid);
        }
        let b = Budget::new(deadline)?;
        let ids=self.authority.read_sql(t,b.remaining(),move|c|Box::pin(async move{
            crate::storage::lock_guard(c,t).await?;
            let now=crate::session_storage::now(c).await?;
            let rows=sqlx::query("SELECT grant_id FROM identity_authority.downstream_grants WHERE tenant_id=$1::uuid AND next_attempt<=$2 AND lease_until<=$2 ORDER BY next_attempt,grant_id LIMIT $3")
                .bind(t.to_string()).bind(now).bind(i64::from(limit)).fetch_all(c).await?;
            rows.into_iter().map(|r|r.try_get::<Uuid,_>("grant_id").map_err(Into::into)).collect::<Result<Vec<_>,MutationError>>()
        })).await?;
        let mut done = 0;
        for id in ids {
            let registrations = self.registrations.clone();
            // read_sql is the shared transaction runner; this internal maintenance step changes only scheduling metadata.
            let candidate=self.authority.read_sql(t,b.remaining(),move|c|Box::pin(async move{
                let g=db::load_grant(c,t,id).await?;let now=crate::session_storage::now(c).await?;
                if g.lease>now{return Ok(None);}
                let mut invalid=registrations.get(&g.client).is_none_or(|r|db::binding(&g,r).is_err());
                if g.session.is_some(){match db::session(c,&g).await {Ok(_)=>{},Err(MutationError::Downstream(DownstreamError::Inactive))=>invalid=true,Err(e)=>return Err(e)}}
                let expired=now>=g.horizon || (g.state!=FlowState::Active && now>=g.expiry);
                let accepting=matches!(g.state,FlowState::LoginAccepting|FlowState::ConsentAccepting);
                if g.state!=FlowState::Revoking && !invalid && !expired && !accepting {
                    sqlx::query("UPDATE identity_authority.downstream_grants SET next_attempt=$3 WHERE tenant_id=$1::uuid AND grant_id=$2").bind(t.to_string()).bind(id).bind(now+30).execute(c).await?;
                    return Ok(None);
                }
                // Claim before the remote call. A concurrent sweeper sees the lease and cannot delete this work.
                sqlx::query("UPDATE identity_authority.downstream_grants SET lease_until=$3 WHERE tenant_id=$1::uuid AND grant_id=$2").bind(t.to_string()).bind(id).bind(now+60).execute(c).await?;
                Ok(Some((g.consent,g.sid,now+60)))
            })).await?;
            let Some((consent, sid, lease)) = candidate else {
                continue;
            };
            self.revoke_local(t, id, b.remaining()).await?;
            let result = self
                .remote(&b, self.protocol.revoke(consent.as_deref(), &sid))
                .await;
            let success = result.is_ok();
            let removed=self.authority.conditional_write_sql(t,b.remaining(),move|c|Box::pin(async move{
                let g=db::load_grant(c,t,id).await?;let now=crate::session_storage::now(c).await?;
                if g.state!=FlowState::Revoking || g.lease!=lease{return Err(DownstreamError::Rejected.into());}
                let remove=success && now>=g.horizon;
                if remove {
                    sqlx::query("DELETE FROM identity_authority.downstream_grants WHERE tenant_id=$1::uuid AND grant_id=$2").bind(t.to_string()).bind(id).execute(c).await?;
                }else{
                    sqlx::query("UPDATE identity_authority.downstream_grants SET lease_until=0,next_attempt=$3 WHERE tenant_id=$1::uuid AND grant_id=$2").bind(t.to_string()).bind(id).bind(now+30).execute(c).await?;
                }
                Ok((remove,if remove{vec![event(t,id,"cleaned")]}else{vec![]}))
            })).await?;
            if removed {
                done += 1;
            }
            result?;
        }
        Ok(done)
    }
}
