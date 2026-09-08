//! Controlled maintenance without transferable authorization tickets.
//! ref: kanidm server/core/src/actors/internal.rs@c6ca0f2a79a57267060f95f0ceeafdb4dd6f5696.
use crate::{
    storage::*,
    transaction::{SecurityEvent, reject},
    *,
};
use rss_identity_core::account::{LoginKey, Password, PasswordKdf, SecurityAction};
use rss_transactional_messaging::policy::OperationDeadline;

impl Authority {
    /// Initialize the deployment once using its independently held maintenance identity.
    pub async fn initialize(
        &self,
        key: AccountKey,
        login: LoginKey,
        password: Password,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.require_maintenance()?;
        let budget = Budget::new(deadline)?;
        let hash = budget.password(PasswordKdf::new().hash(password)).await?;
        self.mutate(key.tenant, budget.remaining(), move |tx| {
            Box::pin(async move {
                crate::transaction::connection(tx, move |c| {
                    Box::pin(async move {
                        let initialized: bool = sqlx::query_scalar(
                            "SELECT bootstrap_tenant IS NOT NULL FROM identity_authority.deployment FOR UPDATE",
                        )
                        .fetch_one(&mut *c)
                        .await?;
                        if initialized {
                            return Err(reject().into());
                        }
                        guard(c, key.tenant).await?;
                        insert_account(c, key, login.as_str(), hash.as_str(), true, false).await?;
                        sqlx::query("UPDATE identity_authority.deployment SET bootstrap_tenant=$1::uuid")
                            .bind(key.tenant.to_string())
                            .execute(&mut *c)
                            .await?;
                        let state = load_for_maintenance(c, key).await?.state;
                        Ok((state, SecurityEvent::account(SecurityAction::Initialized, state, None)))
                    })
                })
                .await
            })
        })
        .await
    }

    /// Replace only an existing administrator's password, retaining all access states.
    /// Concurrent maintenance writes serialize; the last committed password wins.
    pub async fn recover_administrator(
        &self,
        key: AccountKey,
        password: Password,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.require_maintenance()?;
        let budget = Budget::new(deadline)?;
        let hash = budget.password(PasswordKdf::new().hash(password)).await?;
        self.mutate(key.tenant, budget.remaining(), move |tx| {
            Box::pin(async move {
                crate::transaction::connection(tx, move |c| {
                    Box::pin(async move {
                        guard(c, key.tenant).await?;
                        let old = load_for_maintenance(c, key).await?.state;
                        let (next, action) = old.recover()?;
                        sqlx::query(
                            "UPDATE identity_authority.accounts SET password_hash=$3,auth_epoch=$4,credential_version=$5
                             WHERE tenant_id=$1::uuid AND principal_id=$2::uuid",
                        )
                        .bind(key.tenant.to_string())
                        .bind(key.principal.as_uuid().to_string())
                        .bind(hash.as_str())
                        .bind(next.epoch())
                        .bind(next.credential_version())
                        .execute(&mut *c)
                        .await?;
                        Ok((next, SecurityEvent::account(action, next, None)))
                    })
                })
                .await
            })
        })
        .await
    }
}
