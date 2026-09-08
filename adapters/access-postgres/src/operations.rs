use crate::{storage::*, transaction::SecurityEvent, *};
use access_core::account::{LocalChange, SecurityAction};
use access_core::{
    PrincipalId,
    account::{LoginKey, Password, PasswordKdf},
};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;

impl Authority {
    pub async fn verify_password(
        &self,
        tenant: TenantId,
        login: LoginKey,
        password: Password,
        source: AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<AuthenticationCandidate, AuthorityError> {
        self.require_runtime()?;
        let budget = Budget::new(deadline)?;
        self.reserve(
            tenant,
            format!("p:{}", login.as_str()),
            &source,
            budget.remaining(),
        )
        .await?;
        let snapshot=self.read(tenant,budget.remaining(),move|tx|Box::pin(async move {
            crate::transaction::connection(tx,move|c|Box::pin(async move {
                let id:Option<String>=sqlx::query_scalar("SELECT principal_id::text FROM access_authority.accounts WHERE tenant_id=$1::uuid AND login_key=$2").bind(tenant.to_string()).bind(login.as_str()).fetch_optional(&mut *c).await?;
                match id {
                    Some(id)=>Ok(Some((load(c,AccountKey {tenant,principal:principal(&id)?}).await?,authority_id(c).await?))),
                    None=>Ok(None)
                }
            })).await
        })).await?;
        let kdf = PasswordKdf::new();
        let Some((stored, authority)) = snapshot else {
            budget.password(kdf.dummy(password)).await?;
            return Err(AuthorityError::Rejected);
        };
        let valid = budget.password(kdf.verify(password, stored.hash)).await?;
        if !valid || !stored.state.enabled() || !stored.state.member_active() {
            return Err(AuthorityError::Rejected);
        }
        let candidate = AuthenticationCandidate {
            state: stored.state,
            authority,
            expires: budget.0,
        };
        self.read(tenant, budget.remaining(), move |tx| {
            Box::pin(async move {
                crate::transaction::connection(tx, move |c| {
                    Box::pin(async move {
                        current(c, &candidate, false).await?;
                        Ok(candidate)
                    })
                })
                .await
            })
        })
        .await
    }

    pub async fn create_account(
        &self,
        actor: AuthenticationCandidate,
        login: LoginKey,
        password: Password,
        administrator: bool,
        emergency: bool,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.require_runtime()?;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        let hash = budget.password(PasswordKdf::new().hash(password)).await?;
        let key = AccountKey {
            tenant: actor.state.key().tenant,
            principal: PrincipalId::generate(),
        };
        AccountState::new_local(key, administrator, emergency)
            .map_err(|_| AuthorityError::Invalid)?;
        self.mutate(key.tenant, budget.remaining(), move |tx| {
            Box::pin(async move {
                crate::transaction::connection(tx, move |c| {
                    Box::pin(async move {
                        guard(c, key.tenant).await?;
                        current(c, &actor, true).await?;
                        insert_account(
                            c,
                            key,
                            login.as_str(),
                            hash.as_str(),
                            administrator,
                            emergency,
                        )
                        .await?;
                        let state = load(c, key).await?.state;
                        Ok((
                            state,
                            SecurityEvent::account(
                                SecurityAction::AccountCreated,
                                state,
                                Some(actor.state.key()),
                            ),
                        ))
                    })
                })
                .await
            })
        })
        .await
    }

    pub async fn change_account(
        &self,
        actor: AuthenticationCandidate,
        target: AccountKey,
        change: AccountChange,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        if actor.state.key().tenant != target.tenant {
            return Err(AuthorityError::Rejected);
        }
        self.require_runtime()?;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        let (change, hash) = match change {
            AccountChange::Password(password) => (
                LocalChange::Password,
                Some(budget.password(PasswordKdf::new().hash(password)).await?),
            ),
            AccountChange::Enabled(v) => (LocalChange::Enabled(v), None),
            AccountChange::Administrator(v) => (LocalChange::Administrator(v), None),
            AccountChange::Membership(v) => (LocalChange::Membership(v), None),
        };
        self.mutate(target.tenant,budget.remaining(),move|tx|Box::pin(async move {
            crate::transaction::connection(tx,move|c|Box::pin(async move {
                guard(c,target.tenant).await?;
                // All account writers take this guard; candidate readers lock only their account.
                if actor.state.key().principal.as_uuid()>target.principal.as_uuid() {load(c,target).await?;}
                let actor_state=current(c,&actor,false).await?;
                let old=load(c,target).await?.state;
                let (next,action)=old.change(&actor_state,change,admin_count(c,target.tenant).await?)?;
                sqlx::query("UPDATE access_authority.accounts SET enabled=$3,administrator=$4,emergency=emergency AND $4,auth_epoch=$5,credential_version=$6,password_hash=coalesce($7,password_hash) WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
                    .bind(target.tenant.to_string()).bind(target.principal.as_uuid().to_string()).bind(next.enabled()).bind(next.administrator()).bind(next.epoch()).bind(next.credential_version()).bind(hash.as_ref().map(|h|h.as_str())).execute(&mut *c).await?;
                sqlx::query("UPDATE access_authority.memberships SET active=$3,epoch=$4 WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
                    .bind(target.tenant.to_string()).bind(target.principal.as_uuid().to_string()).bind(next.member_active()).bind(next.membership_epoch()).execute(&mut *c).await?;
                let state=load(c,target).await?.state;
                Ok((state,SecurityEvent::account(action,state,Some(actor.state.key()))))
            })).await
        })).await
    }
}
