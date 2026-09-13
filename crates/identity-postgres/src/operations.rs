use crate::{storage::*, transaction::SecurityEvent, *};
use rss_identity_core::account::{LocalChange, SecurityAction};
use rss_identity_core::{
    PrincipalId,
    account::{LoginKey, Password},
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
                let id:Option<String>=sqlx::query_scalar(concat!("SELECT principal_id::text FROM identity_authority.local_credentials WHERE tenant","_id=$1::uuid AND login_key=$2")).bind(tenant.to_string()).bind(login.as_str()).fetch_optional(&mut *c).await?;
                match id {
                    Some(id)=>Ok(Some((load(c,AccountKey {tenant,principal:principal(&id)?}).await?,authority_id(c).await?))),
                    None=>Ok(None)
                }
            })).await
        })).await?;
        let kdf = &self.kdf;
        let Some((stored, authority)) = snapshot else {
            budget.password(kdf.dummy(password)).await?;
            return Err(AuthorityError::Rejected);
        };
        let hash = stored.hash.ok_or(AuthorityError::Rejected)?;
        let valid = budget.password(kdf.verify(password, hash)).await?;
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

    pub async fn create_local_account(
        &self,
        actor: AuthenticatedSession,
        login: LoginKey,
        password: Password,
        role: LocalAccountRole,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.require_runtime()?;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        self.require_administrator(&actor)?;
        let hash = budget.password(self.kdf.hash(password)).await?;
        let key = AccountKey {
            tenant: actor.key.tenant,
            principal: PrincipalId::generate(),
        };
        let (administrator, emergency) = role.flags();
        self.write_sql(key.tenant, budget.remaining(), move |c| {
            Box::pin(async move {
                let loaded = crate::session_storage::recheck(c, &actor).await?;
                loaded.authorize_administration(key.tenant)?;
                if loaded.system_domain && (administrator || emergency) {
                    return Err(rss_identity_core::platform::PlatformError::Invalid.into());
                }
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
                    vec![SecurityEvent::account(
                        SecurityAction::AccountCreated,
                        state,
                        Some(actor.key),
                    )],
                ))
            })
        })
        .await
    }

    pub async fn set_account_enabled(
        &self,
        actor: AuthenticatedSession,
        target: AccountKey,
        enabled: bool,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.apply_account_change(
            actor,
            target,
            AccountChange::Enabled(enabled),
            None,
            deadline,
        )
        .await
    }
    pub async fn set_account_administrator(
        &self,
        actor: AuthenticatedSession,
        target: AccountKey,
        administrator: bool,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.apply_account_change(
            actor,
            target,
            AccountChange::Administrator(administrator),
            None,
            deadline,
        )
        .await
    }
    pub async fn set_account_membership(
        &self,
        actor: AuthenticatedSession,
        target: AccountKey,
        active: bool,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.apply_account_change(
            actor,
            target,
            AccountChange::Membership(active),
            None,
            deadline,
        )
        .await
    }
    pub async fn reset_local_password(
        &self,
        actor: AuthenticatedSession,
        target: AccountKey,
        password: Password,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        if actor.key == target {
            return Err(AuthorityError::Invalid);
        }
        self.apply_account_change(
            actor,
            target,
            AccountChange::Password(password),
            None,
            deadline,
        )
        .await
    }
    pub async fn change_own_password(
        &self,
        actor: AuthenticatedSession,
        current_password: Password,
        new_password: Password,
        source: AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        let key = actor.key;
        let login = self.read_sql(key.tenant, budget.remaining(), move |c| Box::pin(async move {
            crate::session_storage::recheck(c, &actor).await?;
            let name: Option<String> = sqlx::query_scalar("SELECT login_key FROM identity_authority.local_credentials WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
                .bind(key.tenant.to_string()).bind(key.principal.as_uuid()).fetch_optional(c).await?;
            Ok((actor, name))
        })).await?;
        let (actor, login) = login;
        let login = LoginKey::parse(&login.ok_or(AuthorityError::ReauthenticationFailed)?)?;
        let candidate = self
            .verify_password(
                key.tenant,
                login,
                current_password,
                source,
                budget.remaining(),
            )
            .await
            .map_err(|e| {
                if e == AuthorityError::Rejected {
                    AuthorityError::ReauthenticationFailed
                } else {
                    e
                }
            })?;
        if candidate.account() != key {
            return Err(AuthorityError::ReauthenticationFailed);
        }
        self.apply_account_change(
            actor,
            key,
            AccountChange::Password(new_password),
            Some(candidate),
            budget.remaining(),
        )
        .await
    }
    async fn apply_account_change(
        &self,
        actor: AuthenticatedSession,
        target: AccountKey,
        change: AccountChange,
        reauthentication: Option<AuthenticationCandidate>,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.require_runtime()?;
        if actor.key.tenant != target.tenant {
            return Err(AuthorityError::Rejected);
        }
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        if let Some(proof) = &reauthentication {
            budget.0 = budget.0.min(proof.expires);
        }
        if reauthentication.is_none() {
            self.require_administrator(&actor)?;
        }
        let (change, hash) = match change {
            AccountChange::Password(password) => (
                LocalChange::Password,
                Some(budget.password(self.kdf.hash(password)).await?),
            ),
            AccountChange::Enabled(v) => (LocalChange::Enabled(v), None),
            AccountChange::Administrator(v) => (LocalChange::Administrator(v), None),
            AccountChange::Membership(v) => (LocalChange::Membership(v), None),
        };
        self.write_sql(target.tenant, budget.remaining(), move |c| Box::pin(async move {
            let loaded = crate::session_storage::recheck(c, &actor).await?;
            if let Some(proof) = reauthentication {
                if proof.account() != actor.key || target != actor.key { return Err(crate::transaction::reject().into()); }
                current(c, &proof, false).await?;
            } else { loaded.authorize_administration(target.tenant)?; }
            let old = load(c, target).await?.state;
            let (next, action) = if loaded.system_domain {
                let platform = crate::platform::load_platform(c, target).await?;
                let next = platform.change(change, crate::platform::platform_count(c,target.tenant).await?)?.account();
                let action = match change {
                    LocalChange::Enabled(true)=>SecurityAction::AccountEnabled,
                    LocalChange::Enabled(false)=>SecurityAction::AccountDisabled,
                    LocalChange::Membership(true)=>SecurityAction::MembershipEnabled,
                    LocalChange::Membership(false)=>SecurityAction::MembershipDisabled,
                    LocalChange::Password=>SecurityAction::PasswordChanged,
                    LocalChange::Administrator(_)=>return Err(rss_identity_core::platform::PlatformError::Invalid.into()),
                };
                (next, action)
            } else { old.change(&loaded.state, change, admin_count(c, target.tenant).await?)? };
            sqlx::query("UPDATE identity_authority.accounts SET enabled=$3,administrator=$4,emergency=emergency AND $4,auth_epoch=$5 WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
                .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(next.enabled()).bind(next.administrator()).bind(next.epoch()).execute(&mut *c).await?;
            if let Some(hash) = hash {
                sqlx::query("UPDATE identity_authority.local_credentials SET password_hash=$3 WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
                    .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(hash.as_str()).execute(&mut *c).await?;
            }
            sqlx::query("UPDATE identity_authority.memberships SET active=$3,epoch=$4 WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
                .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(next.member_active()).bind(next.membership_epoch()).execute(&mut *c).await?;
            Ok((next, vec![SecurityEvent::account(action, next, Some(actor.key))]))
        })).await
    }
    pub(crate) fn require_administrator(
        &self,
        actor: &AuthenticatedSession,
    ) -> Result<(), AuthorityError> {
        self.require_runtime()?;
        // Early resource rejection only; every SQL operation must still recheck current authority.
        if !(if actor.key.tenant == self.system_domain {
            actor.identity.platform_administrator
        } else {
            actor.identity.administrator
        }) {
            return Err(AuthorityError::RuleRejected(
                rss_identity_core::account::AccountRuleError::InsufficientPrivilege,
            ));
        }
        Ok(())
    }
    pub async fn list_accounts(
        &self,
        actor: AuthenticatedSession,
        cursor: Option<PrincipalId>,
        limit: u16,
        deadline: OperationDeadline,
    ) -> Result<AccountPage, AuthorityError> {
        self.require_runtime()?;
        if !(1..=100).contains(&limit) {
            return Err(AuthorityError::Invalid);
        }
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        self.read_sql(actor.key.tenant, budget.remaining(), move |c| Box::pin(async move {
            crate::session_storage::recheck(c, &actor).await?.authorize_administration(actor.key.tenant)?;
            let rows:Vec<(uuid::Uuid,Option<String>)>=sqlx::query_as("SELECT a.principal_id,l.login_key FROM identity_authority.accounts a LEFT JOIN identity_authority.local_credentials l USING(tenant_id,principal_id) WHERE a.tenant_id=$1::uuid AND ($2::uuid IS NULL OR a.principal_id>$2) ORDER BY a.principal_id LIMIT $3")
                .bind(actor.key.tenant.to_string()).bind(cursor.map(|id|id.as_uuid())).bind(i64::from(limit)+1).fetch_all(&mut *c).await?;
            let more=rows.len()>usize::from(limit); let mut accounts=Vec::new();
            for (id,login) in rows.into_iter().take(usize::from(limit)) {
                let principal=principal(&id.to_string())?;
                let state=load(c,AccountKey{tenant:actor.key.tenant,principal}).await?.state;
                accounts.push(AccountView::new(state,login));
            }
            let next_cursor=if more {accounts.last().map(|a|a.principal_id.clone())} else {None};
            Ok(AccountPage{accounts,next_cursor})
        })).await
    }
}

#[derive(Debug, Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalAccountRole {
    Member,
    Administrator,
    Emergency,
}
impl LocalAccountRole {
    fn flags(self) -> (bool, bool) {
        match self {
            Self::Member => (false, false),
            Self::Administrator => (true, false),
            Self::Emergency => (true, true),
        }
    }
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct AccountView {
    pub principal_id: String,
    pub login: Option<String>,
    pub enabled: bool,
    pub administrator: bool,
    pub emergency: bool,
    pub member_active: bool,
    pub has_local_password: bool,
}
impl AccountView {
    pub fn new(state: AccountState, login: Option<String>) -> Self {
        Self {
            principal_id: state.key().principal.as_uuid().to_string(),
            login,
            enabled: state.enabled(),
            administrator: state.administrator(),
            emergency: state.emergency(),
            member_active: state.member_active(),
            has_local_password: state.has_local_password(),
        }
    }
}
#[derive(Debug, serde::Serialize)]
pub struct AccountPage {
    pub accounts: Vec<AccountView>,
    pub next_cursor: Option<String>,
}
