use crate::{storage::*, transaction::SecurityEvent, *};
use rss_identity_core::account::{LocalChange, SecurityAction};
use rss_identity_core::{
    PrincipalId,
    account::{LoginKey, Password},
};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;

impl Authority {
    /// Verify credentials and issue a session only after the atomic security event commits.
    pub async fn login_local(
        &self,
        tenant: TenantId,
        login: LoginKey,
        password: Password,
        source: AttemptSource,
        replacement: Option<AuthenticatedSession>,
        deadline: OperationDeadline,
    ) -> Result<IssuedSession, AuthorityError> {
        let budget = Budget::new(deadline)?;
        let candidate =
            Box::pin(self.verify_password(tenant, login, password, source, budget.remaining()))
                .await?;
        Box::pin(self.create_session(candidate, replacement, budget.remaining())).await
    }

    pub(crate) async fn verify_password(
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
                        current(c, &candidate).await?;
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
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.require_runtime()?;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);

        let hash = budget.password(self.kdf.hash(password)).await?;
        let key = AccountKey {
            tenant: actor.key.tenant,
            principal: PrincipalId::generate(),
        };
        let policy = self.policy.clone();
        let instance = self.instance;
        self.write_sql(key.tenant, budget.remaining(), move |c| {
            Box::pin(async move {
                let loaded = crate::session_storage::recheck(c, &actor).await?;
                crate::management::authorize(
                    policy.as_ref(),
                    instance,
                    &loaded,
                    ManagementOperation::CreateAccount,
                    Some(key),
                )?;
                insert_account(c, key, login.as_str(), hash.as_str()).await?;
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
        let (actor, login) = self.local_login_key(actor, budget.remaining()).await?;
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
    /// Password reauthentication rotates only the currently authenticated account's session.
    pub async fn reauthenticate_local(
        &self,
        actor: AuthenticatedSession,
        password: Password,
        source: AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<IssuedSession, AuthorityError> {
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        let key = actor.key;
        let (actor, login) = self.local_login_key(actor, budget.remaining()).await?;
        Box::pin(self.login_local(
            key.tenant,
            login,
            password,
            source,
            Some(actor),
            budget.remaining(),
        ))
        .await
    }
    async fn local_login_key(
        &self,
        actor: AuthenticatedSession,
        deadline: OperationDeadline,
    ) -> Result<(AuthenticatedSession, LoginKey), AuthorityError> {
        let key = actor.key;
        let (actor, name) = self.read_sql(key.tenant, deadline, move |c|Box::pin(async move {
            crate::session_storage::recheck(c,&actor).await?;
            let name:Option<String> = sqlx::query_scalar("SELECT login_key FROM identity_authority.local_credentials WHERE tenant_id=$1::uuid AND principal_id=$2")
                .bind(key.tenant.to_string()).bind(key.principal.as_uuid()).fetch_optional(c).await?;
            Ok((actor,name))
        })).await?;
        let login = LoginKey::parse(&name.ok_or(AuthorityError::ReauthenticationFailed)?)?;
        Ok((actor, login))
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
        let (change, hash) = match change {
            AccountChange::Password(password) => (
                LocalChange::Password,
                Some(budget.password(self.kdf.hash(password)).await?),
            ),
            AccountChange::Enabled(v) => (LocalChange::Enabled(v), None),
            AccountChange::Membership(v) => (LocalChange::Membership(v), None),
        };
        let policy = self.policy.clone();
        let instance = self.instance;
        let operation = match change {
            LocalChange::Password => ManagementOperation::ResetPassword,
            LocalChange::Enabled(v) => ManagementOperation::SetAccountEnabled(v),
            LocalChange::Membership(v) => ManagementOperation::SetMembership(v),
        };
        self.write_sql(target.tenant, budget.remaining(), move |c| Box::pin(async move {
            let loaded = crate::session_storage::recheck(c, &actor).await?;
            if let Some(proof) = reauthentication {
                if proof.account() != actor.key || target != actor.key { return Err(crate::transaction::reject().into()); }
                current(c, &proof).await?;
            } else { crate::management::authorize(policy.as_ref(),instance,&loaded,operation,Some(target))?; }
            let old = load(c, target).await?.state;
            let (next, action) = old.change(change)?;
            sqlx::query("UPDATE identity_authority.accounts SET enabled=$3,auth_epoch=$4 WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
                .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(next.enabled()).bind(next.epoch()).execute(&mut *c).await?;
            if let Some(hash) = hash {
                sqlx::query("UPDATE identity_authority.local_credentials SET password_hash=$3 WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
                    .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(hash.as_str()).execute(&mut *c).await?;
            }
            sqlx::query("UPDATE identity_authority.memberships SET active=$3,epoch=$4 WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
                .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(next.member_active()).bind(next.membership_epoch()).execute(&mut *c).await?;
            Ok((next, vec![SecurityEvent::account(action, next, Some(actor.key))]))
        })).await
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
        let policy = self.policy.clone();
        let instance = self.instance;
        self.read_sql(actor.key.tenant, budget.remaining(), move |c| Box::pin(async move {
            let loaded = crate::session_storage::recheck(c, &actor).await?;
            crate::management::authorize(policy.as_ref(),instance,&loaded,ManagementOperation::ListAccounts,None)?;
            let rows:Vec<(uuid::Uuid,Option<String>)>=sqlx::query_as("SELECT a.principal_id,l.login_key FROM identity_authority.accounts a LEFT JOIN identity_authority.local_credentials l USING(tenant_id,principal_id) WHERE a.tenant_id=$1::uuid AND ($2::uuid IS NULL OR a.principal_id>$2) ORDER BY a.principal_id LIMIT $3")
                .bind(actor.key.tenant.to_string()).bind(cursor.map(|id|id.as_uuid())).bind(i64::from(limit)+1).fetch_all(&mut *c).await?;
            let more=rows.len()>usize::from(limit); let mut accounts=Vec::new();
            for (id,login) in rows.into_iter().take(usize::from(limit)) {
                let principal=principal(&id.to_string())?;
                let state=load(c,AccountKey{tenant:actor.key.tenant,principal}).await?.state;
                accounts.push(AccountView::new(state,login));
            }
            let next_cursor=if more {accounts.last().map(|a|a.principal_id)} else {None};
            Ok(AccountPage{accounts,next_cursor})
        })).await
    }
}

#[derive(Debug, Clone)]
pub struct AccountView {
    pub principal_id: PrincipalId,
    pub login: Option<String>,
    pub enabled: bool,
    pub member_active: bool,
    pub has_local_password: bool,
}
impl AccountView {
    pub fn new(state: AccountState, login: Option<String>) -> Self {
        Self {
            principal_id: state.key().principal,
            login,
            enabled: state.enabled(),
            member_active: state.member_active(),
            has_local_password: state.has_local_password(),
        }
    }
}
/// Domain results are mapped to wire DTOs by the hosting adapter.
/// ```compile_fail
/// fn serialize(page: rss_identity_postgres::AccountPage) { let _ = serde_json::to_value(page); }
/// ```
#[derive(Debug)]
pub struct AccountPage {
    pub accounts: Vec<AccountView>,
    pub next_cursor: Option<PrincipalId>,
}
