//! System-domain operations. ref: Keycloak AdminRoles.java@06f4cad3925fd2cd95dc81d55b58b6d0282a7806.
use crate::{
    session_storage,
    storage::*,
    transaction::{MutationError, SecurityEvent, corrupt},
    *,
};
use rss_identity_core::{
    PrincipalId,
    account::{LoginKey, Password},
    platform::{PlatformAccount, PlatformError},
};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use serde::Serialize;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub struct NewTenantAdministrator {
    pub operation_id: Uuid,
    pub tenant: TenantId,
    pub principal: PrincipalId,
    pub login: LoginKey,
    pub password: Password,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformOperationKind {
    TenantCreated,
    AdministratorAdded,
}
impl PlatformOperationKind {
    fn label(self) -> &'static str {
        match self {
            Self::TenantCreated => "tenant_created",
            Self::AdministratorAdded => "administrator_added",
        }
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct PlatformOperation {
    pub operation_id: Uuid,
    pub kind: PlatformOperationKind,
    pub tenant_id: String,
    pub principal_id: Uuid,
    pub created_at: i64,
}
#[derive(Debug, Clone, Serialize)]
pub struct TenantView {
    pub tenant_id: String,
    pub name: String,
    pub initial_principal_id: Uuid,
}
#[derive(Debug, Serialize)]
pub struct TenantPage {
    pub tenants: Vec<TenantView>,
    pub next_cursor: Option<String>,
}
#[derive(Serialize)]
pub(crate) struct PlatformEvent {
    pub tenant: String,
    pub action: &'static str,
    pub actor: Option<Uuid>,
    pub target_tenant: String,
    pub principal: Uuid,
    pub operation_id: Option<Uuid>,
}
pub(crate) fn event(
    system: TenantId,
    action: &'static str,
    actor: Option<AccountKey>,
    target: AccountKey,
    operation_id: Option<Uuid>,
) -> SecurityEvent {
    SecurityEvent::Platform(PlatformEvent {
        tenant: system.to_string(),
        action,
        actor: actor.map(|v| v.principal.as_uuid()),
        target_tenant: target.tenant.to_string(),
        principal: target.principal.as_uuid(),
        operation_id,
    })
}
pub(crate) async fn system_domain(
    c: &mut PgConnection,
) -> Result<Option<TenantId>, rss_transactional_messaging_postgres::PgError> {
    let id: Option<String> =
        sqlx::query_scalar("SELECT system_domain::text FROM identity_authority.deployment")
            .fetch_one(c)
            .await?;
    id.map(|v| TenantId::parse(&v).map_err(|_| corrupt()))
        .transpose()
}
pub(crate) async fn platform_role(
    c: &mut PgConnection,
    key: AccountKey,
) -> Result<bool, rss_transactional_messaging_postgres::PgError> {
    sqlx::query_scalar("SELECT EXISTS(SELECT FROM identity_authority.platform_administrators p JOIN identity_authority.deployment d ON d.system_domain=p.tenant_id WHERE p.tenant_id=$1::uuid AND p.principal_id=$2)")
        .bind(key.tenant.to_string()).bind(key.principal.as_uuid()).fetch_one(c).await.map_err(Into::into)
}
pub(crate) async fn load_platform(
    c: &mut PgConnection,
    key: AccountKey,
) -> Result<PlatformAccount, MutationError> {
    let system = system_domain(c).await?.ok_or(PlatformError::Forbidden)?;
    let state = load(c, key).await?.state;
    Ok(PlatformAccount::new(
        system,
        state,
        platform_role(c, key).await?,
    )?)
}
pub(crate) async fn platform_count(
    c: &mut PgConnection,
    system: TenantId,
) -> Result<i64, rss_transactional_messaging_postgres::PgError> {
    sqlx::query_scalar("SELECT count(*) FROM identity_authority.platform_administrators p JOIN identity_authority.accounts a USING(tenant_id,principal_id) JOIN identity_authority.memberships m USING(tenant_id,principal_id) JOIN identity_authority.local_credentials l USING(tenant_id,principal_id) WHERE p.tenant_id=$1::uuid AND a.enabled AND m.active")
        .bind(system.to_string()).fetch_one(c).await.map_err(Into::into)
}
pub(crate) async fn recheck_platform(
    c: &mut PgConnection,
    actor: &AuthenticatedSession,
) -> Result<(), MutationError> {
    let loaded = session_storage::recheck(c, actor).await?;
    if !loaded.platform_administrator {
        return Err(PlatformError::Forbidden.into());
    }
    Ok(())
}
fn conflict(e: sqlx::Error) -> MutationError {
    if e.as_database_error()
        .is_some_and(|v| v.code().as_deref() == Some("23505"))
    {
        PlatformError::Conflict.into()
    } else {
        e.into()
    }
}
impl Authority {
    pub fn system_domain(&self) -> TenantId {
        self.system_domain
    }
    fn require_platform(&self, actor: &AuthenticatedSession) -> Result<(), AuthorityError> {
        self.require_runtime()?;
        if actor.key.tenant != self.system_domain || !actor.identity.platform_administrator {
            return Err(PlatformError::Forbidden.into());
        }
        Ok(())
    }
    pub async fn provision_business_tenant(
        &self,
        actor: AuthenticatedSession,
        name: String,
        input: NewTenantAdministrator,
        deadline: OperationDeadline,
    ) -> Result<PlatformOperation, AuthorityError> {
        if name.is_empty()
            || name.len() > 128
            || name.trim() != name
            || name.chars().any(char::is_control)
        {
            return Err(PlatformError::Invalid.into());
        }
        self.add_administrator(actor, Some(name), input, deadline)
            .await
    }
    pub async fn add_business_tenant_administrator(
        &self,
        actor: AuthenticatedSession,
        input: NewTenantAdministrator,
        deadline: OperationDeadline,
    ) -> Result<PlatformOperation, AuthorityError> {
        self.add_administrator(actor, None, input, deadline).await
    }
    async fn add_administrator(
        &self,
        actor: AuthenticatedSession,
        name: Option<String>,
        input: NewTenantAdministrator,
        deadline: OperationDeadline,
    ) -> Result<PlatformOperation, AuthorityError> {
        self.require_platform(&actor)?;
        if input.operation_id.is_nil() || input.tenant == self.system_domain {
            return Err(PlatformError::Invalid.into());
        }
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        let hash = budget.password(self.kdf.hash(input.password)).await?;
        let system = self.system_domain;
        let target = AccountKey {
            tenant: input.tenant,
            principal: input.principal,
        };
        self.write_sql(system,budget.remaining(),move|c|Box::pin(async move {
            recheck_platform(c,&actor).await?;
            let seen:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM identity_authority.platform_operations WHERE tenant_id=$1::uuid AND operation_id=$2)").bind(system.to_string()).bind(input.operation_id).fetch_one(&mut *c).await?;
            if seen { return Err(PlatformError::Conflict.into()); }
            let kind=if let Some(name)=name {
                let count:i64=sqlx::query_scalar("SELECT count(*) FROM identity_authority.tenant_registry WHERE tenant_id=$1::uuid").bind(system.to_string()).fetch_one(&mut *c).await?;
                if count>=127 {return Err(PlatformError::Capacity.into());}
                sqlx::query("INSERT INTO identity_authority.tenant_registry VALUES($1::uuid,$2::uuid,$3,$4)").bind(system.to_string()).bind(input.tenant.to_string()).bind(name).bind(input.principal.as_uuid()).execute(&mut *c).await.map_err(conflict)?;
                sqlx::query("SELECT identity_authority.register_tenant($1::uuid,current_setting('rss.execution_epoch')::bigint)").bind(input.tenant.to_string()).execute(&mut *c).await.map_err(conflict)?;
                PlatformOperationKind::TenantCreated
            } else {
                let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM identity_authority.tenant_registry WHERE tenant_id=$1::uuid AND business_tenant=$2::uuid)").bind(system.to_string()).bind(input.tenant.to_string()).fetch_one(&mut *c).await?;
                if !exists {return Err(PlatformError::NotObserved.into());}
                PlatformOperationKind::AdministratorAdded
            };
            sqlx::query("SELECT identity_authority.insert_tenant_administrator($1::uuid,$2,$3,$4)").bind(input.tenant.to_string()).bind(input.principal.as_uuid()).bind(input.login.as_str()).bind(hash.as_str()).execute(&mut *c).await.map_err(conflict)?;
            let now=session_storage::now(c).await?;
            sqlx::query("INSERT INTO identity_authority.platform_operations VALUES($1::uuid,$2,$3,$4::uuid,$5,$6)").bind(system.to_string()).bind(input.operation_id).bind(kind.label()).bind(input.tenant.to_string()).bind(input.principal.as_uuid()).bind(now).execute(c).await.map_err(conflict)?;
            Ok((PlatformOperation{operation_id:input.operation_id,kind,tenant_id:input.tenant.to_string(),principal_id:input.principal.as_uuid(),created_at:now},vec![event(system,kind.label(),Some(actor.key),target,Some(input.operation_id))]))
        })).await
    }
    pub async fn platform_operation(
        &self,
        actor: AuthenticatedSession,
        id: Uuid,
        deadline: OperationDeadline,
    ) -> Result<PlatformOperation, AuthorityError> {
        self.require_platform(&actor)?;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        let system = self.system_domain;
        self.read_sql(system,budget.remaining(),move|c|Box::pin(async move {
            recheck_platform(c,&actor).await?;
            let r=sqlx::query("SELECT kind,business_tenant::text,principal_id,created_at FROM identity_authority.platform_operations WHERE tenant_id=$1::uuid AND operation_id=$2").bind(system.to_string()).bind(id).fetch_optional(c).await?.ok_or(PlatformError::NotObserved)?;
            let kind=match r.try_get::<String,_>("kind")?.as_str(){"tenant_created"=>PlatformOperationKind::TenantCreated,"administrator_added"=>PlatformOperationKind::AdministratorAdded,_=>return Err(corrupt().into())};
            Ok(PlatformOperation{operation_id:id,kind,tenant_id:r.try_get("business_tenant")?,principal_id:r.try_get("principal_id")?,created_at:r.try_get("created_at")?})
        })).await
    }
    pub async fn list_tenants(
        &self,
        actor: AuthenticatedSession,
        cursor: Option<TenantId>,
        limit: u16,
        deadline: OperationDeadline,
    ) -> Result<TenantPage, AuthorityError> {
        self.require_platform(&actor)?;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        if !(1..=100).contains(&limit) {
            return Err(PlatformError::Invalid.into());
        }
        let system = self.system_domain;
        self.read_sql(system,budget.remaining(),move|c|Box::pin(async move {
            recheck_platform(c,&actor).await?;
            let rows=sqlx::query("SELECT business_tenant::text,name,initial_principal FROM identity_authority.tenant_registry WHERE tenant_id=$1::uuid AND ($2::uuid IS NULL OR business_tenant>$2::uuid) ORDER BY business_tenant LIMIT $3").bind(system.to_string()).bind(cursor.map(|v|v.to_string())).bind(i64::from(limit)+1).fetch_all(c).await?;
            let more=rows.len()>usize::from(limit);
            let tenants=rows.into_iter().take(usize::from(limit)).map(|r|Ok(TenantView{tenant_id:r.try_get("business_tenant")?,name:r.try_get("name")?,initial_principal_id:r.try_get("initial_principal")?})).collect::<Result<Vec<_>,sqlx::Error>>()?;
            let next_cursor=if more {tenants.last().map(|v|v.tenant_id.clone())} else {None};
            Ok(TenantPage{tenants,next_cursor})
        })).await
    }
    pub async fn tenant_detail(
        &self,
        actor: AuthenticatedSession,
        target: TenantId,
        deadline: OperationDeadline,
    ) -> Result<TenantView, AuthorityError> {
        self.require_platform(&actor)?;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        let system = self.system_domain;
        self.read_sql(system,budget.remaining(),move|c|Box::pin(async move{
            recheck_platform(c,&actor).await?;
            let r=sqlx::query("SELECT name,initial_principal FROM identity_authority.tenant_registry WHERE tenant_id=$1::uuid AND business_tenant=$2::uuid").bind(system.to_string()).bind(target.to_string()).fetch_optional(c).await?.ok_or(PlatformError::NotObserved)?;
            Ok(TenantView{tenant_id:target.to_string(),name:r.try_get("name")?,initial_principal_id:r.try_get("initial_principal")?})
        })).await
    }
    pub async fn set_platform_role(
        &self,
        actor: AuthenticatedSession,
        principal: PrincipalId,
        granted: bool,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.require_platform(&actor)?;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        let system = self.system_domain;
        let key = AccountKey {
            tenant: system,
            principal,
        };
        self.write_sql(system,budget.remaining(),move|c|Box::pin(async move {
            recheck_platform(c,&actor).await?;
            let target=load_platform(c,key).await?;
            let next=target.set_role(granted,platform_count(c,system).await?)?.account();
            if granted {sqlx::query("INSERT INTO identity_authority.platform_administrators VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(system.to_string()).bind(principal.as_uuid()).execute(&mut *c).await?;}
            else {sqlx::query("DELETE FROM identity_authority.platform_administrators WHERE tenant_id=$1::uuid AND principal_id=$2").bind(system.to_string()).bind(principal.as_uuid()).execute(&mut *c).await?;}
            sqlx::query("UPDATE identity_authority.accounts SET auth_epoch=$3 WHERE tenant_id=$1::uuid AND principal_id=$2").bind(system.to_string()).bind(principal.as_uuid()).bind(next.epoch()).execute(c).await?;
            Ok((next,vec![event(system,if granted {"platform_role_granted"} else {"platform_role_revoked"},Some(actor.key),key,None)]))
        })).await
    }
}
