//! Federation application service. One injected upstream port and the existing PG settlement owner.
use crate::{
    federation_storage as db,
    storage::*,
    transaction::{SecurityEvent, reject},
    *,
};
use rss_identity_core::federation::*;
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;
#[derive(Clone)]
pub struct Federation {
    pub(crate) authority: Authority,
    pub(crate) oidc: Arc<dyn UpstreamOidc>,
    pub(crate) signer: Arc<StateSigner>,
    targets: Arc<BTreeMap<(String, String), String>>,
}
/// Browser input plus transport attribution; the optional replacement is an authority-issued proof.
pub struct LoginRequest {
    pub tenant: TenantId,
    pub provider: ProviderId,
    pub browser: String,
    pub client: String,
    pub target: String,
    pub replacement: Option<AuthenticatedSession>,
    pub source: AttemptSource,
}
/// Linking always starts from an authority-issued session proof.
pub struct LinkRequest {
    pub actor: AuthenticatedSession,
    pub target_provider: ProviderId,
    pub password: Option<rss_identity_core::account::Password>,
    pub browser: String,
    pub client: String,
    pub target: String,
    pub source: AttemptSource,
}
/// A confirmed persisted attempt; the URL contains secrets and has no Debug implementation.
pub struct FederatedRedirect {
    pub url: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkResult {
    Linked,
    AlreadyLinked,
}
impl LinkResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linked => "linked",
            Self::AlreadyLinked => "already_linked",
        }
    }
}
pub enum FederatedOutcome {
    Redirect(FederatedRedirect),
    Session {
        issued: IssuedSession,
        return_url: String,
        link_result: Option<LinkResult>,
    },
}
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    ProviderCreated,
    ProviderUpdated,
    ProviderEnabled,
    ProviderDisabled,
    ProviderTested,
    ProviderTestFailed,
    JitCreated,
    LoggedIn,
    Linked,
    AlreadyLinked,
    Reauthenticated,
}
#[derive(Serialize)]
pub(crate) struct FederationEvent {
    pub tenant: String,
    action: Action,
    provider_id: ProviderId,
    config_version: i64,
    principal: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<ProviderFailure>,
}
pub(crate) fn event(
    tenant: TenantId,
    action: Action,
    provider: &ProviderView,
    principal: Option<rss_identity_core::PrincipalId>,
) -> SecurityEvent {
    SecurityEvent::Federation(FederationEvent {
        tenant: tenant.to_string(),
        action,
        provider_id: provider.id,
        config_version: provider.version,
        principal: principal.map(|p| p.as_uuid()),
        diagnostic: None,
    })
}
impl Federation {
    pub fn new(
        authority: Authority,
        oidc: Arc<dyn UpstreamOidc>,
        signer: StateSigner,
        targets: BTreeMap<(String, String), String>,
    ) -> Result<Self, AuthorityError> {
        authority.require_runtime()?;
        if targets.is_empty() || targets.len() > 128 {
            return Err(FederationError::Configuration.into());
        }
        for ((client, id), target) in &targets {
            let url = url::Url::parse(target).map_err(|_| FederationError::Configuration)?;
            if client.is_empty()
                || client.len() > 128
                || id.is_empty()
                || id.len() > 128
                || target.len() > 2048
                || url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || url.query_pairs().any(|(k, _)| k == "identity_result")
            {
                return Err(FederationError::Configuration.into());
            }
        }
        Ok(Self {
            authority,
            oidc,
            signer: Arc::new(signer),
            targets: Arc::new(targets),
        })
    }
    pub fn authority(&self) -> Authority {
        self.authority.clone()
    }
    pub(crate) fn target(&self, client: &str, id: &str) -> Result<String, AuthorityError> {
        self.targets
            .get(&(client.into(), id.into()))
            .cloned()
            .ok_or(FederationError::Configuration.into())
    }
    pub(crate) fn allowed_return(&self, client: &str, url: &str) -> bool {
        self.targets
            .iter()
            .any(|((c, _), u)| c == client && u == url)
    }
    pub(crate) async fn upstream<T>(
        &self,
        budget: &Budget,
        future: UpstreamFuture<'_, T>,
    ) -> Result<T, AuthorityError> {
        tokio::time::timeout_at(budget.0.into(), future)
            .await
            .map_err(|_| AuthorityError::Federation(FederationError::Unavailable))?
            .map_err(Into::into)
    }
}

impl Authority {
    pub(crate) async fn create_provider(
        &self,
        actor: AuthenticatedSession,
        settings: ProviderSettings,
        deadline: OperationDeadline,
    ) -> Result<ProviderView, AuthorityError> {
        self.require_runtime()?;
        let tenant = actor.key.tenant;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        self.write_sql(tenant,budget.remaining(),move |c| { Box::pin(async move {
                    lock_guard(c, tenant).await?;
                    crate::session_storage::recheck(c, &actor).await?.state.authorize_administration(tenant)?;
                    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_authority.providers WHERE tenant_id=$1::uuid")
                        .bind(tenant.to_string()).fetch_one(&mut *c).await?;
                    if count >= 100 { return Err(FederationError::ProviderLimitReached.into()); }
                    let view = ProviderView {
                        id: ProviderId::generate(),
                        version: 1,
                        enabled: false,
                        revocation_epoch: 1,
                        settings,
                    };
                    sqlx::query("INSERT INTO identity_authority.providers(tenant_id,provider_id,config_version,revocation_epoch,enabled,settings) VALUES($1::uuid,$2::uuid,1,1,false,$3)")
                        .bind(tenant.to_string())
                        .bind(view.id.to_string())
                        .bind(serde_json::to_value(&view.settings).map_err(|_| transaction::corrupt())?)
                        .execute(c)
                        .await?;
                    let audit = event(
                        tenant,
                        Action::ProviderCreated,
                        &view,
                        Some(actor.key.principal),
                    );
                    Ok((view, vec![audit]))
                }) }).await
    }
    pub(crate) async fn update_provider(
        &self,
        actor: AuthenticatedSession,
        id: ProviderId,
        expected_version: i64,
        settings: ProviderSettings,
        deadline: OperationDeadline,
    ) -> Result<ProviderView, AuthorityError> {
        self.require_runtime()?;
        self.edit_provider(actor, id, expected_version, Some(settings), None, deadline)
            .await
    }
    pub(crate) async fn enable_provider(
        &self,
        actor: AuthenticatedSession,
        id: ProviderId,
        expected_version: i64,
        enabled: bool,
        deadline: OperationDeadline,
    ) -> Result<ProviderView, AuthorityError> {
        self.require_runtime()?;
        self.edit_provider(actor, id, expected_version, None, Some(enabled), deadline)
            .await
    }
    async fn edit_provider(
        &self,
        actor: AuthenticatedSession,
        id: ProviderId,
        expected: i64,
        settings: Option<ProviderSettings>,
        enabled: Option<bool>,
        deadline: OperationDeadline,
    ) -> Result<ProviderView, AuthorityError> {
        let tenant = actor.key.tenant;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        self.write_sql(tenant,budget.remaining(),move |c| { Box::pin(async move {
                    lock_guard(c, tenant).await?;
                    crate::session_storage::recheck(c, &actor).await?.state.authorize_administration(tenant)?;
                    let mut view = db::provider(c, tenant, id).await?;
                    if view.version != expected {
                        return Err(FederationError::StaleConfiguration.into());
                    }
                    let action = if let Some(settings) = settings {
                        if settings.issuer() != view.settings.issuer() {
                            return Err(FederationError::Configuration.into());
                        }
                        view.settings = settings;
                        Action::ProviderUpdated
                    } else if let Some(enabled) = enabled {
                        if view.enabled && !enabled {
                            view.revocation_epoch = view
                                .revocation_epoch
                                .checked_add(1)
                                .ok_or(FederationError::Rejected)?;
                        }
                        view.enabled = enabled;
                        if enabled {
                            Action::ProviderEnabled
                        } else {
                            Action::ProviderDisabled
                        }
                    } else {
                        return Err(reject().into());
                    };
                    view.version = view
                        .version
                        .checked_add(1)
                        .ok_or(FederationError::Rejected)?;
                    sqlx::query(concat!(
                        "UPDATE identity_authority.providers SET settings=$3,config_version=$4,enabled=$5",
                        ",revocation_epoch=$6 WHERE tenant_id=$1::uuid AND provider_id=$2::uuid"
                    ))
                    .bind(tenant.to_string())
                    .bind(id.to_string())
                    .bind(serde_json::to_value(&view.settings).map_err(|_| transaction::corrupt())?)
                    .bind(view.version)
                    .bind(view.enabled)
                    .bind(view.revocation_epoch)
                    .execute(c)
                    .await?;
                    let audit = event(tenant, action, &view, Some(actor.key.principal));
                    Ok((view, vec![audit]))
                }) }).await
    }
    pub(crate) async fn list_providers(
        &self,
        actor: AuthenticatedSession,
        deadline: OperationDeadline,
    ) -> Result<Vec<ProviderView>, AuthorityError> {
        self.require_runtime()?;
        let tenant = actor.key.tenant;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        self.read_sql(tenant,budget.remaining(),move |c| { Box::pin(async move {
                    lock_guard(c, tenant).await?;
                    crate::session_storage::recheck(c, &actor).await?.state.authorize_administration(tenant)?;
                    let ids: Vec<Uuid> = sqlx::query_scalar(concat!(
                        "SELECT provider_id FROM identity_authority.providers WHERE tenant_id=$1::uuid OR",
                        "DER BY provider_id LIMIT 101"
                    ))
                    .bind(tenant.to_string())
                    .fetch_all(&mut *c)
                    .await?;
                    if ids.len() > 100 {
                        return Err(FederationError::ProviderLimitReached.into());
                    }
                    let mut result = vec![];
                    for id in ids {
                        result.push(
                            db::provider(
                                c,
                                tenant,
                                ProviderId::parse(&id.to_string()).map_err(|_| transaction::corrupt())?,
                            )
                            .await?,
                        );
                    }
                    Ok(result)
                }) }).await
    }
    pub(crate) async fn test_provider<F>(
        &self,
        actor: AuthenticatedSession,
        id: ProviderId,
        test: F,
        deadline: OperationDeadline,
    ) -> Result<ConnectionReport, AuthorityError>
    where
        F: FnOnce(TenantId, ProviderSettings) -> UpstreamFuture<'static, ConnectionReport>,
    {
        self.require_runtime()?;
        let tenant = actor.key.tenant;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        let (actor, view) = self
            .read_sql(tenant, budget.remaining(), move |c| {
                Box::pin(async move {
                    lock_guard(c, tenant).await?;
                    crate::session_storage::recheck(c, &actor)
                        .await?
                        .state
                        .authorize_administration(tenant)?;
                    Ok((actor, db::provider(c, tenant, id).await?))
                })
            })
            .await?;
        // Cancel upstream work before the shared deadline: permission/version checks and
        // the security event must settle before any report is released.
        let remaining = budget.remaining().timeout();
        let reserve = (remaining / 4).min(std::time::Duration::from_secs(1));
        let upstream_deadline = budget.0 - reserve;
        let result = tokio::time::timeout_at(
            upstream_deadline.into(),
            test(tenant, view.settings.clone()),
        )
        .await
        .unwrap_or(Err(FederationError::Unavailable));
        let diagnostic = result.as_ref().err().map(|e| e.diagnostic());
        let passed = result.is_ok();
        self.write_sql(tenant, budget.remaining(), move |c| {
            Box::pin(async move {
                lock_guard(c, tenant).await?;
                crate::session_storage::recheck(c, &actor)
                    .await?
                    .state
                    .authorize_administration(tenant)?;
                let current = db::provider(c, tenant, id).await?;
                if current.version != view.version {
                    return Err(FederationError::StaleConfiguration.into());
                }
                let audit = SecurityEvent::Federation(FederationEvent {
                    tenant: tenant.to_string(),
                    action: if passed {
                        Action::ProviderTested
                    } else {
                        Action::ProviderTestFailed
                    },
                    provider_id: view.id,
                    config_version: view.version,
                    principal: Some(actor.key.principal.as_uuid()),
                    diagnostic,
                });
                Ok(((), vec![audit]))
            })
        })
        .await?;
        result.map_err(Into::into)
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    #[test]
    fn action_vocabulary_and_payload_match_schema() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("federation-security-event-v1.json")).unwrap();
        let actions = [
            Action::ProviderCreated,
            Action::ProviderUpdated,
            Action::ProviderEnabled,
            Action::ProviderDisabled,
            Action::ProviderTested,
            Action::ProviderTestFailed,
            Action::JitCreated,
            Action::LoggedIn,
            Action::Linked,
            Action::AlreadyLinked,
            Action::Reauthenticated,
        ];
        let values: Vec<_> = actions
            .into_iter()
            .map(|a| serde_json::to_value(a).unwrap())
            .collect();
        assert_eq!(
            values,
            *schema["properties"]["action"]["enum"].as_array().unwrap()
        );
        let event = FederationEvent {
            tenant: Uuid::new_v4().to_string(),
            action: Action::ProviderTestFailed,
            provider_id: ProviderId::generate(),
            config_version: 1,
            principal: None,
            diagnostic: Some(ProviderFailure {
                stage: ProviderStage::Discovery,
                reason: ProviderReason::Unavailable,
            }),
        };
        let event = serde_json::to_value(event).unwrap();
        for key in schema["required"].as_array().unwrap() {
            assert!(event.get(key.as_str().unwrap()).is_some());
        }
        assert!(
            event
                .as_object()
                .unwrap()
                .keys()
                .all(|k| schema["properties"].get(k).is_some())
        );
        for key in ["stage", "reason"] {
            assert!(
                schema["properties"]["diagnostic"]["properties"][key]["enum"]
                    .as_array()
                    .unwrap()
                    .contains(&event["diagnostic"][key])
            );
        }
    }
}

impl Federation {
    pub async fn create_provider(
        &self,
        actor: AuthenticatedSession,
        settings: ProviderSettings,
        deadline: OperationDeadline,
    ) -> Result<ProviderView, AuthorityError> {
        self.authority.require_administrator(&actor)?;
        self.oidc
            .approve_configuration(actor.key.tenant, &settings)?;
        self.authority
            .create_provider(actor, settings, deadline)
            .await
    }
    pub async fn update_provider(
        &self,
        actor: AuthenticatedSession,
        id: ProviderId,
        expected_version: i64,
        settings: ProviderSettings,
        deadline: OperationDeadline,
    ) -> Result<ProviderView, AuthorityError> {
        self.authority.require_administrator(&actor)?;
        self.oidc
            .approve_configuration(actor.key.tenant, &settings)?;
        self.authority
            .update_provider(actor, id, expected_version, settings, deadline)
            .await
    }
    pub async fn enable_provider(
        &self,
        actor: AuthenticatedSession,
        id: ProviderId,
        expected_version: i64,
        enabled: bool,
        deadline: OperationDeadline,
    ) -> Result<ProviderView, AuthorityError> {
        self.authority
            .enable_provider(actor, id, expected_version, enabled, deadline)
            .await
    }
    pub async fn list_providers(
        &self,
        actor: AuthenticatedSession,
        deadline: OperationDeadline,
    ) -> Result<Vec<ProviderView>, AuthorityError> {
        self.authority.list_providers(actor, deadline).await
    }
    pub async fn test_provider(
        &self,
        actor: AuthenticatedSession,
        id: ProviderId,
        deadline: OperationDeadline,
    ) -> Result<ConnectionReport, AuthorityError> {
        let oidc = self.oidc.clone();
        self.authority
            .test_provider(
                actor,
                id,
                move |tenant, settings| Box::pin(async move { oidc.test(tenant, &settings).await }),
                deadline,
            )
            .await
    }
    pub async fn login_options(
        &self,
        tenant: TenantId,
        deadline: OperationDeadline,
    ) -> Result<Vec<LoginOption>, AuthorityError> {
        self.authority.read_sql(tenant,deadline,move |c|Box::pin(async move {
            let rows:Vec<(Uuid,serde_json::Value)>=sqlx::query_as("SELECT provider_id,settings FROM identity_authority.providers WHERE tenant_id=$1::uuid AND enabled ORDER BY provider_id LIMIT 101").bind(tenant.to_string()).fetch_all(c).await?;
            if rows.len()>100 {return Err(reject().into());}
            rows.into_iter().map(|(id,value)|{
                let settings:ProviderSettings=serde_json::from_value(value).map_err(|_|crate::transaction::corrupt())?;
                let issuer=url::Url::parse(settings.issuer().as_str()).map_err(|_|crate::transaction::corrupt())?;
                Ok(LoginOption{provider_id:id,label:format!("{} · {} · {}", issuer.as_str(), settings.client_id().as_str(), id)})
            }).collect()
        })).await
    }
}
#[derive(Serialize)]
pub struct LoginOption {
    pub provider_id: Uuid,
    pub label: String,
}
