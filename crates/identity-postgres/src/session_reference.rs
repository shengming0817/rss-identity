//! Durable host-owned session references, distinct from authentication credentials.
use crate::{
    AccountKey, AuthenticatedSession, Authority, AuthorityError, SessionIdentity, SessionView,
    VerifiedDepartmentSnapshot, VerifiedGroups, session_storage as db,
    sessions::checked_expiry,
    storage::{authority_id, lock_guard},
    transaction::{connection, reject},
    types::Budget,
};
use rss_identity_core::{InstanceId, PrincipalId, SessionId};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use uuid::Uuid;

/// Persist only in trusted host storage after authenticating the original request.
/// This locator is not a bearer credential: no login or management operation accepts it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionReference {
    instance: Uuid,
    tenant: Uuid,
    principal: Uuid,
    session: Uuid,
}

impl AuthenticatedSession {
    /// Retain the exact session without retaining its secret or credential digest.
    pub fn reference(&self) -> Result<SessionReference, AuthorityError> {
        self.assurance()?;
        Ok(SessionReference {
            instance: self.authority,
            tenant: Uuid::parse_str(&self.key.tenant.to_string()).expect("validated tenant"),
            principal: self.key.principal.as_uuid(),
            session: self.view.id.as_uuid(),
        })
    }
}

/// Fresh, bounded identity facts for an existing host-owned operation.
/// Deliberately cannot be used where `AuthenticatedSession` is required.
pub struct RevalidatedSession {
    reference: SessionReference,
    identity: SessionIdentity,
    view: SessionView,
    expires: Instant,
    assurance: rss_identity_core::assurance::Assurance,
    groups: crate::groups::GroupFacts,
    department: Box<crate::department::DepartmentFacts>,
}
impl RevalidatedSession {
    pub fn check_live(&self) -> Result<(), AuthorityError> {
        if Instant::now() >= self.expires {
            Err(AuthorityError::Rejected)
        } else {
            Ok(())
        }
    }
    pub fn instance(&self) -> InstanceId {
        InstanceId::parse(&self.reference.instance.to_string()).expect("validated instance")
    }
    pub fn account(&self) -> AccountKey {
        AccountKey {
            tenant: TenantId::parse(&self.reference.tenant.to_string()).expect("validated tenant"),
            principal: PrincipalId::parse(&self.reference.principal.to_string())
                .expect("validated principal"),
        }
    }
    pub fn identity(&self) -> &SessionIdentity {
        &self.identity
    }
    pub fn view(&self) -> &SessionView {
        &self.view
    }
    pub fn assurance(&self) -> Result<&rss_identity_core::assurance::Assurance, AuthorityError> {
        self.check_live()?;
        Ok(&self.assurance)
    }
    pub fn groups(&self) -> Result<VerifiedGroups<'_>, crate::GroupAccessError> {
        self.groups.view(self.expires)
    }
    pub fn department_snapshot(
        &self,
    ) -> Result<VerifiedDepartmentSnapshot<'_>, crate::DepartmentAccessError> {
        self.department
            .view(self.instance(), self.account(), self.expires)
    }
}
impl std::fmt::Debug for RevalidatedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RevalidatedSession(<private>)")
    }
}

impl Authority {
    /// Recheck an authenticated request's stored locator; never renew session idle.
    /// Hosts must not accept locators from an untrusted caller as authentication.
    pub async fn recheck_session_reference(
        &self,
        tenant: TenantId,
        reference: &SessionReference,
        deadline: OperationDeadline,
    ) -> Result<RevalidatedSession, AuthorityError> {
        self.require_runtime()?;
        if reference.instance != self.instance().as_uuid()
            || reference.tenant.to_string() != tenant.to_string()
            || reference.principal.is_nil()
            || reference.session.is_nil()
        {
            return Err(AuthorityError::Rejected);
        }
        let budget = Budget::new(deadline)?;
        let reference = reference.clone();
        let key = AccountKey {
            tenant,
            principal: PrincipalId::parse(&reference.principal.to_string())
                .map_err(|_| AuthorityError::Rejected)?,
        };
        let session = SessionId::parse(&reference.session.to_string())
            .map_err(|_| AuthorityError::Rejected)?;
        self.read(tenant, budget.remaining(), move |tx| {
            Box::pin(async move {
                connection(tx, move |c| {
                    Box::pin(async move {
                        lock_guard(c, tenant).await?;
                        if authority_id(c).await? != reference.instance {
                            return Err(reject());
                        }
                        let loaded = db::by_id(c, key, session).await?;
                        let expires = checked_expiry(&loaded, budget.0)?;
                        Ok(RevalidatedSession {
                            reference,
                            identity: SessionIdentity::from_state(loaded.state),
                            view: loaded.view,
                            expires,
                            assurance: loaded.assurance,
                            groups: loaded.groups,
                            department: loaded.department_snapshot,
                        })
                    })
                })
                .await
            })
        })
        .await
    }
}
