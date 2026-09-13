//! Central session v1 response projections. Bearer secrets only travel in Set-Cookie.
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub struct Identity {
    pub principal_id: String,
    pub administrator: bool,
    pub platform_administrator: bool,
    pub has_local_password: bool,
}
#[derive(Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub auth_time: i64,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
}
#[derive(Serialize, Deserialize)]
pub struct Issued {
    pub identity: Identity,
    pub session: SessionInfo,
    pub csrf_token: String,
}

/// Normalized facts from the current checked session, never an authorization decision.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationFacts {
    pub auth_time: i64,
    pub acr: crate::Acr,
    pub amr: Vec<crate::Amr>,
}

/// A current subject's eligible provider, not a promise that the remote IdP is available.
#[derive(Debug, Serialize, Deserialize)]
pub struct StepUpProvider {
    pub provider_id: uuid::Uuid,
    pub label: String,
}

/// A no-store browser snapshot bound to one current session.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionSecurity {
    pub session_id: String,
    pub authentication: AuthenticationFacts,
    pub eligible_step_up_providers: Vec<StepUpProvider>,
}
