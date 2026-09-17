//! Private v2 HTTP response projections. Bearer secrets only travel in Set-Cookie.
use serde::Serialize;
#[derive(Serialize)]
pub struct Identity {
    pub principal_id: String,
    pub has_local_password: bool,
}
#[derive(Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub auth_time: i64,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
}
#[derive(Serialize)]
pub struct Issued {
    pub identity: Identity,
    pub session: SessionInfo,
    pub csrf_token: String,
}

/// Normalized facts from the current checked session, never an authorization decision.
#[derive(Debug, Serialize)]
pub struct AuthenticationFacts {
    pub auth_time: i64,
    pub acr: rss_identity_core::assurance::Acr,
    pub amr: Vec<rss_identity_core::assurance::Amr>,
}

/// A current subject's eligible provider, not a promise that the remote IdP is available.
#[derive(Debug, Serialize)]
pub struct StepUpProvider {
    pub provider_id: uuid::Uuid,
    pub label: String,
}

/// A no-store browser snapshot bound to one current session.
#[derive(Debug, Serialize)]
pub struct SessionSecurity {
    pub session_id: String,
    pub authentication: AuthenticationFacts,
    pub eligible_step_up_providers: Vec<StepUpProvider>,
}

impl From<rss_identity_postgres::SessionSecurity> for SessionSecurity {
    fn from(value: rss_identity_postgres::SessionSecurity) -> Self {
        Self {
            session_id: value.session_id.to_string(),
            authentication: AuthenticationFacts {
                auth_time: value
                    .assurance
                    .auth_time()
                    .expect("authenticated session time"),
                acr: value.assurance.acr(),
                amr: value.assurance.amr().to_vec(),
            },
            eligible_step_up_providers: value
                .eligible_step_up_providers
                .into_iter()
                .map(|v| StepUpProvider {
                    provider_id: v.provider_id,
                    label: v.label,
                })
                .collect(),
        }
    }
}
