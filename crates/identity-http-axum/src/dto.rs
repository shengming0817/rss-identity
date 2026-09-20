//! Private v2 HTTP response projections. Bearer secrets only travel in Set-Cookie.
use serde::Serialize;
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub principal_id: String,
    pub has_local_password: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: String,
    pub auth_time: i64,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Issued {
    pub identity: Identity,
    pub session: SessionInfo,
    pub csrf_token: String,
}

/// Normalized facts from the current checked session, never an authorization decision.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationFacts {
    pub auth_time: Option<i64>,
    pub acr: rss_identity_core::assurance::Acr,
    pub amr: Vec<rss_identity_core::assurance::Amr>,
}

/// A current subject's eligible provider, not a promise that the remote IdP is available.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepUpProvider {
    pub provider_id: uuid::Uuid,
    pub label: String,
}

/// A no-store browser snapshot bound to one current session.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
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
                auth_time: value.assurance.auth_time(),
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    principal_id: String,
    login: Option<String>,
    enabled: bool,
    member_active: bool,
    has_local_password: bool,
}
impl From<rss_identity_postgres::AccountView> for Account {
    fn from(v: rss_identity_postgres::AccountView) -> Self {
        Self {
            principal_id: v.principal_id.as_uuid().to_string(),
            login: v.login,
            enabled: v.enabled,
            member_active: v.member_active,
            has_local_password: v.has_local_password,
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountPage {
    accounts: Vec<Account>,
    next_cursor: Option<String>,
}
impl From<rss_identity_postgres::AccountPage> for AccountPage {
    fn from(v: rss_identity_postgres::AccountPage) -> Self {
        Self {
            accounts: v.accounts.into_iter().map(Into::into).collect(),
            next_cursor: v.next_cursor.map(|id| id.as_uuid().to_string()),
        }
    }
}
impl From<&rss_identity_postgres::SessionView> for SessionInfo {
    fn from(v: &rss_identity_postgres::SessionView) -> Self {
        Self {
            id: v.id.to_string(),
            auth_time: v.auth_time,
            idle_expires_at: v.idle_expires_at,
            absolute_expires_at: v.absolute_expires_at,
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPage {
    sessions: Vec<SessionInfo>,
    next_cursor: Option<String>,
}
impl From<rss_identity_postgres::SessionPage> for SessionPage {
    fn from(v: rss_identity_postgres::SessionPage) -> Self {
        Self {
            sessions: v.sessions.iter().map(Into::into).collect(),
            next_cursor: v.next_cursor.map(|id| id.as_uuid().to_string()),
        }
    }
}

#[derive(serde::Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaimMapping {
    email: Option<String>,
    groups: Option<String>,
    department_snapshot: Option<DepartmentSnapshotClaim>,
}
#[derive(serde::Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DepartmentSnapshotClaim {
    claim: String,
    max_age_seconds: i64,
}
#[derive(serde::Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderSettings {
    issuer: String,
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    claims: ClaimMapping,
    jit: bool,
}
impl ProviderSettings {
    pub fn into_domain(
        self,
    ) -> Result<
        rss_identity_core::federation::ProviderSettings,
        rss_identity_core::federation::FederationError,
    > {
        rss_identity_core::federation::ProviderSettingsInput {
            issuer: self.issuer,
            client_id: self.client_id,
            redirect_uri: self.redirect_uri,
            scopes: self.scopes,
            claims: rss_identity_core::federation::ClaimMapping {
                email: self.claims.email,
                groups: self.claims.groups,
                department_snapshot: self
                    .claims
                    .department_snapshot
                    .map(|d| {
                        rss_identity_core::department::DepartmentSnapshotClaim::new(
                            d.claim,
                            d.max_age_seconds,
                        )
                    })
                    .transpose()?,
            },
            jit: self.jit,
        }
        .try_into()
    }
}
impl From<&rss_identity_core::federation::ProviderSettings> for ProviderSettings {
    fn from(v: &rss_identity_core::federation::ProviderSettings) -> Self {
        Self {
            issuer: v.issuer().as_str().into(),
            client_id: v.client_id().as_str().into(),
            redirect_uri: v.redirect_uri().into(),
            scopes: v.scopes().to_vec(),
            claims: ClaimMapping {
                email: v.claims().email.clone(),
                groups: v.claims().groups.clone(),
                department_snapshot: v.claims().department_snapshot.as_ref().map(|d| {
                    DepartmentSnapshotClaim {
                        claim: d.claim().into(),
                        max_age_seconds: d.max_age_seconds(),
                    }
                }),
            },
            jit: v.jit(),
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Provider {
    id: String,
    version: i64,
    enabled: bool,
    revocation_epoch: i64,
    settings: ProviderSettings,
    credential_version: i64,
}
impl From<rss_identity_core::federation::ProviderView> for Provider {
    fn from(v: rss_identity_core::federation::ProviderView) -> Self {
        Self {
            id: v.id.to_string(),
            version: v.version,
            enabled: v.enabled,
            revocation_epoch: v.revocation_epoch,
            settings: (&v.settings).into(),
            credential_version: v.credential_version,
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Providers {
    pub providers: Vec<Provider>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginOptions {
    pub providers: Vec<StepUpProvider>,
}
impl From<rss_identity_postgres::LoginOption> for StepUpProvider {
    fn from(v: rss_identity_postgres::LoginOption) -> Self {
        Self {
            provider_id: v.provider_id,
            label: v.label,
        }
    }
}
fn stage(v: rss_identity_core::federation::ProviderStage) -> &'static str {
    use rss_identity_core::federation::ProviderStage::*;
    match v {
        Binding => "binding",
        Discovery => "discovery",
        Jwks => "jwks",
        Exchange => "exchange",
        Claims => "claims",
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionReport {
    checks: Vec<&'static str>,
    tls_verified: bool,
    authorization_response_issuer: bool,
}
impl From<rss_identity_core::federation::ConnectionReport> for ConnectionReport {
    fn from(v: rss_identity_core::federation::ConnectionReport) -> Self {
        Self {
            checks: v.checks.into_iter().map(stage).collect(),
            tls_verified: v.tls_verified,
            authorization_response_issuer: v.authorization_response_issuer,
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderDiagnostic {
    stage: &'static str,
    reason: &'static str,
}
impl From<rss_identity_core::federation::ProviderFailure> for ProviderDiagnostic {
    fn from(v: rss_identity_core::federation::ProviderFailure) -> Self {
        use rss_identity_core::federation::ProviderReason::*;
        Self {
            stage: stage(v.stage),
            reason: match v.reason {
                InvalidTrustAnchor => "invalid_trust_anchor",
                EgressDenied => "egress_denied",
                TlsRejected => "tls_rejected",
                Unavailable => "unavailable",
                Timeout => "timeout",
                InvalidResponse => "invalid_response",
                IssuerMismatch => "issuer_mismatch",
                IssuerResponseUnsupported => "issuer_response_unsupported",
                CodeRejected => "code_rejected",
                InvalidToken => "invalid_token",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn security_view_preserves_absent_upstream_authentication_time() {
        let value = rss_identity_postgres::SessionSecurity {
            session_id: rss_identity_core::SessionId::generate(),
            assurance: rss_identity_core::assurance::Assurance::new(
                None,
                rss_identity_core::assurance::Acr::Unspecified,
                vec![],
            )
            .unwrap(),
            eligible_step_up_providers: vec![],
        };
        let wire = serde_json::to_value(SessionSecurity::from(value)).unwrap();
        assert_eq!(
            wire["authentication"],
            json!({"authTime":null,"acr":"unspecified","amr":[]})
        );
    }
    #[test]
    fn session_and_provider_diagnostics_have_exact_wire_shapes() {
        assert_eq!(
            serde_json::to_value(Issued {
                identity: Identity {
                    principal_id: "subject".into(),
                    has_local_password: true
                },
                session: SessionInfo {
                    id: "session".into(),
                    auth_time: 1,
                    idle_expires_at: 2,
                    absolute_expires_at: 3
                },
                csrf_token: "csrf".into(),
            })
            .unwrap(),
            json!({"identity":{"principalId":"subject","hasLocalPassword":true},"session":{"id":"session","authTime":1,"idleExpiresAt":2,"absoluteExpiresAt":3},"csrfToken":"csrf"})
        );
        assert_eq!(
            serde_json::to_value(SessionPage {
                sessions: vec![],
                next_cursor: None
            })
            .unwrap(),
            json!({"sessions":[],"nextCursor":null})
        );
        assert_eq!(
            serde_json::to_value(ConnectionReport {
                checks: vec!["binding"],
                tls_verified: true,
                authorization_response_issuer: true
            })
            .unwrap(),
            json!({"checks":["binding"],"tlsVerified":true,"authorizationResponseIssuer":true})
        );
        let id = uuid::Uuid::nil();
        assert_eq!(
            serde_json::to_value(LoginOptions {
                providers: vec![StepUpProvider {
                    provider_id: id,
                    label: "Example".into()
                }]
            })
            .unwrap(),
            json!({"providers":[{"providerId":id,"label":"Example"}]})
        );
    }
    #[test]
    fn provider_department_is_atomic_camel_case_and_optional() {
        let base = json!({"issuer":"https://idp.test","clientId":"client","redirectUri":"https://host.test/api/v2/oidc/callback","scopes":["openid"],"claims":{"email":null,"groups":null},"jit":false});
        let settings = serde_json::from_value::<ProviderSettings>(base.clone())
            .unwrap()
            .into_domain()
            .unwrap();
        let wire = serde_json::to_value(ProviderSettings::from(&settings)).unwrap();
        assert!(wire["claims"].get("departmentSnapshot").unwrap().is_null());
        for field in ["department", "department_snapshot"] {
            let mut legacy = base.clone();
            legacy["claims"][field] = json!(null);
            assert!(serde_json::from_value::<ProviderSettings>(legacy).is_err());
        }
        for department in [
            json!({"claim":"organization_snapshot","maxAgeSeconds":60}),
            json!(null),
        ] {
            let mut input = base.clone();
            input["claims"]["departmentSnapshot"] = department;
            let settings = serde_json::from_value::<ProviderSettings>(input.clone())
                .unwrap()
                .into_domain()
                .unwrap();
            assert_eq!(
                serde_json::to_value(ProviderSettings::from(&settings)).unwrap(),
                input
            );
        }
        for department in [
            json!("organization_snapshot"),
            json!({"claim":"organization_snapshot"}),
            json!({"claim":"organization_snapshot","maxAgeSeconds":0}),
            json!({"claim":"organization_snapshot","max_age_seconds":60}),
            json!({"claim":"email","maxAgeSeconds":60}),
            json!({"claim":"sid","maxAgeSeconds":60}),
        ] {
            let mut input = base.clone();
            input["claims"]["departmentSnapshot"] = department;
            assert!(
                serde_json::from_value::<ProviderSettings>(input)
                    .ok()
                    .and_then(|v| v.into_domain().ok())
                    .is_none()
            );
        }
    }

    #[test]
    fn provider_wire_owns_fields_and_excludes_internal_assurance() {
        let input = json!({"issuer":"https://idp.example.test","clientId":"host","redirectUri":"https://host.example.test/api/v2/oidc/callback","scopes":["openid"],"claims":{"email":null,"groups":"groups","departmentSnapshot":null},"jit":true});
        let settings = serde_json::from_value::<ProviderSettings>(input.clone())
            .unwrap()
            .into_domain()
            .unwrap();
        let provider = rss_identity_core::federation::ProviderView {
            id: rss_identity_core::federation::ProviderId::generate(),
            version: 2,
            enabled: true,
            revocation_epoch: 3,
            settings,
            assurance_profile: [7; 32],
            credential_version: 4,
        };
        let expected = json!({"id":provider.id.to_string(),"version":2,"enabled":true,"revocationEpoch":3,"settings":input,"credentialVersion":4});
        assert_eq!(
            serde_json::to_value(Provider::from(provider)).unwrap(),
            expected
        );
        let mut legacy = input.clone();
        legacy.as_object_mut().unwrap().remove("clientId");
        legacy["client_id"] = json!("host");
        assert!(serde_json::from_value::<ProviderSettings>(legacy).is_err());
        let mut invalid = input;
        invalid["assurance_profile"] = json!([7]);
        assert!(serde_json::from_value::<ProviderSettings>(invalid).is_err());
    }
    #[test]
    fn domain_ids_are_projected_by_the_http_adapter() {
        let principal = rss_identity_core::PrincipalId::generate();
        let page = rss_identity_postgres::AccountPage {
            accounts: vec![rss_identity_postgres::AccountView {
                principal_id: principal,
                login: Some("member".into()),
                enabled: true,
                member_active: true,
                has_local_password: true,
            }],
            next_cursor: Some(principal),
        };
        assert_eq!(
            serde_json::to_value(AccountPage::from(page)).unwrap(),
            json!({"accounts":[{"principalId":principal.as_uuid().to_string(),"login":"member","enabled":true,"memberActive":true,"hasLocalPassword":true}],"nextCursor":principal.as_uuid().to_string()})
        );
    }
}
