//! IdP control plane. Listing and disabling need only PG and actor authentication, not login secrets.
use crate::{budget, login, password, source};
use rss_identity_admin::{AdminError, IdpInputError, read_public_file, read_secret};
use rss_identity_core::federation::*;
use rss_identity_oidc::{ApprovedProvider, HttpOidc, IpNet};
use rss_identity_postgres::Authority;
use rss_request_context::TenantId;
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path};
#[derive(Debug)]
pub enum Operation<'a> {
    List,
    Create(&'a str, &'a str),
    Update(&'a str, &'a str, &'a str, &'a str),
    Enable(&'a str, &'a str, bool),
    Test(&'a str, &'a str),
}
#[derive(Debug)]
pub struct Command<'a> {
    pub actor: &'a str,
    pub password: &'a str,
    pub operation: Operation<'a>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Deployment {
    bindings: Vec<Binding>,
    #[serde(default)]
    secret_files: BTreeMap<String, String>,
    ca_file: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    tenant_id: String,
    issuer: String,
    client_id: String,
    redirect_uri: String,
    secret_ref: String,
    addresses: Vec<String>,
}
fn json<T: serde::de::DeserializeOwned>(path: &str, kind: IdpInputError) -> Result<T, AdminError> {
    let bytes = read_public_file(Path::new(path), 16384).map_err(|_| kind)?;
    serde_json::from_slice(&bytes).map_err(|_| kind.into())
}
fn bindings(d: &Deployment) -> Result<Vec<ApprovedProvider>, AdminError> {
    d.bindings
        .iter()
        .map(|b| {
            Ok(ApprovedProvider {
                tenant: TenantId::parse(&b.tenant_id).map_err(|_| IdpInputError::Tenant)?,
                issuer: b.issuer.clone(),
                client_id: b.client_id.clone(),
                redirect_uri: b.redirect_uri.clone(),
                secret_ref: b.secret_ref.clone(),
                addresses: b
                    .addresses
                    .iter()
                    .map(|s| {
                        s.parse::<IpNet>()
                            .map_err(|_| AdminError::from(IdpInputError::Network))
                    })
                    .collect::<Result<_, _>>()?,
            })
        })
        .collect()
}
fn approved(policy: &str, tenant: TenantId, settings: &ProviderSettings) -> Result<(), AdminError> {
    let deployment: Deployment = json(policy, IdpInputError::Policy)?;
    HttpOidc::approve(&bindings(&deployment)?, tenant, settings)
        .map_err(|_| IdpInputError::Binding.into())
}
pub async fn execute(a: &Authority, tenant: TenantId, c: Command<'_>) -> Result<(), AdminError> {
    // Authenticate before touching deployment/secret input selected by the command.
    let actor = a
        .verify_password(
            tenant,
            login(c.actor)?,
            password(c.password)?,
            source(),
            budget(),
        )
        .await?;
    fn id(s: &str) -> Result<ProviderId, AdminError> {
        ProviderId::parse(s).map_err(|_| IdpInputError::Provider.into())
    }
    fn version(s: &str) -> Result<i64, AdminError> {
        s.parse()
            .ok()
            .filter(|v| *v > 0)
            .ok_or(IdpInputError::Version.into())
    }
    let value = match c.operation {
        Operation::List => serde_json::to_value(a.list_providers(actor, budget()).await?),
        Operation::Create(policy, path) => {
            let settings: ProviderSettings = json(path, IdpInputError::Settings)?;
            approved(policy, tenant, &settings)?;
            serde_json::to_value(a.create_provider(actor, settings, budget()).await?)
        }
        Operation::Update(policy, provider, expected, path) => {
            let settings: ProviderSettings = json(path, IdpInputError::Settings)?;
            approved(policy, tenant, &settings)?;
            serde_json::to_value(
                a.update_provider(actor, id(provider)?, version(expected)?, settings, budget())
                    .await?,
            )
        }
        Operation::Enable(provider, expected, enabled) => serde_json::to_value(
            a.enable_provider(actor, id(provider)?, version(expected)?, enabled, budget())
                .await?,
        ),
        Operation::Test(policy, provider) => {
            let deployment: Deployment = json(policy, IdpInputError::Policy)?;
            let approved = bindings(&deployment)?;
            let report = a
                .test_provider(
                    actor,
                    id(provider)?,
                    move |tenant, settings| {
                        Box::pin(async move {
                            HttpOidc::approve(&approved, tenant, &settings)?;
                            let path = deployment
                                .secret_files
                                .get(settings.secret_ref())
                                .ok_or_else(|| {
                                    FederationError::provider(
                                        ProviderStage::Binding,
                                        ProviderReason::MissingSecret,
                                    )
                                })?;
                            let secret = read_secret(Path::new(path)).map_err(|_| {
                                FederationError::provider(
                                    ProviderStage::Binding,
                                    ProviderReason::MissingSecret,
                                )
                            })?;
                            let ca = deployment
                                .ca_file
                                .map(|path| {
                                    read_public_file(Path::new(&path), 1024 * 1024).map_err(|_| {
                                        FederationError::provider(
                                            ProviderStage::Binding,
                                            ProviderReason::InvalidTrustAnchor,
                                        )
                                    })
                                })
                                .transpose()?;
                            let oidc = HttpOidc::new(
                                approved,
                                BTreeMap::from([(settings.secret_ref().to_owned(), secret)]),
                                ca.as_deref(),
                            )?;
                            oidc.test(tenant, &settings).await
                        })
                    },
                    budget(),
                )
                .await?;
            serde_json::to_value(report)
        }
    }
    .map_err(|_| AdminError::Json)?;
    println!("{value}");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_input_errors_are_safe_and_distinct() {
        let missing = "/private/secret-path-that-must-not-leak";
        let policy = json::<Deployment>(missing, IdpInputError::Policy)
            .err()
            .unwrap()
            .to_string();
        let settings = json::<ProviderSettings>(missing, IdpInputError::Settings)
            .err()
            .unwrap()
            .to_string();
        assert_ne!(policy, settings);
        assert!(!policy.contains(missing));
        assert!(!settings.contains(missing));
        assert!(!settings.contains("secret file"));
        let kinds = [
            IdpInputError::Policy,
            IdpInputError::Settings,
            IdpInputError::Binding,
            IdpInputError::Network,
            IdpInputError::Tenant,
            IdpInputError::Provider,
            IdpInputError::Version,
        ];
        let names: std::collections::BTreeSet<_> =
            kinds.into_iter().map(|e| e.to_string()).collect();
        assert_eq!(names.len(), kinds.len());
    }
}
