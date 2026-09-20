#[cfg(all(test, feature = "loopback-fixture"))]
mod host;
#[cfg(all(test, feature = "loopback-fixture"))]
mod tests {
    use super::host::*;
    use rss_identity_core::{federation::*, groups::GroupFactsMaxAge};
    use rss_identity_postgres::*;
    use std::{collections::BTreeMap, sync::Arc, time::Duration};
    #[tokio::test]
    async fn oidc_host_uses_real_keycloak_and_public_groups() -> anyhow::Result<()> {
        let host = Host::start().await?;
        let local = host.login().await?;
        let issuer = std::env::var("IDENTITY_TEST_FEDERATED_ISSUER")?;
        let pem = std::fs::read_to_string(std::env::var("IDENTITY_TEST_FEDERATED_CA")?)?;
        let oidc = rss_identity_oidc::HttpOidc::for_loopback_test(vec![
            rss_identity_oidc::TrustedAssuranceProfile {
                tenant: host.key.tenant,
                issuer: issuer.clone(),
                client_id: "identity-test".into(),
                keycloak_totp: true,
            },
        ])?;
        let callback = "https://embedded.example.test/api/v2/oidc/callback";
        let federation = Federation::new(
            GroupFactsMaxAge::new(5)?,
            host.authority.clone(),
            Arc::new(oidc),
            StateSigner::new([7; 32], &host.authority.instance().to_string())?,
            FederationConfig {
                callback: callback.into(),
                credential_keys: Arc::new(CredentialKeys::new(
                    "host".into(),
                    vec![("host".into(), [8; 32])],
                )?),
                targets: BTreeMap::from([(
                    "home".into(),
                    "https://embedded.example.test/done".into(),
                )]),
            },
        )?;
        let settings = ProviderSettings::try_from(ProviderSettingsInput {
            issuer: issuer.clone(),
            client_id: "identity-test".into(),
            redirect_uri: callback.into(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            claims: ClaimMapping {
                department_snapshot: Some(rss_identity_core::department::DepartmentSnapshotClaim::new(
                    "organization_snapshot".into(),
                    5,
                )?),
                email: Some("email".into()),
                groups: Some("groups".into()),
            },
            jit: true,
        })?;
        let provider = federation
            .create_provider(
                host.actor(&local).await?,
                settings,
                ProviderCredentials::new("fixture-secret".into(), Some(pem.clone()))?,
                deadline(),
            )
            .await?;
        let provider = federation
            .enable_provider(
                host.actor(&local).await?,
                provider.id,
                provider.version,
                true,
                deadline(),
            )
            .await?;
        let config = rss_identity_http_axum::HttpConfig::new(
            "https://embedded.example.test",
            Duration::from_secs(10),
        )?;
        let _router =
            rss_identity_http_axum::router(host.authority.clone(), config.clone())?.merge(
                rss_identity_http_axum::federated_router(federation.clone(), config)?,
            );
        let browser = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let redirect = federation
            .begin_login(
                LoginRequest {
                    tenant: host.key.tenant,
                    provider: provider.id,
                    browser: browser.into(),
                    target: "home".into(),
                    replacement: None,
                    source: AttemptSource::parse("consumer")?,
                },
                deadline(),
            )
            .await?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes())?)
            .timeout(Duration::from_secs(15))
            .build()?;
        let html = client
            .get(redirect.url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let action = {
            let dom = scraper::Html::parse_document(&html);
            dom.select(&scraper::Selector::parse("form#kc-form-login").unwrap())
                .next()
                .and_then(|f| f.value().attr("action"))
                .ok_or_else(|| anyhow::anyhow!("login form missing"))?
                .to_owned()
        };
        let response = client
            .post(action)
            .form(&[
                ("username", "alice"),
                ("password", "fixture-password"),
                ("credentialId", ""),
            ])
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_redirection(),
            "provider did not authenticate"
        );
        let location = reqwest::Url::parse(
            response
                .headers()
                .get("location")
                .ok_or_else(|| anyhow::anyhow!("callback missing"))?
                .to_str()?,
        )?;
        let query: BTreeMap<String, String> = location.query_pairs().into_owned().collect();
        let outcome = federation
            .complete(
                query["state"].clone(),
                browser.into(),
                zeroize::Zeroizing::new(query["code"].clone()),
                query["iss"].clone(),
                None,
                deadline(),
            )
            .await?;
        let FederatedOutcome::Session {
            issued, return_url, ..
        } = outcome
        else {
            anyhow::bail!("missing session")
        };
        assert_eq!(return_url, "https://embedded.example.test/done");
        let actor = host
            .authority
            .inspect_session(host.key.tenant, secret(&issued), deadline())
            .await?;
        assert_ne!(actor.account(), host.key);
        let VerifiedGroups::Available(groups) = actor.groups()? else {
            anyhow::bail!("groups unavailable")
        };
        assert_eq!(groups.values()?, ["/staff"]);
        assert_eq!(groups.source().issuer(), issuer);
        let VerifiedDepartmentSnapshot::Available(department) = actor.department_snapshot()? else {
            anyhow::bail!("department unavailable");
        };
        assert_eq!(department.snapshot()?.memberships()[0].as_str(), "dept-01");
        assert_eq!(department.account(), actor.account());
        assert_eq!(department.instance(), actor.instance());
        assert_eq!(department.issuer(), issuer);
        assert_eq!(
            department.provider_id().to_string(),
            provider.id.to_string()
        );

        tokio::time::sleep(Duration::from_secs(6)).await;
        assert_eq!(groups.values(), Err(GroupAccessError::SnapshotExpired));
        assert!(matches!(actor.groups()?, VerifiedGroups::Expired));
        assert_eq!(
            department.snapshot(),
            Err(DepartmentAccessError::SnapshotExpired)
        );
        assert!(matches!(actor.department_snapshot()?, VerifiedDepartmentSnapshot::Expired));
        assert!(actor.assurance().is_ok());
        federation
            .enable_provider(
                host.actor(&local).await?,
                provider.id,
                provider.version,
                false,
                deadline(),
            )
            .await?;
        assert!(
            host.authority
                .inspect_session(host.key.tenant, secret(&issued), deadline())
                .await
                .is_err()
        );
        assert!(host.actor(&local).await.is_ok());
        host.maintenance
            .recover_local_password(host.key, password(), deadline())
            .await?;
        assert!(host.actor(&local).await.is_err());
        host.close().await;
        Ok(())
    }
}

#[cfg(all(test, not(feature = "loopback-fixture")))]
mod production {
    #[test]
    fn production_transport_rejects_loopback() -> anyhow::Result<()> {
        let profile = rss_identity_oidc::TrustedAssuranceProfile {
            tenant: rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111")?,
            issuer: "https://127.0.0.1:443/realms/identity".into(),
            client_id: "identity-test".into(),
            keycloak_totp: true,
        };
        assert!(rss_identity_oidc::HttpOidc::new(vec![profile], vec![]).is_err());
        let access = rss_identity_oidc::PrivateProviderAccess {
            tenant: rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111")?,
            issuer: "https://10.42.0.9:8443/realms/reference".into(),
            client_id: "reference".into(),
            cidrs: vec!["10.42.0.9/32".parse()?],
        };
        rss_identity_oidc::HttpOidc::new(vec![], vec![access])?;
        Ok(())
    }
}
