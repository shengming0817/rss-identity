//! Standalone simulated product: public client + standard OIDC only.
#[cfg(test)]
mod tests {
    use openidconnect::{core::*, *};
    use reqwest::{Client, Url};
    use rss_identity_client::{ClientConfig, IdentityClient};
    use serde_json::{Value, json};
    use std::time::Duration;
    use zeroize::Zeroizing;
    fn query(u: &Url, k: &str) -> anyhow::Result<String> {
        u.query_pairs()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.into_owned())
            .ok_or_else(|| anyhow::anyhow!("missing callback field"))
    }
    fn location(r: reqwest::Response) -> anyhow::Result<Url> {
        anyhow::ensure!(r.status().is_redirection(), "expected protocol redirect");
        Ok(Url::parse(
            r.headers()
                .get("location")
                .ok_or_else(|| anyhow::anyhow!("missing location"))?
                .to_str()?,
        )?)
    }
    async fn post(
        c: &Client,
        origin: &str,
        path: &str,
        value: Value,
        csrf: Option<&str>,
    ) -> anyhow::Result<Value> {
        let mut r = c
            .post(format!("{origin}{path}"))
            .header("Origin", origin)
            .header("X-Identity-Request", "1")
            .json(&value);
        if let Some(s) = csrf {
            r = r.header("X-CSRF-Token", s);
        }
        let r = r.send().await?;
        anyhow::ensure!(r.status().is_success(), "Identity rejected browser request");
        Ok(r.json().await?)
    }
    #[tokio::test]
    #[ignore = "run by make test-downstream with production bridge and real Hydra"]
    async fn product_code_pkce_online_identity_and_logout() -> anyhow::Result<()> {
        let issuer = std::env::var("IDENTITY_TEST_DOWNSTREAM_ISSUER")?;
        let origin = issuer.trim_end_matches('/');
        let ca = std::fs::read(std::env::var("IDENTITY_TEST_DOWNSTREAM_CA")?)?;
        let http = Client::builder()
            .no_proxy()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
            .build()?;
        let metadata = CoreProviderMetadata::discover_async(IssuerUrl::new(issuer.clone())?, &http)
            .await
            .map_err(|_| anyhow::anyhow!("discovery failed"))?;
        let oidc = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new("mdm".into()),
            Some(ClientSecret::new("fixture-oidc-mdm-secret".into())),
        )
        .set_redirect_uri(RedirectUrl::new(
            "https://mdm.example.test/auth/callback".into(),
        )?);
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (authorization, state, nonce) = oidc
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge)
            .add_extra_param("audience", "mdm-api")
            .url();
        let session = post(
            &http,
            origin,
            "/api/v1/tenants/11111111-1111-4111-8111-111111111111/login",
            json!({"login":"admin","password":"correct horse battery staple"}),
            None,
        )
        .await?;
        let csrf = session["csrf_token"].as_str().unwrap();
        let login = location(http.get(authorization).send().await?)?;
        let challenge = query(&login, "login_challenge")?;
        let handle = post(
            &http,
            origin,
            "/api/v1/downstream/login",
            json!({"challenge":challenge}),
            None,
        )
        .await?;
        let response = post(
            &http,
            origin,
            "/api/v1/downstream/login/accept",
            json!({"flow":handle,"challenge":challenge}),
            Some(csrf),
        )
        .await?;
        let consent = location(
            http.get(response["redirect_to"].as_str().unwrap())
                .send()
                .await?,
        )?;
        let challenge = query(&consent, "consent_challenge")?;
        let handle = post(
            &http,
            origin,
            "/api/v1/downstream/consent",
            json!({"challenge":challenge}),
            None,
        )
        .await?;
        let response = post(
            &http,
            origin,
            "/api/v1/downstream/consent/accept",
            json!({"flow":handle,"challenge":challenge}),
            Some(csrf),
        )
        .await?;
        let callback = location(
            http.get(response["redirect_to"].as_str().unwrap())
                .send()
                .await?,
        )?;
        anyhow::ensure!(
            query(&callback, "state")? == *state.secret(),
            "state rejected"
        );
        let token = oidc
            .exchange_code(AuthorizationCode::new(query(&callback, "code")?))?
            .set_pkce_verifier(verifier)
            .request_async(&http)
            .await
            .map_err(|_| anyhow::anyhow!("code exchange failed"))?;
        let id_token = token
            .id_token()
            .ok_or_else(|| anyhow::anyhow!("missing ID token"))?;
        let verified = id_token
            .claims(&oidc.id_token_verifier(), &nonce)
            .map_err(|_| anyhow::anyhow!("ID token rejected"))?;
        assert!(
            id_token
                .claims(&oidc.id_token_verifier(), &Nonce::new("wrong".into()))
                .is_err()
        );
        let sdk = IdentityClient::new(
            ClientConfig {
                identity_origin: origin.into(),
                issuer: issuer.clone(),
                client_id: "mdm".into(),
                validation_secret: Zeroizing::new("fixture-validation-mdm-secret-32bytes".into()),
                tenant_id: "11111111-1111-4111-8111-111111111111".into(),
                audience: "mdm-api".into(),
                timeout: Duration::from_secs(10),
                ca_pem: Some(ca),
            },
            std::sync::Arc::new(rss_identity_client::SystemClock),
        )?;
        let credential = token.access_token().secret();
        let proof = sdk.validate(credential).await?;
        anyhow::ensure!(
            proof.subject() == verified.subject().as_str(),
            "subject mismatch"
        );
        sdk.validate(credential).await?;
        let logout = http
            .post(format!(
                "{origin}/api/v1/tenants/11111111-1111-4111-8111-111111111111/session/logout"
            ))
            .header("Origin", origin)
            .header("X-CSRF-Token", csrf)
            .send()
            .await?;
        assert_eq!(logout.status(), 204);
        assert!(sdk.validate(credential).await.is_err());
        Ok(())
    }
}
