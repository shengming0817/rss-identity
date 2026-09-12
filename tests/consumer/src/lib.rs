//! Standalone simulated product: public client + standard OIDC only.
//! ref: openidconnect 4.0.1 client.rs and verification/mod.rs.
use openidconnect::{core::*, *};
use reqwest::{Client, Url};
use rss_identity_client::{ClientConfig, IdentityClient, VerifiedIdentity};
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

type Oidc = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub struct ProductConfig {
    pub issuer: String,
    pub client_id: String,
    pub audience: String,
    pub redirect_uri: String,
    pub identity_origin: String,
    pub tenant_id: String,
    pub oidc_secret: Zeroizing<String>,
    pub validation_secret: Zeroizing<String>,
    pub ca_pem: Vec<u8>,
}

pub struct Product {
    oidc: Oidc,
    http: Client,
    sdk: IdentityClient,
    audience: String,
    callback: Url,
}

/// Owned once by one pending browser transaction; never serialized or logged.
pub struct Pending {
    state: CsrfToken,
    nonce: Nonce,
    verifier: PkceCodeVerifier,
}
pub struct ProductSession {
    credential: Zeroizing<String>,
    subject: String,
}

impl Product {
    pub async fn discover(c: ProductConfig, http: Client) -> anyhow::Result<Self> {
        let metadata =
            CoreProviderMetadata::discover_async(IssuerUrl::new(c.issuer.clone())?, &http)
                .await
                .map_err(|_| anyhow::anyhow!("discovery failed"))?;
        let oidc = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(c.client_id.clone()),
            Some(ClientSecret::new(c.oidc_secret.to_string())),
        )
        .set_redirect_uri(RedirectUrl::new(c.redirect_uri.clone())?);
        let sdk = IdentityClient::new(
            ClientConfig {
                identity_origin: c.identity_origin,
                issuer: c.issuer,
                client_id: c.client_id,
                validation_secret: c.validation_secret,
                tenant_id: c.tenant_id,
                audience: c.audience.clone(),
                timeout: Duration::from_secs(5),
                ca_pem: Some(c.ca_pem),
            },
            Arc::new(rss_identity_client::SystemClock),
        )?;
        Ok(Self {
            oidc,
            http,
            sdk,
            audience: c.audience,
            callback: Url::parse(&c.redirect_uri)?,
        })
    }

    pub fn begin(&self) -> (Url, Pending) {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state, nonce) = self
            .oidc
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge)
            .add_extra_param("audience", &self.audience)
            .url();
        (
            url,
            Pending {
                state,
                nonce,
                verifier,
            },
        )
    }

    pub async fn exchange(
        &self,
        pending: Pending,
        callback: &Url,
    ) -> anyhow::Result<ProductSession> {
        anyhow::ensure!(
            callback.origin() == self.callback.origin() && callback.path() == self.callback.path(),
            "callback origin rejected"
        );
        let one = |key: &str| -> anyhow::Result<String> {
            let values: Vec<_> = callback.query_pairs().filter(|(k, _)| k == key).collect();
            anyhow::ensure!(
                values.len() == 1 && !values[0].1.is_empty(),
                "callback field rejected"
            );
            Ok(values[0].1.to_string())
        };
        anyhow::ensure!(
            one("state")? == *pending.state.secret()
                && !callback.query_pairs().any(|(k, _)| k == "error"),
            "callback state rejected"
        );
        let token = self
            .oidc
            .exchange_code(AuthorizationCode::new(one("code")?))?
            .set_pkce_verifier(pending.verifier)
            .request_async(&self.http)
            .await
            .map_err(|_| anyhow::anyhow!("code exchange failed"))?;
        let id = token
            .id_token()
            .ok_or_else(|| anyhow::anyhow!("missing ID token"))?;
        let verifier = self
            .oidc
            .id_token_verifier()
            .set_allowed_algs(vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256]);
        let claims = id
            .claims(&verifier, &pending.nonce)
            .map_err(|_| anyhow::anyhow!("ID token rejected"))?;
        // Preserve the existing consumer's nonce negative assertion in its T2 build.
        #[cfg(test)]
        anyhow::ensure!(
            id.claims(&verifier, &Nonce::new("wrong".into())).is_err(),
            "nonce accepted"
        );
        let session = ProductSession {
            credential: Zeroizing::new(token.access_token().secret().clone()),
            subject: claims.subject().as_str().into(),
        };
        self.verify(&session).await?;
        Ok(session)
    }

    pub async fn verify(
        &self,
        session: &ProductSession,
    ) -> Result<VerifiedIdentity, rss_identity_client::Error> {
        let facts = self.sdk.validate(&session.credential).await?;
        if facts.subject() != session.subject {
            return Err(rss_identity_client::Error::Rejected);
        }
        Ok(facts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::{Client, Url};
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
        let product = Product::discover(
            ProductConfig {
                issuer: issuer.clone(),
                client_id: "mdm".into(),
                audience: "mdm-api".into(),
                redirect_uri: "https://mdm.example.test/auth/callback".into(),
                identity_origin: origin.into(),
                tenant_id: "11111111-1111-4111-8111-111111111111".into(),
                oidc_secret: Zeroizing::new("fixture-oidc-mdm-secret".into()),
                validation_secret: Zeroizing::new("fixture-validation-mdm-secret-32bytes".into()),
                ca_pem: ca,
            },
            http.clone(),
        )
        .await?;
        let (authorization, pending) = product.begin();
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
        let session = product.exchange(pending, &callback).await?;
        product.verify(&session).await?;
        product.verify(&session).await?;
        let logout = http
            .post(format!(
                "{origin}/api/v1/tenants/11111111-1111-4111-8111-111111111111/session/logout"
            ))
            .header("Origin", origin)
            .header("X-CSRF-Token", csrf)
            .send()
            .await?;
        assert_eq!(logout.status(), 204);
        assert!(product.verify(&session).await.is_err());
        Ok(())
    }
}
