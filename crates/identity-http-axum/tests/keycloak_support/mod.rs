//! Disposable fixture OTP only. Production Identity never receives an OTP secret.
use hmac::{Hmac, KeyInit, Mac};
use std::time::{SystemTime, UNIX_EPOCH};
pub fn totp() -> anyhow::Result<String> {
    let counter = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 30;
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(b"fixture-totp-secret-2339")?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 15);
    let value = u32::from_be_bytes(digest[offset..offset + 4].try_into()?) & 0x7fffffff;
    Ok(format!("{:06}", value % 1_000_000))
}

pub async fn authorize(url: &str, user: &str, require_totp: bool) -> anyhow::Result<reqwest::Url> {
    let pem = std::fs::read(std::env::var("IDENTITY_TEST_FEDERATED_CA")?)?;
    let browser = reqwest::Client::builder()
        .no_proxy()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_pem(&pem)?)
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let html = browser
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let action = form(&html, "form#kc-form-login")?;
    let response = browser
        .post(action)
        .form(&[
            ("username", user),
            ("password", "fixture-password"),
            ("credentialId", ""),
        ])
        .send()
        .await?;
    let response = if require_totp {
        let action = form(&response.text().await?, "form#kc-otp-login-form")?;
        browser
            .post(action)
            .form(&[("otp", totp()?), ("login", "Log In".into())])
            .send()
            .await?
    } else {
        response
    };
    anyhow::ensure!(
        response.status().is_redirection(),
        "Keycloak authentication did not redirect: {}",
        response.status()
    );
    Ok(reqwest::Url::parse(
        response
            .headers()
            .get("location")
            .ok_or_else(|| anyhow::anyhow!("Keycloak callback absent"))?
            .to_str()?,
    )?)
}
fn form(html: &str, selector: &str) -> anyhow::Result<String> {
    let dom = scraper::Html::parse_document(html);
    Ok(dom
        .select(&scraper::Selector::parse(selector).unwrap())
        .next()
        .and_then(|f| f.value().attr("action"))
        .ok_or_else(|| anyhow::anyhow!("expected Keycloak form absent: {selector}"))?
        .to_owned())
}

/// Disposable realm administration through Keycloak's real public TLS Admin API.
pub struct StaffMembership {
    client: reqwest::Client,
    token: zeroize::Zeroizing<String>,
    groups_url: String,
    group: String,
    original: bool,
}
impl StaffMembership {
    pub async fn load() -> anyhow::Result<Self> {
        let issuer = std::env::var("IDENTITY_TEST_FEDERATED_ISSUER")?;
        let origin = issuer.trim_end_matches("/realms/identity");
        let c = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(10))
            .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                std::env::var("IDENTITY_TEST_FEDERATED_CA")?,
            )?)?)
            .build()?;
        let token: serde_json::Value = c
            .post(format!(
                "{origin}/realms/master/protocol/openid-connect/token"
            ))
            .form(&[
                ("client_id", "admin-cli"),
                ("grant_type", "password"),
                ("username", "fixture-operator"),
                ("password", "fixture-operator-password"),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let token = token["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("fixture admin credential absent"))?;
        let users: serde_json::Value = c
            .get(format!(
                "{origin}/admin/realms/identity/users?username=alice&exact=true"
            ))
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let groups: serde_json::Value = c
            .get(format!(
                "{origin}/admin/realms/identity/groups?search=staff&exact=true"
            ))
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let user = users[0]["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("fixture user absent"))?;
        let group = groups[0]["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("fixture group absent"))?;
        let mut membership = Self {
            client: c,
            token: zeroize::Zeroizing::new(token.to_owned()),
            groups_url: format!("{origin}/admin/realms/identity/users/{user}/groups"),
            group: group.to_owned(),
            original: false,
        };
        membership.original = membership.current().await?;
        Ok(membership)
    }
    pub async fn current(&self) -> anyhow::Result<bool> {
        let groups: serde_json::Value = self
            .client
            .get(&self.groups_url)
            .bearer_auth(self.token.as_str())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let groups = groups
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("fixture memberships malformed"))?;
        Ok(groups
            .iter()
            .any(|group| group["id"].as_str() == Some(self.group.as_str())))
    }
    pub async fn set(&self, member: bool) -> anyhow::Result<()> {
        self.client
            .request(
                if member {
                    reqwest::Method::PUT
                } else {
                    reqwest::Method::DELETE
                },
                format!("{}/{}", self.groups_url, self.group),
            )
            .bearer_auth(self.token.as_str())
            .send()
            .await?
            .error_for_status()?;
        anyhow::ensure!(
            self.current().await? == member,
            "fixture membership read-back failed"
        );
        Ok(())
    }
    pub async fn restore(&self) -> anyhow::Result<()> {
        self.set(self.original).await
    }
}
