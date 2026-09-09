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
