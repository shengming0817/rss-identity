//! Explicit local Hydra installation task, run in Hydra's network namespace.
//! ref: ory/hydra v26.2.0 client/handler.go and fosite/access_request_handler.go.
use crate::{AppError, config::RuntimeConfig, read_secret};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path, time::Duration};
use zeroize::Zeroizing;

/// A local operator transport. Ports vary for isolated provider tests; hosts never vary.
pub struct LocalHydra {
    http: Client,
    admin: String,
    public: String,
}

impl LocalHydra {
    pub fn new(admin_port: u16, public_port: u16) -> Result<Self, AppError> {
        if admin_port == 0 || public_port == 0 || admin_port == public_port {
            return Err(AppError::Configuration);
        }
        Ok(Self {
            http: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .map_err(|_| AppError::Provider)?,
            admin: format!("http://127.0.0.1:{admin_port}"),
            public: format!("http://127.0.0.1:{public_port}"),
        })
    }

    /// Creates missing clients, verifies existing clients, and refuses drift without overwriting it.
    /// A create acknowledgement is not sufficient: every client is read back and authenticated.
    pub async fn install(&self, config: &RuntimeConfig) -> Result<usize, AppError> {
        config.validate()?;
        if !(1..=86400).contains(&config.hydra.access_token_seconds) {
            return Err(AppError::Configuration);
        }
        let mut ids = BTreeSet::new();
        let mut clients = Vec::new();
        // Validate every local input before the first remote mutation.
        for client in &config.hydra.clients {
            if client.client_id.is_empty()
                || client.client_id.len() > 256
                || client.audience.is_empty()
                || !ids.insert(&client.client_id)
            {
                return Err(AppError::Configuration);
            }
            let secret = read_secret(Path::new(&client.oidc_secret_file))?;
            if secret.len() < 32 {
                return Err(AppError::Configuration);
            }
            let desired = json!({
                "client_id":client.client_id,
                "grant_types":["authorization_code"], "response_types":["code"],
                "scope":"openid", "audience":[client.audience],
                "redirect_uris":[format!("{}/auth/callback",config.identity_origin.product_origin())],
                "token_endpoint_auth_method":"client_secret_basic", "access_token_strategy":"opaque",
                "skip_consent":false, "skip_logout_consent":false,
                "authorization_code_grant_access_token_lifespan":format!("{}s",config.hydra.access_token_seconds),
            });
            clients.push((desired, secret));
        }
        self.wait_ready(Duration::from_secs(60)).await?;
        for (desired, secret) in &clients {
            self.ensure(desired, secret).await?;
        }
        Ok(clients.len())
    }

    // Only readiness GETs are retried. No client mutation occurs inside this deadline.
    async fn wait_ready(&self, budget: Duration) -> Result<(), AppError> {
        tokio::time::timeout(budget, async {
            loop {
                let mut ready = true;
                for endpoint in [&self.admin, &self.public] {
                    if !matches!(self.http.get(format!("{endpoint}/health/ready")).send().await,
                        Ok(response) if response.status() == StatusCode::OK)
                    {
                        ready = false;
                        break;
                    }
                }
                if ready {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .map_err(|_| AppError::Provider)
    }

    async fn ensure(&self, desired: &Value, secret: &str) -> Result<(), AppError> {
        let id = desired["client_id"]
            .as_str()
            .ok_or(AppError::Configuration)?;
        let mut url = reqwest::Url::parse(&format!("{}/admin/clients/", self.admin))
            .map_err(|_| AppError::Configuration)?;
        url.path_segments_mut()
            .map_err(|_| AppError::Configuration)?
            .pop_if_empty()
            .push(id);
        let (status, mut actual) = response(self.http.get(url.clone())).await?;
        if status == StatusCode::NOT_FOUND {
            let mut create = desired.clone();
            create["client_secret"] = Value::String(secret.to_owned());
            // Keep the wire payload out of diagnostics, including unknown commit outcomes.
            let payload =
                Zeroizing::new(serde_json::to_vec(&create).map_err(|_| AppError::Configuration)?);
            if let Some(Value::String(value)) = create.get_mut("client_secret") {
                use zeroize::Zeroize;
                value.zeroize();
            }
            let sent = response(
                self.http
                    .post(format!("{}/admin/clients", self.admin))
                    .header("Content-Type", "application/json")
                    .body(payload.to_vec()),
            )
            .await;
            if let Ok((status, _)) = &sent
                && *status != StatusCode::CREATED
                && *status != StatusCode::CONFLICT
                && !status.is_server_error()
            {
                return Err(AppError::Provider);
            }
            // Never blindly repeat POST after timeout/5xx/conflict: recover by exact readback.
            let (status, observed) = response(self.http.get(url)).await?;
            if status != StatusCode::OK {
                return Err(AppError::Provider);
            }
            actual = observed;
        } else if status != StatusCode::OK {
            return Err(AppError::Provider);
        }
        verify_fields(desired, &actual)?;
        // Hydra authenticates before looking up this impossible authorization code.
        // invalid_grant proves client authentication; invalid_client is credential drift.
        // ref: fosite/handler/oauth2/flow_authorize_code_token.go @ v26.2.0.
        let encode = |value: &str| {
            url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
        };
        let (status, value) = response(
            self.http
                .post(format!("{}/oauth2/token", self.public))
                .basic_auth(encode(id), Some(encode(secret)))
                .form(&[
                    ("grant_type", "authorization_code"),
                    ("code", "!identity-registration-probe!"),
                ]),
        )
        .await?;
        if status != StatusCode::BAD_REQUEST || value["error"] != "invalid_grant" {
            return Err(AppError::Provider);
        }
        Ok(())
    }
}

fn verify_fields(desired: &Value, actual: &Value) -> Result<(), AppError> {
    for (key, value) in desired.as_object().ok_or(AppError::Configuration)? {
        let matches = if key == "authorization_code_grant_access_token_lifespan" {
            // Hydra normalizes durations (e.g. 300s -> 5m0s).
            duration_seconds(actual[key].as_str()) == duration_seconds(value.as_str())
        } else {
            actual.get(key) == Some(value)
        };
        if !matches {
            return Err(AppError::Provider);
        }
    }
    Ok(())
}

fn duration_seconds(value: Option<&str>) -> Option<u64> {
    let mut total = 0u64;
    let mut number = String::new();
    for ch in value?.chars() {
        if ch.is_ascii_digit() {
            number.push(ch);
            continue;
        }
        let scale = match ch {
            'h' => 3600,
            'm' => 60,
            's' => 1,
            _ => return None,
        };
        total = total.checked_add(number.parse::<u64>().ok()?.checked_mul(scale)?)?;
        number.clear();
    }
    if !number.is_empty() || total == 0 {
        None
    } else {
        Some(total)
    }
}

async fn response(request: RequestBuilder) -> Result<(StatusCode, Value), AppError> {
    let mut response = request.send().await.map_err(|_| AppError::Provider)?;
    let status = response.status();
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| AppError::Provider)? {
        if bytes.len() + chunk.len() > 1024 * 1024 {
            return Err(AppError::Provider);
        }
        bytes.extend_from_slice(&chunk);
    }
    let mut value: Value = serde_json::from_slice(&bytes).map_err(|_| AppError::Provider)?;
    if let Some(Value::String(secret)) = value.get_mut("client_secret") {
        use zeroize::Zeroize;
        secret.zeroize();
    }
    Ok((status, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn readiness_budget_bounds_stalled_health_headers() {
        // Listening without accepting keeps the request pending beyond the admission budget.
        let admin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let public = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let hydra = LocalHydra::new(
            admin.local_addr().unwrap().port(),
            public.local_addr().unwrap().port(),
        )
        .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            hydra.wait_ready(Duration::from_millis(20)),
        )
        .await;
        assert!(matches!(result, Ok(Err(AppError::Provider))));
    }
}
