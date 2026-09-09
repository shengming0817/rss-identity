//! Request-scoped Identity validation client. No OIDC flow, database dependency, or success cache.
use rss_identity_contracts::{
    IdentityFacts, ValidationFailure, ValidationFailureCode, ValidationRequest,
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid validation configuration or input")]
    Invalid,
    #[error("identity rejected")]
    Rejected,
    #[error("identity unavailable")]
    Unavailable,
    #[error("identity request failed: {code:?} (correlation {correlation_id})")]
    Server {
        code: ValidationFailureCode,
        correlation_id: uuid::Uuid,
    },
}
impl Error {
    pub fn correlation_id(&self) -> Option<uuid::Uuid> {
        match self {
            Self::Server { correlation_id, .. } => Some(*correlation_id),
            _ => None,
        }
    }
    pub fn is_unavailable(&self) -> bool {
        matches!(
            self,
            Self::Unavailable
                | Self::Server {
                    code: ValidationFailureCode::IdentityUnavailable
                        | ValidationFailureCode::RateLimited,
                    ..
                }
        )
    }
}
fn server_failure(status: u16, bytes: &[u8]) -> Error {
    let Ok(value) = serde_json::from_slice::<ValidationFailure>(bytes) else {
        return Error::Unavailable;
    };
    let Ok(id) = uuid::Uuid::parse_str(&value.correlation_id) else {
        return Error::Unavailable;
    };
    if id.is_nil() {
        return Error::Unavailable;
    }
    if status != value.code.http_status() {
        return Error::Unavailable;
    }
    let code = value.code;
    Error::Server {
        code,
        correlation_id: id,
    }
}
/// Wall time dependency, explicitly supplied by the consumer. PG remains the identity authority.
pub trait Clock: Send + Sync {
    fn unix_seconds(&self) -> Result<i64, Error>;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn unix_seconds(&self) -> Result<i64, Error> {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Unavailable)?
            .as_secs();
        i64::try_from(seconds).map_err(|_| Error::Unavailable)
    }
}
struct Inner {
    http: reqwest::Client,
    clock: Arc<dyn Clock>,
    endpoint: String,
    issuer: String,
    client: String,
    secret: Zeroizing<String>,
    tenant: String,
    audience: String,
}
#[derive(Clone)]
pub struct IdentityClient(Arc<Inner>);
/// Verified for one request only. A serialized response cannot construct this type.
/// ```compile_fail
/// let proof: rss_identity_client::VerifiedIdentity = serde_json::from_str("{}").unwrap();
/// ```
pub struct VerifiedIdentity(IdentityFacts);
impl VerifiedIdentity {
    pub fn subject(&self) -> &str {
        &self.0.subject
    }
    pub fn tenant_id(&self) -> &str {
        &self.0.tenant_id
    }
    pub fn session_id(&self) -> &str {
        &self.0.session_id
    }
    pub fn client_id(&self) -> &str {
        &self.0.client_id
    }
    pub fn audience(&self) -> &str {
        &self.0.audience
    }
    pub fn issuer(&self) -> &str {
        &self.0.issuer
    }
    pub fn auth_time(&self) -> i64 {
        self.0.auth_time
    }
    pub fn expires_at(&self) -> i64 {
        self.0.expires_at
    }
    pub fn amr(&self) -> &[String] {
        &self.0.amr
    }
    pub fn acr(&self) -> &str {
        &self.0.acr
    }
}
/// Explicit endpoint and binding; caller owns secret loading and product session storage.
pub struct ClientConfig {
    pub identity_origin: String,
    pub issuer: String,
    pub client_id: String,
    pub validation_secret: Zeroizing<String>,
    pub tenant_id: String,
    pub audience: String,
    pub timeout: Duration,
    pub ca_pem: Option<Vec<u8>>,
}
fn url(s: &str) -> Result<url::Url, Error> {
    let u = url::Url::parse(s).map_err(|_| Error::Invalid)?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        Err(Error::Invalid)
    } else {
        Ok(u)
    }
}
fn nonempty(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.trim() == s && !s.chars().any(char::is_control)
}
impl IdentityClient {
    pub fn new(c: ClientConfig, clock: Arc<dyn Clock>) -> Result<Self, Error> {
        let origin = url(&c.identity_origin)?;
        url(&c.issuer)?;
        let tenant = uuid::Uuid::parse_str(&c.tenant_id).map_err(|_| Error::Invalid)?;
        if origin.origin().ascii_serialization() != c.identity_origin
            || tenant.is_nil()
            || c.timeout.is_zero()
            || c.timeout > Duration::from_secs(60)
            || !nonempty(&c.client_id, 256)
            || c.client_id.contains(':')
            || !nonempty(&c.validation_secret, 4096)
            || c.validation_secret.len() < 32
            || !nonempty(&c.audience, 256)
        {
            return Err(Error::Invalid);
        }
        let mut b = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(c.timeout);
        if let Some(pem) = c.ca_pem {
            b = b.add_root_certificate(
                reqwest::Certificate::from_pem(&pem).map_err(|_| Error::Invalid)?,
            );
        }
        Ok(Self(Arc::new(Inner {
            clock,
            http: b.build().map_err(|_| Error::Unavailable)?,
            endpoint: format!("{}/internal/v1/identity/validate", c.identity_origin),
            issuer: c.issuer,
            client: c.client_id,
            secret: c.validation_secret,
            tenant: tenant.to_string(),
            audience: c.audience,
        })))
    }
    pub async fn validate(&self, credential: &str) -> Result<VerifiedIdentity, Error> {
        if !nonempty(credential, 16384) {
            return Err(Error::Invalid);
        }
        let c = &self.0;
        let started = c.clock.unix_seconds()?;
        let request = ValidationRequest {
            credential: credential.into(),
            tenant_id: c.tenant.clone(),
            audience: c.audience.clone(),
        };
        let mut response = c
            .http
            .post(&c.endpoint)
            .basic_auth(&c.client, Some(c.secret.as_str()))
            .json(&request)
            .send()
            .await
            .map_err(|_| Error::Unavailable)?;
        let status = response.status();
        if response
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            != Some("no-store")
        {
            return Err(Error::Unavailable);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
            if bytes.len() + chunk.len() > 65536 {
                return Err(Error::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            return Err(server_failure(status.as_u16(), &bytes));
        }
        if status != reqwest::StatusCode::OK {
            return Err(Error::Unavailable);
        }
        let facts: IdentityFacts =
            serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
        let now = c.clock.unix_seconds()?;
        if started <= 0 || now < started {
            return Err(Error::Unavailable);
        }
        let sid = uuid::Uuid::parse_str(&facts.session_id).map_err(|_| Error::Rejected)?;
        if facts.tenant_id != c.tenant
            || facts.client_id != c.client
            || facts.audience != c.audience
            || facts.issuer != c.issuer
            || !nonempty(&facts.subject, 255)
            || sid.is_nil()
            || facts.expires_at <= now
            || facts.auth_time <= 0
            || facts.auth_time >= facts.expires_at
            || facts.acr != "unspecified"
            || !(facts.amr.is_empty() || facts.amr == ["pwd"])
        {
            return Err(Error::Rejected);
        }
        Ok(VerifiedIdentity(facts))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn client_rejects_untrusted_configuration() {
        for origin in [
            "http://identity.test",
            "https://identity.test/path",
            "https://user@identity.test",
        ] {
            assert!(
                IdentityClient::new(
                    ClientConfig {
                        identity_origin: origin.into(),
                        issuer: "https://identity.test/oidc".into(),
                        client_id: "a".into(),
                        validation_secret: Zeroizing::new("x".repeat(32)),
                        tenant_id: uuid::Uuid::new_v4().to_string(),
                        audience: "api".into(),
                        timeout: Duration::from_secs(5),
                        ca_pem: None
                    },
                    Arc::new(SystemClock)
                )
                .is_err()
            );
        }
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn facts() -> Value {
        let now = 1000;
        json!({"subject":"pairwise-subject","tenant_id":"11111111-1111-4111-8111-111111111111","session_id":"22222222-2222-4222-8222-222222222222","client_id":"mdm","audience":"mdm-api","issuer":"https://identity.test","auth_time":now-10,"expires_at":now+300,"amr":["pwd"],"acr":"unspecified"})
    }
    async fn response(
        status: u16,
        headers: &str,
        body: String,
        delay: bool,
    ) -> Result<VerifiedIdentity, Error> {
        response_clock(status, headers, body, delay, Arc::new(FixedClock(1000))).await
    }
    struct FixedClock(i64);
    impl Clock for FixedClock {
        fn unix_seconds(&self) -> Result<i64, Error> {
            Ok(self.0)
        }
    }
    struct SequenceClock(std::sync::Mutex<std::collections::VecDeque<i64>>);
    impl Clock for SequenceClock {
        fn unix_seconds(&self) -> Result<i64, Error> {
            self.0.lock().unwrap().pop_front().ok_or(Error::Unavailable)
        }
    }
    async fn response_clock(
        status: u16,
        headers: &str,
        body: String,
        delay: bool,
        clock: Arc<dyn Clock>,
    ) -> Result<VerifiedIdentity, Error> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let wire = format!(
            "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
            body.len()
        );
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0; 4096];
            let _ = socket.read(&mut buf).await;
            if delay {
                tokio::time::sleep(Duration::from_millis(350)).await;
            }
            let _ = socket.write_all(wire.as_bytes()).await;
        });
        let mut client = IdentityClient::new(
            ClientConfig {
                identity_origin: "https://identity.test".into(),
                issuer: "https://identity.test".into(),
                client_id: "mdm".into(),
                validation_secret: Zeroizing::new("x".repeat(32)),
                tenant_id: "11111111-1111-4111-8111-111111111111".into(),
                audience: "mdm-api".into(),
                timeout: Duration::from_millis(200),
                ca_pem: None,
            },
            clock,
        )
        .unwrap();
        // Unit-only endpoint replacement retains the production HTTP builder and redirect/timeout policy.
        Arc::get_mut(&mut client.0).unwrap().endpoint = format!("http://{address}/validate");
        let result = client.validate("fixture-opaque-token").await;
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        result
    }
    const HEADERS: &str = "Cache-Control: no-store\r\nContent-Type: application/json\r\n";
    #[tokio::test]
    async fn client_rejects_each_invalid_success_binding() {
        assert!(
            response(200, HEADERS, facts().to_string(), false)
                .await
                .is_ok()
        );
        for (field, value) in [
            ("tenant_id", json!("wrong")),
            ("client_id", json!("other")),
            ("audience", json!("wrong")),
            ("issuer", json!("https://wrong.test")),
            ("subject", json!("")),
            ("session_id", json!("00000000-0000-0000-0000-000000000000")),
            ("auth_time", json!(0)),
            ("auth_time", json!(i64::MAX)),
            ("expires_at", json!(1)),
            ("amr", json!(["mfa"])),
            ("acr", json!("mfa")),
        ] {
            let mut value_body = facts();
            value_body[field] = value;
            assert!(
                matches!(
                    response(200, HEADERS, value_body.to_string(), false).await,
                    Err(Error::Rejected)
                ),
                "field {field}"
            );
        }
        let mut ahead = facts();
        ahead["auth_time"] = json!(ahead["auth_time"].as_i64().unwrap() + 30);
        assert!(
            response(200, HEADERS, ahead.to_string(), false)
                .await
                .is_ok()
        );
    }
    #[tokio::test]
    async fn client_bounds_responses_and_keeps_safe_failure_ids() {
        for (status, code, unavailable) in [
            (400, "malformed_request", false),
            (401, "invalid_client", false),
            (401, "invalid_credential", false),
            (403, "identity_not_active", false),
            (429, "rate_limited", true),
            (503, "identity_unavailable", true),
        ] {
            let id = uuid::Uuid::new_v4();
            let body = json!({"code":code,"correlation_id":id}).to_string();
            let Err(error) = response(status, HEADERS, body, false).await else {
                panic!("failure accepted");
            };
            assert_eq!(error.correlation_id(), Some(id));
            assert_eq!(error.is_unavailable(), unavailable);
        }
        for (status, headers, body, delay) in [
            (200, "", facts().to_string(), false),
            (200, HEADERS, "invalid json".into(), false),
            (200, HEADERS, "x".repeat(65537), false),
            (
                302,
                "Cache-Control: no-store\r\nLocation: https://untrusted.invalid/\r\n",
                String::new(),
                false,
            ),
            (500, HEADERS, "private failure".into(), false),
            (200, HEADERS, facts().to_string(), true),
        ] {
            assert!(matches!(
                response(status, headers, body, delay).await,
                Err(Error::Unavailable)
            ));
        }
    }
    #[tokio::test]
    async fn clock_expiry_boundary_and_request_rollback_fail_closed() {
        for now in [1299, 1300, 1301] {
            let result = response_clock(
                200,
                HEADERS,
                facts().to_string(),
                false,
                Arc::new(FixedClock(now)),
            )
            .await;
            assert_eq!(result.is_ok(), now < 1300);
        }
        for times in [[1000, 999], [1299, 1300]] {
            let clock = Arc::new(SequenceClock(std::sync::Mutex::new(times.into())));
            assert!(
                response_clock(200, HEADERS, facts().to_string(), false, clock)
                    .await
                    .is_err()
            );
        }
    }
    #[test]
    fn wire_failure_code_and_status_are_closed() {
        for code in [
            ValidationFailureCode::MalformedRequest,
            ValidationFailureCode::InvalidClient,
            ValidationFailureCode::InvalidCredential,
            ValidationFailureCode::IdentityNotActive,
            ValidationFailureCode::IdentityUnavailable,
            ValidationFailureCode::RateLimited,
            ValidationFailureCode::CsrfRejected,
        ] {
            let bytes = serde_json::to_vec(&ValidationFailure {
                code,
                correlation_id: uuid::Uuid::new_v4().to_string(),
            })
            .unwrap();
            assert!(
                matches!(server_failure(code.http_status(),&bytes),Error::Server{code:actual,..} if actual==code)
            );
            assert!(matches!(server_failure(200, &bytes), Error::Unavailable));
        }
        let bytes =
            br#"{"code":"unknown","correlation_id":"22222222-2222-4222-8222-222222222222"}"#;
        assert!(serde_json::from_slice::<ValidationFailure>(bytes).is_err());
    }
}
