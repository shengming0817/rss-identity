//! HTTP-only platform client. Database and maintenance credentials are not dependencies.
mod browser;
mod store;
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum Error {
    #[error("invalid_input_or_private_file")]
    Input,
    #[error("reauthentication_required")]
    Authentication,
    #[error("request_rejected_or_conflict")]
    Conflict,
    #[error("service_unavailable_operation_not_completed")]
    Unavailable,
    #[error("operation_outcome_unknown_use_saved_operation_id")]
    Unknown,
    #[error("logout_not_confirmed_run_logout_again")]
    LogoutPending,
    #[error("session_busy")]
    Busy,
}
impl Error {
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Input => 2,
            Self::Authentication => 10,
            Self::Conflict => 11,
            Self::Unavailable => 12,
            Self::Unknown => 20,
            Self::LogoutPending => 21,
            Self::Busy => 22,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    format_version: u32,
    origin: String,
    system_domain_id: String,
    session_dir: PathBuf,
    ca_file: Option<PathBuf>,
    request_seconds: u64,
}
impl Config {
    fn load(path: &Path) -> Result<Self, Error> {
        let c: Self =
            serde_json::from_slice(&store::public(path, 16384)?).map_err(|_| Error::Input)?;
        let u = url::Url::parse(&c.origin).map_err(|_| Error::Input)?;
        if c.format_version != 1
            || u.scheme() != "https"
            || u.origin().ascii_serialization() != c.origin
            || !(1..=60).contains(&c.request_seconds)
            || id(c.system_domain_id.clone()).is_err()
        {
            return Err(Error::Input);
        }
        Ok(c)
    }
    fn route(&self, path: &str) -> String {
        format!("/api/v1/tenants/{}/{}", self.system_domain_id, path)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    principal_id: String,
    administrator: bool,
    platform_administrator: bool,
    has_local_password: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionInfo {
    id: String,
    auth_time: i64,
    idle_expires_at: i64,
    absolute_expires_at: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    version: u32,
    origin: String,
    system_domain_id: String,
    cookie: String,
    csrf_token: String,
    identity: Identity,
    session: SessionInfo,
    logout_pending: bool,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.cookie.zeroize();
        self.csrf_token.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issued {
    identity: Identity,
    session: SessionInfo,
    csrf_token: String,
}
fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(v) => v.iter_mut().for_each(wipe),
        Value::Object(v) => v.values_mut().for_each(wipe),
        _ => {}
    }
}
struct Reply {
    status: StatusCode,
    cookie: Option<Zeroizing<String>>,
    value: Value,
}
impl Drop for Reply {
    fn drop(&mut self) {
        wipe(&mut self.value);
    }
}
struct Client {
    http: reqwest::Client,
    config: Config,
}
impl Client {
    fn new(config: Config) -> Result<Self, Error> {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(config.request_seconds))
            .connect_timeout(Duration::from_secs(config.request_seconds.min(10)));
        if let Some(path) = &config.ca_file {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&store::public(path, 1024 * 1024)?)
                    .map_err(|_| Error::Input)?,
            );
        }
        Ok(Self {
            http: builder.build().map_err(|_| Error::Input)?,
            config,
        })
    }
    async fn request(
        &self,
        method: Method,
        path: &str,
        session: Option<&Session>,
        mut body: Option<Value>,
        business_write: bool,
    ) -> Result<Reply, Error> {
        let failure = || {
            if business_write {
                Error::Unknown
            } else {
                Error::Unavailable
            }
        };
        let mut request = self
            .http
            .request(method.clone(), format!("{}{}", self.config.origin, path))
            .header("origin", &self.config.origin)
            .header("x-identity-request", "1");
        if let Some(s) = session {
            request = request
                .header("cookie", format!("__Host-identity-session={}", s.cookie))
                .header("x-csrf-token", &s.csrf_token);
        }
        let bytes = if let Some(v) = body.as_mut() {
            let bytes = Zeroizing::new(serde_json::to_vec(v).map_err(|_| Error::Input)?);
            wipe(v);
            Some(bytes)
        } else {
            None
        };
        if let Some(bytes) = &bytes {
            request = request
                .header("content-type", "application/json")
                .body(bytes.to_vec());
        }
        let mut response = request.send().await.map_err(|_| failure())?;
        let status = response.status();
        let mut cookie = None;
        let mut cookie_seen = false;
        for value in response.headers().get_all("set-cookie") {
            let text = value.to_str().map_err(|_| failure())?;
            if let Some(value) = text
                .split(';')
                .next()
                .and_then(|v| v.strip_prefix("__Host-identity-session="))
            {
                if cookie_seen {
                    return Err(failure());
                }
                cookie_seen = true;
                if value.is_empty() {
                    continue;
                }
                if value.len() != 64
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(failure());
                }
                cookie = Some(Zeroizing::new(value.to_owned()));
            }
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| failure())? {
            if bytes.len() + chunk.len() > 65536 {
                return Err(failure());
            }
            bytes.extend_from_slice(&chunk);
        }
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|_| failure())?
        };
        Ok(Reply {
            status,
            cookie,
            value,
        })
    }
    fn classify(reply: &Reply, write: bool) -> Error {
        match reply.status.as_u16() {
            401 | 403 => Error::Authentication,
            400 | 409 | 429 => Error::Conflict,
            503 if reply.value.get("code").and_then(Value::as_str)
                == Some("operation_not_completed") =>
            {
                Error::Unavailable
            }
            _ if write => Error::Unknown,
            _ => Error::Unavailable,
        }
    }
    fn issued(&self, mut reply: Reply) -> Result<Session, Error> {
        if !reply.status.is_success() {
            return Err(Self::classify(&reply, false));
        }
        let value: Issued = serde_json::from_value(std::mem::take(&mut reply.value))
            .map_err(|_| Error::Authentication)?;
        let secret = reply.cookie.take().ok_or(Error::Authentication)?;
        if !value.identity.platform_administrator
            || value.identity.administrator
            || value.csrf_token.len() != 64
        {
            return Err(Error::Authentication);
        }
        Ok(Session {
            version: 1,
            origin: self.config.origin.clone(),
            system_domain_id: self.config.system_domain_id.clone(),
            cookie: secret.to_string(),
            csrf_token: value.csrf_token,
            identity: value.identity,
            session: value.session,
            logout_pending: false,
        })
    }
    fn check_local(&self, s: &Session) -> Result<(), Error> {
        if s.version != 1
            || s.origin != self.config.origin
            || s.system_domain_id != self.config.system_domain_id
            || s.cookie.len() != 64
            || !s.identity.platform_administrator
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    async fn logout(&self, store: &store::Store, mut s: Session) -> Result<(), Error> {
        self.check_local(&s)?;
        let result = self
            .request(
                Method::GET,
                &self.config.route("session"),
                Some(&s),
                None,
                false,
            )
            .await;
        if matches!(&result,Ok(v) if v.status==StatusCode::UNAUTHORIZED) {
            store.clear()?;
            return Ok(());
        }
        if matches!(&result,Ok(v) if v.status.is_success()) {
            let result = self
                .request(
                    Method::POST,
                    &self.config.route("session/logout"),
                    Some(&s),
                    Some(json!({})),
                    false,
                )
                .await;
            if matches!(result,Ok(v) if v.status==StatusCode::NO_CONTENT || v.status==StatusCode::UNAUTHORIZED)
            {
                store.clear()?;
                return Ok(());
            }
        }
        s.logout_pending = true;
        store.save(&s)?;
        Err(Error::LogoutPending)
    }
    async fn active(&self, store: &store::Store) -> Result<Session, Error> {
        let s = store.load()?.ok_or(Error::Authentication)?;
        self.check_local(&s)?;
        if s.logout_pending {
            return Err(Error::LogoutPending);
        }
        let reply = self
            .request(
                Method::GET,
                &self.config.route("session"),
                Some(&s),
                None,
                false,
            )
            .await?;
        if reply.status == StatusCode::UNAUTHORIZED {
            store.clear()?;
            return Err(Error::Authentication);
        }
        if !reply.status.is_success() {
            return Err(Self::classify(&reply, false));
        }
        let result = self
            .request(
                Method::POST,
                &self.config.route("session/refresh"),
                Some(&s),
                Some(json!({})),
                false,
            )
            .await;
        let next = match result.and_then(|r| self.issued(r)) {
            Ok(s) => s,
            Err(_) => {
                store.clear()?;
                return Err(Error::Authentication);
            }
        };
        if next.session.id != s.session.id
            || next.identity.principal_id != s.identity.principal_id
            || next.session.absolute_expires_at != s.session.absolute_expires_at
        {
            store.clear()?;
            return Err(Error::Authentication);
        }
        if store.save(&next).is_err() {
            let _ = store.clear();
            return Err(Error::Authentication);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Input)?
            .as_secs() as i64;
        if next.session.absolute_expires_at - now <= self.config.request_seconds as i64 {
            return Err(Error::Authentication);
        }
        Ok(next)
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    operation_id: uuid::Uuid,
    kind: String,
    tenant_id: String,
    principal_id: uuid::Uuid,
    created_at: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationReply {
    operation: Operation,
    active: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Tenant {
    tenant_id: String,
    name: String,
    initial_principal_id: uuid::Uuid,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TenantPage {
    tenants: Vec<Tenant>,
    next_cursor: Option<String>,
}
fn options(args: &[String]) -> Result<BTreeMap<String, String>, Error> {
    let mut result = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let key = &args[i];
        if !key.starts_with("--") {
            return Err(Error::Input);
        }
        let value = if key == "--sso" {
            i += 1;
            String::new()
        } else {
            let v = args.get(i + 1).ok_or(Error::Input)?.clone();
            i += 2;
            v
        };
        if result.insert(key.clone(), value).is_some() {
            return Err(Error::Input);
        }
    }
    Ok(result)
}
fn take(o: &mut BTreeMap<String, String>, key: &str) -> Result<String, Error> {
    o.remove(key).ok_or(Error::Input)
}
fn id(value: String) -> Result<String, Error> {
    let id = uuid::Uuid::parse_str(&value).map_err(|_| Error::Input)?;
    if id.is_nil() {
        return Err(Error::Input);
    }
    Ok(id.to_string())
}
pub fn usage() -> &'static str {
    "identity-platform --config FILE COMMAND\n  login --login NAME --password-file FILE\n  login --sso --provider UUID\n  logout\n  tenant create --tenant UUID --name NAME --principal UUID --login NAME --password-file FILE --operation UUID\n  tenant admin add --tenant UUID --principal UUID --login NAME --password-file FILE --operation UUID\n  tenant list [--cursor UUID] [--limit 1..100]\n  operation status --operation UUID\nPasswords are read from private files. Never retry an unknown write automatically."
}
pub async fn run(args: Vec<String>) -> Result<(i32, Value), Error> {
    if args.len() < 3 || args[0] != "--config" {
        return Err(Error::Input);
    }
    let c = Config::load(Path::new(&args[1]))?;
    let store = store::Store::lock(&c.session_dir)?;
    let client = Client::new(c)?;
    let end = args[2..]
        .iter()
        .position(|v| v.starts_with("--"))
        .map(|v| v + 2)
        .unwrap_or(args.len());
    let command = args[2..end].join(" ");
    let mut opts = options(&args[end..])?;
    if command == "logout" {
        if !opts.is_empty() {
            return Err(Error::Input);
        }
        if let Some(s) = store.load()? {
            client.logout(&store, s).await?;
        }
        return Ok((0, json!({"logged_out":true})));
    }
    if command == "login" {
        let sso = opts.remove("--sso").is_some();
        let (provider, login, password) = if sso {
            (Some(id(take(&mut opts, "--provider")?)?), None, None)
        } else {
            (
                None,
                Some(take(&mut opts, "--login")?),
                Some(store::secret(Path::new(&take(
                    &mut opts,
                    "--password-file",
                )?))?),
            )
        };
        if !opts.is_empty() {
            return Err(Error::Input);
        }
        if let Some(s) = store.load()? {
            client.logout(&store, s).await?;
        }
        let reply = if let Some(provider) = provider {
            browser::login(&client, &provider).await?
        } else {
            client
                .request(
                    Method::POST,
                    &client.config.route("login"),
                    None,
                    Some(json!({"login":login,"password":password.as_deref().map(|v|v.as_str())})),
                    false,
                )
                .await?
        };
        let session = client.issued(reply)?;
        store.save(&session)?;
        return Ok((
            0,
            json!({"principal_id":session.identity.principal_id,"session_id":session.session.id,"absolute_expires_at":session.session.absolute_expires_at}),
        ));
    }
    let mut expected_operation = None;
    let mut expected_account = None;
    let (method, path, body, write) = match command.as_str() {
        "tenant create" | "tenant admin add" => {
            let tenant = id(take(&mut opts, "--tenant")?)?;
            let principal = id(take(&mut opts, "--principal")?)?;
            let operation = id(take(&mut opts, "--operation")?)?;
            expected_operation = Some(operation.clone());
            expected_account = Some((tenant.clone(), principal.clone()));
            let login = take(&mut opts, "--login")?;
            let password = store::secret(Path::new(&take(&mut opts, "--password-file")?))?;
            let admin = json!({"operation_id":operation,"principal_id":principal,"login":login,"password":password.as_str()});
            if command == "tenant create" {
                let name = take(&mut opts, "--name")?;
                (
                    Method::POST,
                    "/api/v1/platform/tenants".into(),
                    Some(json!({"tenant_id":tenant,"name":name,"administrator":admin})),
                    true,
                )
            } else {
                (
                    Method::POST,
                    format!("/api/v1/platform/tenants/{tenant}/administrators"),
                    Some(admin),
                    true,
                )
            }
        }
        "tenant list" => {
            let mut u =
                url::Url::parse(&format!("{}/api/v1/platform/tenants", client.config.origin))
                    .map_err(|_| Error::Input)?;
            if let Some(cursor) = opts.remove("--cursor") {
                u.query_pairs_mut().append_pair("cursor", &id(cursor)?);
            }
            if let Some(limit) = opts.remove("--limit") {
                let n: u16 = limit.parse().map_err(|_| Error::Input)?;
                if !(1..=100).contains(&n) {
                    return Err(Error::Input);
                }
                u.query_pairs_mut().append_pair("limit", &n.to_string());
            }
            (
                Method::GET,
                format!(
                    "{}{}",
                    u.path(),
                    u.query().map(|v| format!("?{v}")).unwrap_or_default()
                ),
                None,
                false,
            )
        }
        "operation status" => {
            let operation = id(take(&mut opts, "--operation")?)?;
            expected_operation = Some(operation.clone());
            (
                Method::GET,
                format!("/api/v1/platform/operations/{operation}"),
                None,
                false,
            )
        }
        _ => return Err(Error::Input),
    };
    if !opts.is_empty() {
        return Err(Error::Input);
    }
    let session = client.active(&store).await?;
    let mut reply = client
        .request(method, &path, Some(&session), body, write)
        .await?;
    if reply.status == StatusCode::NOT_FOUND && command == "operation status" {
        return Ok((20, json!({"status":"not_observed","safe_to_retry":false})));
    }
    if !reply.status.is_success() {
        return Err(Client::classify(&reply, write));
    }
    let value = std::mem::take(&mut reply.value);
    if command == "tenant list" {
        let page: TenantPage = serde_json::from_value(value).map_err(|_| Error::Unavailable)?;
        return Ok((
            0,
            serde_json::to_value(page).map_err(|_| Error::Unavailable)?,
        ));
    }
    let operation: OperationReply = serde_json::from_value(value).map_err(|_| {
        if write {
            Error::Unknown
        } else {
            Error::Unavailable
        }
    })?;
    if !matches!(
        operation.operation.kind.as_str(),
        "tenant_created" | "administrator_added"
    ) || expected_operation.as_deref()
        != Some(operation.operation.operation_id.to_string().as_str())
        || expected_account.is_some_and(|(tenant, principal)| {
            tenant != operation.operation.tenant_id
                || principal != operation.operation.principal_id.to_string()
                || operation.operation.kind
                    != if command == "tenant create" {
                        "tenant_created"
                    } else {
                        "administrator_added"
                    }
        })
    {
        return Err(Error::Unknown);
    }
    Ok((
        if operation.active { 0 } else { 3 },
        serde_json::to_value(operation).map_err(|_| Error::Unknown)?,
    ))
}

#[cfg(test)]
mod tests;
