//! Fixed, disposable browser consumer; not an MDM implementation or production BFF.
//! ref: axum axum-v0.8.9 axum/src/serve/mod.rs.
use axum::{
    Json, Router,
    extract::{Query, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use identity_consumer_proof::{Pending, Product, ProductConfig, ProductSession};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    listen: String,
    product_origin: String,
    issuer: String,
    validation_origin: String,
    ca_file: String,
    public_address: String,
    clients: Vec<Client>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Client {
    client_id: String,
    tenant_id: String,
    audience: String,
    oidc_secret_file: String,
    validation_secret_file: String,
}
struct Flow {
    product: String,
    pending: Pending,
    until: Instant,
}
struct Session {
    product: String,
    value: Arc<ProductSession>,
    until: Instant,
}
struct App {
    origin: String,
    products: BTreeMap<String, Product>,
    flows: Mutex<BTreeMap<String, Flow>>,
    sessions: Mutex<BTreeMap<String, Session>>,
}
fn secret(path: &str) -> anyhow::Result<Zeroizing<String>> {
    use std::os::unix::fs::PermissionsExt;
    let p = Path::new(path);
    let m = p.symlink_metadata()?;
    anyhow::ensure!(
        m.file_type().is_file() && m.permissions().mode() & 0o077 == 0 && m.len() <= 16384,
        "private file rejected"
    );
    Ok(Zeroizing::new(std::fs::read_to_string(p)?))
}
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut values = headers
        .get_all("cookie")
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|s| s.split(';'))
        .filter_map(|s| s.trim().split_once('='))
        .filter(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned());
    let value = values.next()?;
    (values.next().is_none() && value.len() <= 128).then_some(value)
}
fn issue(name: &str, value: &str) -> String {
    let age = if name == "__Host-t33-session" {
        1800
    } else {
        300
    };
    format!("{name}={value}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age={age}")
}
fn failure(status: StatusCode) -> Response {
    (status, Json(json!({"code": if status == StatusCode::SERVICE_UNAVAILABLE {"identity_unavailable"} else {"invalid_credential"}}))).into_response()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    client_id: String,
}
async fn login(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<Login>,
) -> Response {
    if headers.get("origin").and_then(|v| v.to_str().ok()) != Some(&app.origin)
        || headers.get("x-t33-request").and_then(|v| v.to_str().ok()) != Some("1")
    {
        return failure(StatusCode::FORBIDDEN);
    }
    let Some(product) = app.products.get(&input.client_id) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let (url, pending) = product.begin();
    let handle = openidconnect::CsrfToken::new_random().secret().clone();
    let mut flows = app.flows.lock().unwrap();
    flows.retain(|_, v| v.until > Instant::now());
    if flows.len() >= 32 {
        return failure(StatusCode::SERVICE_UNAVAILABLE);
    }
    if let Some(old) = cookie(&headers, "__Host-t33-browser") {
        flows.remove(&old);
    }
    flows.insert(
        handle.clone(),
        Flow {
            product: input.client_id,
            pending,
            until: Instant::now() + Duration::from_secs(300),
        },
    );
    let mut response = Json(json!({"authorization_url": url.as_str()})).into_response();
    response.headers_mut().insert(
        "set-cookie",
        issue("__Host-t33-browser", &handle).parse().unwrap(),
    );
    response
}
async fn callback(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let Some(handle) = cookie(&headers, "__Host-t33-browser") else {
        return failure(StatusCode::UNAUTHORIZED);
    };
    let flow = app.flows.lock().unwrap().remove(&handle);
    let Some(flow) = flow.filter(|v| v.until > Instant::now()) else {
        return failure(StatusCode::UNAUTHORIZED);
    };
    let Some(query) = query.filter(|q| q.len() <= 8192) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let Ok(url) = reqwest::Url::parse(&format!("{}/auth/callback?{}", app.origin, query)) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    let value = match app.products[&flow.product]
        .exchange(flow.pending, &url)
        .await
    {
        Ok(value) => value,
        Err(_) => return failure(StatusCode::UNAUTHORIZED),
    };
    let handle = openidconnect::CsrfToken::new_random().secret().clone();
    let mut sessions = app.sessions.lock().unwrap();
    sessions.retain(|_, v| v.until > Instant::now());
    if sessions.len() >= 32 {
        return failure(StatusCode::SERVICE_UNAVAILABLE);
    }
    if let Some(old) = cookie(&headers, "__Host-t33-session") {
        sessions.remove(&old);
    }
    sessions.insert(
        handle.clone(),
        Session {
            product: flow.product,
            value: Arc::new(value),
            until: Instant::now() + Duration::from_secs(1800),
        },
    );
    let mut response = Redirect::to("/session").into_response();
    response.headers_mut().insert(
        "set-cookie",
        issue("__Host-t33-session", &handle).parse().unwrap(),
    );
    response
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Comparison {
    client_id: Option<String>,
}
async fn session(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(comparison): Query<Comparison>,
) -> Response {
    let Some(handle) = cookie(&headers, "__Host-t33-session") else {
        return failure(StatusCode::UNAUTHORIZED);
    };
    let value = app
        .sessions
        .lock()
        .unwrap()
        .get(&handle)
        .filter(|s| s.until > Instant::now())
        .map(|s| (s.product.clone(), s.value.clone()));
    let Some((product, session)) = value else {
        return failure(StatusCode::UNAUTHORIZED);
    };
    let comparison = comparison.client_id.as_deref().unwrap_or(&product);
    let Some(verifier) = app.products.get(comparison) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    match verifier.verify(&session).await {
        Ok(facts) => Json(json!({"subject": facts.subject(), "session_id": facts.session_id(),
            "tenant_id": facts.tenant_id(), "client_id": facts.client_id(), "audience": facts.audience(),
            "issuer": facts.issuer()})).into_response(),
        Err(error) => failure(if error.is_unavailable() { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::UNAUTHORIZED }),
    }
}
async fn execute() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("configuration required"))?;
    let config: Config = serde_json::from_str(&secret(&path)?)?;
    let ca = std::fs::read(&config.ca_file)?;
    let issuer = reqwest::Url::parse(&config.issuer)?;
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
        .resolve(
            issuer
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("issuer host missing"))?,
            config.public_address.parse()?,
        )
        .build()?;
    let mut products = BTreeMap::new();
    for c in config.clients {
        let id = c.client_id.clone();
        let p = Product::discover(
            ProductConfig {
                issuer: config.issuer.clone(),
                client_id: c.client_id,
                audience: c.audience,
                redirect_uri: format!("{}/auth/callback", config.product_origin),
                identity_origin: config.validation_origin.clone(),
                tenant_id: c.tenant_id,
                oidc_secret: secret(&c.oidc_secret_file)?,
                validation_secret: secret(&c.validation_secret_file)?,
                ca_pem: ca.clone(),
            },
            http.clone(),
        )
        .await?;
        anyhow::ensure!(products.insert(id, p).is_none(), "duplicate client");
    }
    anyhow::ensure!(!products.is_empty(), "no clients");
    let app = Arc::new(App {
        origin: config.product_origin,
        products,
        flows: Mutex::new(BTreeMap::new()),
        sessions: Mutex::new(BTreeMap::new()),
    });
    let router = Router::new()
        .route("/auth/login", post(login))
        .route(
            "/auth/callback",
            get(callback).head(|| async { StatusCode::METHOD_NOT_ALLOWED }),
        )
        .route("/session", get(session))
        .route("/ready", get(|| async { StatusCode::NO_CONTENT }))
        .layer(axum::middleware::map_response(
            |mut response: Response| async move {
                response
                    .headers_mut()
                    .insert("cache-control", "no-store".parse().unwrap());
                response
                    .headers_mut()
                    .insert("referrer-policy", "no-referrer".parse().unwrap());
                response
            },
        ))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
#[tokio::main]
async fn main() {
    if execute().await.is_err() {
        eprintln!("T33 consumer unavailable");
        std::process::exit(1);
    }
}
