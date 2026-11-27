//! Local HTTPS protocol peer; counts physical TCP accepts and completed TLS handshakes separately.
use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use http::{HeaderMap, StatusCode, header};
use openssl::{
    asn1::Asn1Time,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    x509::{X509, X509NameBuilder, extension::SubjectAlternativeName},
};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    },
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Notify, Semaphore},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

#[derive(Default)]
pub(super) struct Counts {
    pub tcp: AtomicUsize,
    pub tls: AtomicUsize,
    pub discovery: AtomicUsize,
    pub jwks: AtomicUsize,
    pub post: AtomicUsize,
}
impl Counts {
    pub fn snapshot(&self) -> [usize; 5] {
        [
            &self.tcp,
            &self.tls,
            &self.discovery,
            &self.jwks,
            &self.post,
        ]
        .map(|n| n.load(SeqCst))
    }
}
struct Listener {
    socket: TcpListener,
    tls: TlsAcceptor,
    counts: Arc<Counts>,
}
impl axum::serve::Listener for Listener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, peer) = self.socket.accept().await.unwrap();
            self.counts.tcp.fetch_add(1, SeqCst);
            if let Ok(stream) = self.tls.accept(stream).await {
                self.counts.tls.fetch_add(1, SeqCst);
                return (stream, peer);
            }
        }
    }
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}
pub(super) struct Peer {
    pub issuer: String,
    pub ca: String,
    pub counts: Arc<Counts>,
    pub token: Mutex<String>,
    pub key_b: AtomicBool,
    pub alternate_uri: AtomicBool,
    pub keys_down: AtomicBool,
    pub keys_padding: AtomicUsize,
    pub hold: AtomicBool,
    pub entered: Notify,
    pub release: Semaphore,
    pub response_headers: Mutex<HeaderMap>,
    pub last_modified_only: AtomicBool,
    pub headers: Mutex<Vec<(String, Option<String>)>>,
}
impl Peer {
    pub async fn start() -> anyhow::Result<Arc<Self>> {
        let key = PKey::from_ec_key(EcKey::generate(
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?.as_ref(),
        )?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "OIDC loopback fixture")?;
        let name = name.build();
        let mut cert = X509::builder()?;
        cert.set_version(2)?;
        cert.set_subject_name(&name)?;
        cert.set_issuer_name(&name)?;
        cert.set_pubkey(&key)?;
        cert.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        cert.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
        let san = SubjectAlternativeName::new()
            .ip("127.0.0.1")
            .dns("localhost")
            .build(&cert.x509v3_context(None, None))?;
        cert.append_extension(san)?;
        cert.sign(&key, MessageDigest::sha256())?;
        let cert = cert.build();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.to_der()?.into()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.private_key_to_pkcs8()?).into(),
        )?;
        let socket = TcpListener::bind("127.0.0.1:0").await?;
        let counts = Arc::new(Counts::default());
        let peer = Arc::new(Self {
            issuer: format!("https://{}/realm", socket.local_addr()?),
            ca: String::from_utf8(cert.to_pem()?)?,
            counts: counts.clone(),
            token: Mutex::default(),
            key_b: false.into(),
            alternate_uri: false.into(),
            keys_down: false.into(),
            keys_padding: 0.into(),
            hold: false.into(),
            entered: Notify::new(),
            release: Semaphore::new(0),
            headers: Mutex::default(),
            response_headers: Mutex::default(),
            last_modified_only: false.into(),
        });
        let routes = Router::new()
            .route("/realm/.well-known/openid-configuration", get(discovery))
            .route("/realm/keys", get(keys))
            .route("/realm/next", get(keys))
            .route("/realm/token", post(token))
            .with_state(peer.clone());
        let listener = Listener {
            socket,
            tls: TlsAcceptor::from(Arc::new(config)),
            counts,
        };
        tokio::spawn(async move {
            axum::serve(listener, routes).await.unwrap();
        });
        Ok(peer)
    }
    async fn document(&self, path: &str, headers: HeaderMap, tag: &str, json: Value) -> Response {
        let lm = self.last_modified_only.load(SeqCst);
        let (validator, conditional, tag) = if lm {
            (
                header::LAST_MODIFIED,
                header::IF_MODIFIED_SINCE,
                "Fri, 01 Jan 2021 00:00:00 GMT",
            )
        } else {
            (header::ETAG, header::IF_NONE_MATCH, tag)
        };
        let condition = headers
            .get(conditional)
            .map(|v| v.to_str().unwrap().to_owned());
        self.headers
            .lock()
            .unwrap()
            .push((path.into(), condition.clone()));
        if self.hold.load(SeqCst) {
            self.entered.notify_one();
            self.release.acquire().await.unwrap().forget();
        }
        let mut response = if condition.as_deref() == Some(tag) {
            (StatusCode::NOT_MODIFIED, [(validator, tag)]).into_response()
        } else {
            ([(validator, tag)], Json(json)).into_response()
        };
        response
            .headers_mut()
            .extend(self.response_headers.lock().unwrap().clone());
        response
    }
}
async fn discovery(State(peer): State<Arc<Peer>>, headers: HeaderMap) -> Response {
    peer.counts.discovery.fetch_add(1, SeqCst);
    let moved = peer.alternate_uri.load(SeqCst);
    let mut json = json!({"issuer":peer.issuer,"authorization_endpoint":format!("{}/auth",peer.issuer),
      "token_endpoint":format!("{}/token",peer.issuer), "jwks_uri": format!("{}/{}",peer.issuer,if moved {"next"} else {"keys"}),
      "response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256","HS256"],
      "authorization_response_iss_parameter_supported":true});
    if moved {
        json["fixture_extension"] = json!("new metadata after the signing endpoint moved");
    }
    peer.document(
        "discovery",
        headers,
        if moved { "\"d2\"" } else { "\"d1\"" },
        json,
    )
    .await
}
async fn keys(
    State(peer): State<Arc<Peer>>,
    uri: axum::extract::OriginalUri,
    headers: HeaderMap,
) -> Response {
    peer.counts.jwks.fetch_add(1, SeqCst);
    if peer.keys_down.load(SeqCst) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let b = peer.key_b.load(SeqCst);
    let key: Value = serde_json::from_str(if b {
        include_str!("../../tests/fixtures/entra-b.json")
    } else {
        include_str!("../../tests/fixtures/entra-a.json")
    })
    .unwrap();
    peer.document(
        uri.path(),
        headers,
        if b { "\"b\"" } else { "\"a\"" },
        json!({"keys":[key],"padding":"x".repeat(peer.keys_padding.load(SeqCst))}),
    )
    .await
}
async fn token(State(peer): State<Arc<Peer>>) -> Json<Value> {
    peer.counts.post.fetch_add(1, SeqCst);
    Json(
        json!({"id_token":peer.token.lock().unwrap().clone(),"token_type":"Bearer","access_token":"fixture"}),
    )
}
