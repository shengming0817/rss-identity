use crate::{HttpConfig, boundary};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_identity_contracts::{ValidationFailure, ValidationFailureCode, ValidationRequest};
use rss_identity_core::downstream::{BrowserBindingSecret, DownstreamError, Secret};
use rss_identity_postgres::{AuthorityError, Downstream, FlowHandle};
use rss_transactional_messaging::policy::OperationDeadline;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc, time::Instant};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
const BROWSER: &str = "__Host-identity-downstream-browser";
#[derive(Clone)]
struct Http {
    service: Downstream,
    config: HttpConfig,
    clients: Arc<BTreeMap<String, [u8; 32]>>,
}
#[derive(Clone, Copy)]
struct Budget(Instant);
impl Budget {
    fn remaining(self) -> OperationDeadline {
        OperationDeadline::from_remaining(self.0.saturating_duration_since(Instant::now()))
    }
}
struct Failure {
    code: ValidationFailureCode,
    diagnostic: Option<crate::HttpFailure>,
}
#[derive(Clone, Copy)]
struct ErrorCode(ValidationFailureCode);
/// Safe response extension for host logging; its ID is identical to the public error body.
#[derive(Debug, Clone, Copy)]
pub struct DownstreamDiagnostic {
    pub correlation_id: uuid::Uuid,
    pub code: ValidationFailureCode,
    pub failure: Option<crate::HttpFailure>,
}
impl Failure {
    fn new(code: ValidationFailureCode) -> Self {
        Self {
            code,
            diagnostic: None,
        }
    }
    fn timeout() -> Self {
        Self {
            code: ValidationFailureCode::IdentityUnavailable,
            diagnostic: Some(crate::HttpFailure::RequestTimeout),
        }
    }
}
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let mut r = StatusCode::from_u16(self.code.http_status())
            .expect("valid contract status")
            .into_response();
        r.extensions_mut().insert(ErrorCode(self.code));
        if let Some(diagnostic) = self.diagnostic {
            r.extensions_mut().insert(diagnostic);
        }
        r
    }
}
impl From<AuthorityError> for Failure {
    fn from(e: AuthorityError) -> Self {
        let mut failure = match e {
            AuthorityError::RateLimited => Self::new(ValidationFailureCode::RateLimited),
            AuthorityError::Invalid | AuthorityError::Downstream(DownstreamError::Invalid) => {
                Self::new(ValidationFailureCode::MalformedRequest)
            }
            AuthorityError::Downstream(DownstreamError::Inactive) => {
                Self::new(ValidationFailureCode::IdentityNotActive)
            }
            AuthorityError::Rejected | AuthorityError::Downstream(DownstreamError::Rejected) => {
                Self::new(ValidationFailureCode::InvalidCredential)
            }
            _ => Self::new(ValidationFailureCode::IdentityUnavailable),
        };
        failure.diagnostic = Some(crate::HttpFailure::Authority(e));
        failure
    }
}
impl From<DownstreamError> for Failure {
    fn from(e: DownstreamError) -> Self {
        AuthorityError::from(e).into()
    }
}
fn bad() -> Failure {
    Failure::new(ValidationFailureCode::MalformedRequest)
}
fn unauthorized() -> Failure {
    Failure::new(ValidationFailureCode::InvalidCredential)
}
fn required(headers: &HeaderMap, name: &str) -> Result<String, Failure> {
    boundary::unique(headers, name)
        .map_err(|_| bad())?
        .map(Into::into)
        .ok_or_else(bad)
}
/// Mount alongside the central/federated routers. Credentials are version-resolved deployment secrets.
pub fn downstream_router(
    service: Downstream,
    config: HttpConfig,
    secrets: BTreeMap<String, Zeroizing<String>>,
) -> Result<Router, AuthorityError> {
    let expected: std::collections::BTreeSet<_> = service.clients().map(String::from).collect();
    if secrets
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        != expected
    {
        return Err(AuthorityError::Invalid);
    }
    let mut clients = BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    for (id, secret) in secrets {
        if id.contains(':') || secret.len() < 32 || secret.len() > 4096 {
            return Err(AuthorityError::Invalid);
        }
        let digest: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        if !seen.insert(digest) {
            return Err(AuthorityError::Invalid);
        }
        clients.insert(id, digest);
    }
    let s = Http {
        service,
        config,
        clients: Arc::new(clients),
    };
    Ok(Router::new()
        .route("/api/v1/downstream/login", post(begin))
        .route("/api/v1/downstream/login/accept", post(accept_login))
        .route("/api/v1/downstream/consent", post(consent))
        .route("/api/v1/downstream/consent/accept", post(accept_consent))
        .route("/internal/v1/identity/validate", post(validate))
        .layer(DefaultBodyLimit::max(32768))
        .layer(middleware::from_fn_with_state(s.clone(), boundary_layer))
        .with_state(s))
}
async fn boundary_layer(State(s): State<Http>, mut req: Request, next: Next) -> Response {
    req.extensions_mut()
        .insert(Budget(Instant::now() + s.config.timeout));
    let fail = if req.uri().to_string().len() > 8192 {
        Some(bad())
    } else if req.uri().path().starts_with("/api/")
        && (boundary::unique(req.headers(), "origin").ok().flatten() != Some(&s.config.origin)
            || boundary::unique(req.headers(), "x-identity-request")
                .ok()
                .flatten()
                != Some("1"))
    {
        Some(Failure::new(ValidationFailureCode::CsrfRejected))
    } else if req.uri().path() == "/internal/v1/identity/validate" {
        match authenticate(&s, req.headers()) {
            Ok(caller) => {
                req.extensions_mut().insert(caller);
                None
            }
            Err(error) => Some(error),
        }
    } else {
        None
    };
    let mut r = if let Some(e) = fail {
        e.into_response()
    } else {
        let deadline = req
            .extensions()
            .get::<Budget>()
            .expect("installed request budget")
            .0;
        let (parts, body) = req.into_parts();
        // Only body acquisition is cancelled. PG settlement remains owned by Authority/RSS.
        match tokio::time::timeout_at(deadline.into(), axum::body::to_bytes(body, 32768)).await {
            Ok(Ok(bytes)) => {
                next.run(Request::from_parts(parts, axum::body::Body::from(bytes)))
                    .await
            }
            Ok(Err(_)) => Failure::new(ValidationFailureCode::MalformedRequest).into_response(),
            Err(_) => Failure::timeout().into_response(),
        }
    };
    if !r.status().is_success() {
        let status = r.status();
        let code = r.extensions().get::<ErrorCode>().map(|v| v.0).unwrap_or(
            if status == StatusCode::SERVICE_UNAVAILABLE {
                ValidationFailureCode::IdentityUnavailable
            } else {
                ValidationFailureCode::MalformedRequest
            },
        );
        let failure = r.extensions().get::<crate::HttpFailure>().copied();
        let extensions = std::mem::take(r.extensions_mut());
        let correlation_id = uuid::Uuid::new_v4();
        r = (
            StatusCode::from_u16(code.http_status()).expect("valid contract status"),
            Json(ValidationFailure {
                code,
                correlation_id: correlation_id.to_string(),
            }),
        )
            .into_response();
        r.extensions_mut().extend(extensions);
        r.extensions_mut().insert(DownstreamDiagnostic {
            correlation_id,
            code,
            failure,
        });
    }
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    r.headers_mut().insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    r
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeInput {
    challenge: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptInput {
    flow: FlowHandle,
    challenge: String,
}
fn browser(h: &HeaderMap) -> Result<BrowserBindingSecret, Failure> {
    let s = boundary::named_cookie(h, BROWSER)
        .map_err(|_| bad())?
        .ok_or_else(unauthorized)?;
    BrowserBindingSecret::parse(s.into()).map_err(|_| unauthorized())
}
async fn begin(
    State(s): State<Http>,
    axum::Extension(b): axum::Extension<Budget>,
    h: HeaderMap,
    Json(v): Json<ChallengeInput>,
) -> Result<Response, Failure> {
    let existing = boundary::named_cookie(&h, BROWSER).map_err(|_| bad())?;
    let secret = if let Some(x) = existing {
        BrowserBindingSecret::parse(x.into()).map_err(|_| unauthorized())?
    } else {
        BrowserBindingSecret::generate().map_err(|_| bad())?
    };
    let cookie = if existing.is_none() {
        Some(format!(
            "{BROWSER}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600",
            secret.expose()
        ))
    } else {
        None
    };
    let flow = s
        .service
        .begin_login(Secret::new(v.challenge)?, secret, b.remaining())
        .await?;
    let mut response = Json(flow).into_response();
    if let Some(c) = cookie {
        response
            .headers_mut()
            .insert(header::SET_COOKIE, c.parse().map_err(|_| bad())?);
    }
    Ok(response)
}
async fn actor(
    s: &Http,
    h: &HeaderMap,
    f: &FlowHandle,
    b: Budget,
) -> Result<rss_identity_postgres::AuthenticatedSession, Failure> {
    let cookie = boundary::cookie(h)
        .map_err(|_| unauthorized())?
        .ok_or_else(unauthorized)?;
    boundary::csrf(h, &cookie).map_err(|_| Failure::new(ValidationFailureCode::CsrfRejected))?;
    let tenant = rss_request_context::TenantId::parse(&f.tenant_id).map_err(|_| bad())?;
    Ok(s.service
        .authority()
        .inspect_session(tenant, cookie, b.remaining())
        .await?)
}
async fn accept_login(
    State(s): State<Http>,
    axum::Extension(b): axum::Extension<Budget>,
    h: HeaderMap,
    Json(v): Json<AcceptInput>,
) -> Result<Json<serde_json::Value>, Failure> {
    let proof = actor(&s, &h, &v.flow, b).await?;
    let redirect = s
        .service
        .accept_login(
            v.flow,
            Secret::new(v.challenge)?,
            browser(&h)?,
            proof,
            b.remaining(),
        )
        .await?;
    Ok(Json(serde_json::json!({"redirect_to":redirect.expose()})))
}
async fn consent(
    State(s): State<Http>,
    axum::Extension(b): axum::Extension<Budget>,
    h: HeaderMap,
    Json(v): Json<ChallengeInput>,
) -> Result<Json<FlowHandle>, Failure> {
    Ok(Json(
        s.service
            .inspect_consent(&Secret::new(v.challenge)?, &browser(&h)?, b.remaining())
            .await?,
    ))
}
async fn accept_consent(
    State(s): State<Http>,
    axum::Extension(b): axum::Extension<Budget>,
    h: HeaderMap,
    Json(v): Json<AcceptInput>,
) -> Result<Json<serde_json::Value>, Failure> {
    let proof = actor(&s, &h, &v.flow, b).await?;
    let redirect = s
        .service
        .accept_consent(
            v.flow,
            Secret::new(v.challenge)?,
            browser(&h)?,
            proof,
            b.remaining(),
        )
        .await?;
    Ok(Json(serde_json::json!({"redirect_to":redirect.expose()})))
}
async fn validate(
    State(s): State<Http>,
    axum::Extension(b): axum::Extension<Budget>,
    axum::Extension(Caller(client)): axum::Extension<Caller>,
    Json(v): Json<ValidationRequest>,
) -> Result<Json<rss_identity_contracts::IdentityFacts>, Failure> {
    let tenant = rss_request_context::TenantId::parse(&v.tenant_id).map_err(|_| bad())?;
    let proof = s
        .service
        .validate(
            &client,
            tenant,
            &v.audience,
            Secret::new(v.credential)?,
            b.remaining(),
        )
        .await?;
    Ok(Json(rss_identity_contracts::IdentityFacts {
        subject: proof.subject().to_owned(),
        tenant_id: proof.tenant_id().to_owned(),
        session_id: proof.session_id().to_owned(),
        client_id: proof.client_id().to_owned(),
        audience: proof.audience().to_owned(),
        issuer: proof.issuer().to_owned(),
        auth_time: proof.auth_time(),
        amr: proof.amr().to_owned(),
        acr: proof.acr(),
        expires_at: proof.expires_at(),
    }))
}

#[derive(Clone)]
struct Caller(String);
fn authenticate(s: &Http, h: &HeaderMap) -> Result<Caller, Failure> {
    let invalid = || Failure::new(ValidationFailureCode::InvalidClient);
    let authorization = Zeroizing::new(required(h, "authorization").map_err(|_| invalid())?);
    let encoded = authorization.strip_prefix("Basic ").ok_or_else(invalid)?;
    if encoded.len() > 8192 {
        return Err(invalid());
    }
    let decoded = Zeroizing::new(STANDARD.decode(encoded).map_err(|_| invalid())?);
    let text = std::str::from_utf8(&decoded).map_err(|_| invalid())?;
    let (client, secret) = text.split_once(':').ok_or_else(invalid)?;
    let hash: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
    let expected = s.clients.get(client).ok_or_else(invalid)?;
    if !bool::from(hash.ct_eq(expected)) {
        return Err(invalid());
    }
    Ok(Caller(client.to_owned()))
}
