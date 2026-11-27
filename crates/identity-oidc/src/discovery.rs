//! Bounded discovery using the existing vetted transport; JWT verification has one owner.
//! ref: openidconnect-rs src/discovery/mod.rs @ b639b5d39eac6903238867aeb2b29326502e6b26.
use super::{
    Channel, Transport, failure,
    resources::{ByteLease, Resources},
};
use futures_util::{
    FutureExt,
    future::{BoxFuture, WeakShared},
};
use http::{HeaderMap, HeaderValue, header};
use rss_identity_core::federation::{FederationError, ProviderReason, ProviderStage};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use url::Url;

#[derive(Default, Deserialize, Serialize)]
pub(super) struct Jwks {
    pub keys: Vec<serde_json::Value>,
}
#[derive(Deserialize)]
pub(super) struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Option<TokenEndpoint>,
    pub jwks_uri: Url,
    #[serde(rename = "response_types_supported")]
    _response_types_supported: Vec<String>,
    #[serde(rename = "subject_types_supported")]
    _subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
}

impl Metadata {
    pub(super) fn bound_token_endpoint(&self, registered: &str) -> Result<&str, FederationError> {
        self.token_endpoint
            .as_ref()
            .filter(|endpoint| endpoint.advertised == registered)
            .map(|endpoint| endpoint.advertised.as_str())
            .ok_or(FederationError::Configuration)
    }
}

#[derive(Deserialize)]
#[serde(try_from = "String")]
pub(super) struct TokenEndpoint {
    pub url: Url,
    // The enterprise exchange compares the advertised endpoint against the exact host binding.
    advertised: String,
}

impl TryFrom<String> for TokenEndpoint {
    type Error = url::ParseError;

    fn try_from(advertised: String) -> Result<Self, Self::Error> {
        let url = Url::parse(&advertised)?;
        Ok(Self { url, advertised })
    }
}

pub(super) enum Kind {
    Discovery { issuer: String },
    Keys { uri: Url },
}
impl Kind {
    pub async fn probe(
        &self,
        t: &Transport,
        resources: &Resources,
    ) -> Result<Vec<u8>, FederationError> {
        let stage = self.stage();
        let _permit = resources
            .refreshes
            .clone()
            .try_acquire_owned()
            .map_err(|_| failure(stage, ProviderReason::Unavailable))?;
        let request = http::Request::get(self.url())
            .header(header::ACCEPT, "application/json")
            .body(Vec::new())
            .map_err(|_| invalid(stage))?;
        let response = t.call(stage, request).await?;
        if response.status() != http::StatusCode::OK || !valid_media(response.headers(), stage) {
            return Err(invalid(stage));
        }
        self.validate(response.body(), &t.channel)?;
        Ok(response.into_body())
    }
    fn stage(&self) -> ProviderStage {
        match self {
            Self::Discovery { .. } => ProviderStage::Discovery,
            Self::Keys { .. } => ProviderStage::Jwks,
        }
    }
    fn url(&self) -> String {
        match self {
            Self::Discovery { issuer } => format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            ),
            Self::Keys { uri } => uri.to_string(),
        }
    }
    fn validate(&self, bytes: &[u8], channel: &Channel) -> Result<Option<Url>, FederationError> {
        match self {
            Self::Discovery { issuer } => {
                let metadata: Metadata = decode(bytes, self.stage())?;
                if metadata.issuer != *issuer {
                    return Err(failure(self.stage(), ProviderReason::IssuerMismatch));
                }
                let token = metadata
                    .token_endpoint
                    .ok_or_else(|| failure(self.stage(), ProviderReason::EgressDenied))?;
                for url in [
                    &metadata.authorization_endpoint,
                    &token.url,
                    &metadata.jwks_uri,
                ] {
                    if url.origin().ascii_serialization() != channel.origin
                        || !url.username().is_empty()
                        || url.password().is_some()
                        || url.fragment().is_some()
                    {
                        return Err(failure(self.stage(), ProviderReason::EgressDenied));
                    }
                }
                Ok(Some(metadata.jwks_uri))
            }
            Self::Keys { .. } => {
                let keys: Jwks = decode(bytes, self.stage())?;
                if keys.keys.len() > channel.policy.max_jwks_keys {
                    return Err(invalid(self.stage()));
                }
                Ok(None)
            }
        }
    }
}
fn invalid(stage: ProviderStage) -> FederationError {
    failure(stage, ProviderReason::InvalidResponse)
}
fn decode<T: DeserializeOwned>(bytes: &[u8], stage: ProviderStage) -> Result<T, FederationError> {
    serde_json::from_slice(bytes).map_err(|_| invalid(stage))
}
type Flight = BoxFuture<'static, Result<Arc<Representation>, FederationError>>;

#[derive(Default)]
struct State {
    cached: Option<Cached>,
    flight: Option<WeakShared<Flight>>,
    next_unknown: Option<Instant>,
}
struct Cached {
    value: Arc<Representation>,
    until: Instant,
    lifetime: Duration,
}
pub(super) struct Representation {
    bytes: Box<[u8]>,
    etag: Option<HeaderValue>,
    modified: Option<HeaderValue>,
    keys: Option<(Url, Arc<Document>)>,
    _lease: ByteLease,
}
impl Representation {
    pub fn metadata(&self) -> Result<Metadata, FederationError> {
        decode(&self.bytes, ProviderStage::Discovery)
    }
    pub fn jwks(&self) -> Result<Jwks, FederationError> {
        decode(&self.bytes, ProviderStage::Jwks)
    }
    pub fn keys(&self) -> Result<(&Url, &Arc<Document>), FederationError> {
        self.keys
            .as_ref()
            .map(|(url, doc)| (url, doc))
            .ok_or_else(|| invalid(ProviderStage::Discovery))
    }
}
#[derive(Default)]
pub(super) struct Document {
    state: Mutex<State>,
    retired: AtomicBool,
}
impl Document {
    fn check(&self) -> Result<(), FederationError> {
        if self.retired.load(Ordering::Acquire) {
            Err(FederationError::StaleConfiguration)
        } else {
            Ok(())
        }
    }
    // A weak handle lets callers drive a single public GET without spawning a detached task.
    // Each waiter has its own timeout; when the last one leaves, HTTP I/O and its permit drop.
    pub async fn read(
        self: &Arc<Self>,
        resources: &Arc<Resources>,
        t: &Transport,
        kind: Kind,
        unknown_in: Option<&Arc<Representation>>,
    ) -> Result<Arc<Representation>, FederationError> {
        let stage = kind.stage();
        self.check()?;
        t.channel.check()?;
        super::left(t.deadline, stage)?;
        let flight = {
            let mut state = self.state.lock().unwrap();
            let now = Instant::now();
            if let Some(seen) = unknown_in
                && state.cached.is_none()
            {
                return Ok(seen.clone());
            }
            if let Some(hit) = &state.cached
                && hit.until > now
                && (unknown_in.is_none_or(|seen| !Arc::ptr_eq(seen, &hit.value))
                    || state.next_unknown.is_some_and(|d| d > now))
            {
                return Ok(hit.value.clone());
            }
            t.charge(stage)?;
            if let Some(running) = state.flight.as_ref().and_then(WeakShared::upgrade) {
                running
            } else {
                let permit = resources
                    .refreshes
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| failure(stage, ProviderReason::Unavailable))?;
                let owner = self.clone();
                let resources = resources.clone();
                let channel = t.channel.clone();
                state.next_unknown = now.checked_add(resources.policy.refresh_cooldown);
                let work = async move {
                    let _permit = permit;
                    let result = owner.fetch(&resources, &channel, kind).await;
                    owner.state.lock().unwrap().flight = None;
                    result
                }
                .boxed()
                .shared();
                state.flight = work.downgrade();
                work
            }
        };
        let result = tokio::time::timeout_at(t.deadline.instant().into(), flight)
            .await
            .map_err(|_| failure(stage, ProviderReason::Timeout))??;
        self.check()?;
        t.channel.check()?;
        super::left(t.deadline, stage)?;
        Ok(result)
    }

    async fn fetch(
        &self,
        resources: &Resources,
        channel: &Channel,
        kind: Kind,
    ) -> Result<Arc<Representation>, FederationError> {
        let stage = kind.stage();
        let mut previous = self
            .state
            .lock()
            .unwrap()
            .cached
            .as_ref()
            .map(|c| (c.value.clone(), c.lifetime));
        let mut request = http::Request::get(kind.url()).header(header::ACCEPT, "application/json");
        if let Some((old, _)) = &previous {
            if let Some(tag) = &old.etag {
                request = request.header(header::IF_NONE_MATCH, tag);
            } else if let Some(date) = &old.modified {
                request = request.header(header::IF_MODIFIED_SINCE, date);
            }
        }
        self.check()?;
        let cutoff = Instant::now()
            .checked_add(channel.policy.request_timeout)
            .ok_or(FederationError::Configuration)?;
        let response = channel
            .call(
                stage,
                rss_request_context::Deadline::at(cutoff),
                request.body(Vec::new()).map_err(|_| invalid(stage))?,
            )
            .await?;
        self.check()?;
        channel.check()?;
        let (parts, bytes) = response.into_parts();
        let cap = match &kind {
            Kind::Discovery { .. } => resources.policy.discovery_ttl,
            Kind::Keys { .. } => resources.policy.jwks_ttl,
        };
        let mut upper = cap;
        let value = if parts.status == http::StatusCode::NOT_MODIFIED {
            let (old, prior_lifetime) = previous.as_ref().ok_or_else(|| invalid(stage))?;
            if old.etag.is_none() && old.modified.is_none()
                || parts
                    .headers
                    .get(header::ETAG)
                    .is_some_and(|v| Some(v) != old.etag.as_ref())
            {
                return Err(invalid(stage));
            }
            if !parts.headers.contains_key(header::CACHE_CONTROL) {
                upper = *prior_lifetime;
            }
            old.clone()
        } else {
            if parts.status != http::StatusCode::OK || !valid_media(&parts.headers, stage) {
                return Err(invalid(stage));
            }
            let keys_uri = kind.validate(&bytes, channel)?;
            let etag = parts.headers.get(header::ETAG).cloned();
            let modified = parts.headers.get(header::LAST_MODIFIED).cloned();
            let keys = keys_uri.map(|uri| {
                let doc = previous
                    .as_ref()
                    .and_then(|(r, _)| r.keys.as_ref())
                    .filter(|(old, _)| old == &uri)
                    .map(|(_, d)| d.clone())
                    .unwrap_or_default();
                (uri, doc)
            });
            // Account exact stored bytes. Parsed DTOs live only in their caller.
            let overhead = etag.as_ref().map_or(0, |v| v.as_bytes().len())
                + modified.as_ref().map_or(0, |v| v.as_bytes().len())
                + keys.as_ref().map_or(0, |(u, _)| u.as_str().len());
            // Discard an expired representation before charging its replacement. Live callers
            // retain their own leases; a refresh cannot double-count an otherwise idle entry.
            let mut state = self.state.lock().unwrap();
            if state
                .cached
                .as_ref()
                .is_some_and(|old| old.until <= Instant::now())
                && let Some(old) = state.cached.take()
            {
                retire_changed_keys(&old.value, keys.as_ref());
            }
            drop(state);
            drop(previous.take());
            let lease = resources.reserve(
                bytes
                    .len()
                    .checked_add(overhead)
                    .ok_or(FederationError::Unavailable)?,
            )?;
            Arc::new(Representation {
                bytes: bytes.into_boxed_slice(),
                etag,
                modified,
                keys,
                _lease: lease,
            })
        };
        let (store, lifetime) = freshness(&parts.headers, upper);
        let age = parts.headers.get(header::AGE).map_or(0, |v| {
            v.to_str()
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(u64::MAX)
        });
        let mut state = self.state.lock().unwrap();
        self.check()?;
        channel.check()?;
        if let Some(old) = &state.cached {
            retire_changed_keys(&old.value, value.keys.as_ref());
        }
        state.cached = if store {
            Some(Cached {
                value: value.clone(),
                lifetime,
                until: Instant::now()
                    .checked_add(lifetime.saturating_sub(Duration::from_secs(age)))
                    .ok_or(FederationError::Configuration)?,
            })
        } else {
            None
        };
        Ok(value)
    }
}
fn retire_changed_keys(old: &Representation, next: Option<&(Url, Arc<Document>)>) {
    if let Some((_, old_keys)) = &old.keys
        && next.is_none_or(|(_, new_keys)| !Arc::ptr_eq(old_keys, new_keys))
    {
        old_keys.retired.store(true, Ordering::Release);
    }
}
fn valid_media(headers: &HeaderMap, stage: ProviderStage) -> bool {
    headers.get(header::CONTENT_TYPE).is_none_or(|value| {
        value.to_str().is_ok_and(|s| {
            let media = s.split(';').next().unwrap_or("").trim();
            media.eq_ignore_ascii_case("application/json")
                || stage == ProviderStage::Jwks
                    && media.eq_ignore_ascii_case("application/jwk-set+json")
        })
    })
}
fn freshness(headers: &HeaderMap, mut cap: Duration) -> (bool, Duration) {
    for value in headers.get_all(header::CACHE_CONTROL) {
        let Ok(s) = value.to_str() else {
            return (false, Duration::ZERO);
        };
        for part in s.split(',').map(str::trim) {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            if name.eq_ignore_ascii_case("no-store") {
                return (false, Duration::ZERO);
            }
            if name.eq_ignore_ascii_case("no-cache") {
                cap = Duration::ZERO;
            }
            if name.eq_ignore_ascii_case("max-age") {
                cap = cap.min(Duration::from_secs(
                    value.trim_matches('"').parse().unwrap_or(0),
                ));
            }
        }
    }
    (true, cap)
}
