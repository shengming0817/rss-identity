//! Fixed-endpoint Hydra adapter. ref: ory/hydra oauth2/handler.go and flow/consent_types.go @ 0b84568fffccf151dc5e6c7955fdfb738555bf4b.
pub use ipnet::IpNet;
use reqwest::{Client, Method, Url};
use rss_identity_core::downstream::*;
use serde_json::{Value, json};
use std::{net::IpAddr, sync::Arc, time::Duration};

/// Admin transport is private and authenticated by the deployment's service gateway.
pub struct Hydra {
    client: Client,
    admin: Url,
    issuer: Url,
    issuer_identity: String,
    service: Secret,
}
#[derive(Debug, thiserror::Error)]
#[error("unapproved Hydra destination")]
struct Egress;
struct Resolver {
    host: String,
    addresses: Vec<IpNet>,
}
impl reqwest::dns::Resolve for Resolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = self.host.clone();
        let allowed = self.addresses.clone();
        Box::pin(async move {
            if name.as_str() != host {
                return Err(Egress.into());
            }
            let addresses: Vec<_> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            resolved_addresses(name.as_str(), &host, &allowed, addresses)
        })
    }
}
fn resolved_addresses(
    name: &str,
    host: &str,
    allowed: &[IpNet],
    addresses: Vec<std::net::SocketAddr>,
) -> Result<reqwest::dns::Addrs, Box<dyn std::error::Error + Send + Sync>> {
    if name != host
        || addresses.is_empty()
        || addresses
            .iter()
            .any(|a| !allowed.iter().any(|n| n.contains(&a.ip())))
    {
        return Err(Egress.into());
    }
    Ok(Box::new(addresses.into_iter()))
}
fn secure_url(s: &str) -> Result<Url, DownstreamError> {
    let u = Url::parse(s).map_err(|_| DownstreamError::Invalid)?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(DownstreamError::Invalid);
    }
    Ok(u)
}
impl Hydra {
    pub fn new(
        admin: &str,
        issuer: &str,
        addresses: Vec<IpNet>,
        service: Secret,
        ca: Option<&[u8]>,
    ) -> Result<Self, DownstreamError> {
        let issuer_identity = issuer.to_owned();
        let admin = secure_url(admin)?;
        let issuer = secure_url(issuer)?;
        if admin.path() != "/" || addresses.is_empty() || addresses.len() > 32 {
            return Err(DownstreamError::Invalid);
        }
        let host = admin.host_str().ok_or(DownstreamError::Invalid)?;
        if let Ok(ip) = host.parse::<IpAddr>()
            && !addresses.iter().any(|n| n.contains(&ip))
        {
            return Err(DownstreamError::Invalid);
        }
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .dns_resolver(Arc::new(Resolver {
                host: host.into(),
                addresses,
            }));
        if let Some(ca) = ca {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(ca).map_err(|_| DownstreamError::Invalid)?,
            );
        }
        Ok(Self {
            client: builder.build().map_err(|_| DownstreamError::Unavailable)?,
            admin,
            issuer,
            issuer_identity,
            service,
        })
    }
    /// Bounded private provider readiness probe through the existing authenticated transport.
    pub async fn ready(&self) -> Result<(), DownstreamError> {
        self.request(Method::GET, "health/ready", &[], None, None)
            .await
            .map(|_| ())
    }
    async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<Value>,
        token: Option<&str>,
    ) -> Result<Value, DownstreamError> {
        let mut req = self
            .client
            .request(
                method,
                self.admin
                    .join(path)
                    .map_err(|_| DownstreamError::Invalid)?,
            )
            .bearer_auth(self.service.expose())
            .query(query);
        if let Some(body) = body {
            req = req.json(&body);
        }
        if let Some(token) = token {
            req = req.form(&[("token", token)]);
        }
        let mut response = req.send().await.map_err(|_| DownstreamError::Unavailable)?;
        let status = response.status();
        if !status.is_success() {
            return Err(if status.is_server_error() || status.as_u16() == 429 {
                DownstreamError::Unavailable
            } else {
                DownstreamError::Rejected
            });
        }
        if status.as_u16() == 204 {
            return Ok(Value::Null);
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| DownstreamError::Unavailable)?
        {
            if bytes.len() + chunk.len() > 1024 * 1024 {
                return Err(DownstreamError::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| DownstreamError::Unavailable)
    }
    fn redirect(&self, v: Value) -> Result<Secret, DownstreamError> {
        let target = string(&v, "redirect_to")?;
        let u = Url::parse(&target).map_err(|_| DownstreamError::Rejected)?;
        let prefix = self.issuer.path().trim_end_matches('/');
        if u.origin() != self.issuer.origin()
            || u.path() != format!("{prefix}/oauth2/auth")
            || !u.username().is_empty()
            || u.password().is_some()
            || u.fragment().is_some()
        {
            return Err(DownstreamError::Rejected);
        }
        Secret::new(target)
    }
    fn challenge(&self, v: Value, consent: bool) -> Result<Challenge, DownstreamError> {
        let c = &v["client"];
        if strings(c, "grant_types")? != ["authorization_code"]
            || strings(c, "response_types")? != ["code"]
            || string(c, "token_endpoint_auth_method")? != "client_secret_basic"
        {
            return Err(DownstreamError::Rejected);
        }
        let request =
            Url::parse(&string(&v, "request_url")?).map_err(|_| DownstreamError::Rejected)?;
        if request.origin() != self.issuer.origin()
            || request.path() != format!("{}/oauth2/auth", self.issuer.path().trim_end_matches('/'))
        {
            return Err(DownstreamError::Rejected);
        }
        let values = |key: &str| {
            request
                .query_pairs()
                .filter(|(k, _)| k == key)
                .map(|(_, v)| v.into_owned())
                .collect::<Vec<_>>()
        };
        let redirects = values("redirect_uri");
        let pkce = values("code_challenge");
        if redirects.len() != 1
            || !strings(c, "redirect_uris")?.contains(&redirects[0])
            || values("response_type") != ["code"]
            || values("scope") != ["openid"]
            || values("state").len() != 1
            || values("nonce").len() != 1
            || values("state")[0].is_empty()
            || values("nonce")[0].is_empty()
        {
            return Err(DownstreamError::Rejected);
        }
        let pkce_s256 = values("code_challenge_method") == ["S256"]
            && pkce.len() == 1
            && pkce[0].len() == 43
            && pkce[0]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        Ok(Challenge {
            client: string(c, "client_id")?,
            redirect: redirects[0].clone(),
            audiences: strings(&v, "requested_access_token_audience")?,
            scopes: strings(&v, "requested_scope")?,
            pkce_s256,
            login_session_id: string(
                &v,
                if consent {
                    "login_session_id"
                } else {
                    "session_id"
                },
            )?,
            subject: v["subject"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(Into::into),
            consent_request_id: if consent {
                Some(string(&v, "consent_request_id")?)
            } else {
                None
            },
            login_binding: if consent {
                Some(string(&v["context"], "identity_grant_id")?)
            } else {
                None
            },
        })
    }
}
fn string(v: &Value, k: &str) -> Result<String, DownstreamError> {
    v[k].as_str()
        .map(Into::into)
        .ok_or(DownstreamError::Rejected)
}
fn strings(v: &Value, k: &str) -> Result<Vec<String>, DownstreamError> {
    v[k].as_array()
        .ok_or(DownstreamError::Rejected)?
        .iter()
        .map(|v| v.as_str().map(Into::into).ok_or(DownstreamError::Rejected))
        .collect()
}
impl DownstreamProtocol for Hydra {
    fn issuer(&self) -> &str {
        &self.issuer_identity
    }
    fn login<'a>(&'a self, c: &'a Secret) -> ProtocolFuture<'a, Challenge> {
        Box::pin(async move {
            let v = self
                .request(
                    Method::GET,
                    "admin/oauth2/auth/requests/login",
                    &[("login_challenge", c.expose())],
                    None,
                    None,
                )
                .await?;
            self.challenge(v, false)
        })
    }
    fn consent<'a>(&'a self, c: &'a Secret) -> ProtocolFuture<'a, Challenge> {
        Box::pin(async move {
            let v = self
                .request(
                    Method::GET,
                    "admin/oauth2/auth/requests/consent",
                    &[("consent_challenge", c.expose())],
                    None,
                    None,
                )
                .await?;
            self.challenge(v, true)
        })
    }
    fn accept_login<'a>(&'a self, c: &'a Secret, d: LoginDecision) -> ProtocolFuture<'a, Secret> {
        Box::pin(async move {
            self.redirect(self.request(Method::PUT,"admin/oauth2/auth/requests/login/accept",&[("login_challenge",c.expose())],Some(json!({"context":{"identity_grant_id":d.grant_id},"subject":d.subject,"acr":"unspecified","remember":false})),None).await?)
        })
    }
    fn accept_consent<'a>(
        &'a self,
        c: &'a Secret,
        d: ConsentDecision,
    ) -> ProtocolFuture<'a, Secret> {
        Box::pin(async move {
            self.redirect(self.request(Method::PUT,"admin/oauth2/auth/requests/consent/accept",&[("consent_challenge",c.expose())],Some(json!({"grant_scope":["openid"],"grant_access_token_audience":[d.audience],"remember":false,"session":{"access_token":{"identity_grant_id":d.grant_id,"identity_version":1}}})),None).await?)
        })
    }
    fn introspect<'a>(&'a self, c: &'a Secret) -> ProtocolFuture<'a, TokenObservation> {
        Box::pin(async move {
            let v = self
                .request(
                    Method::POST,
                    "admin/oauth2/introspect",
                    &[],
                    None,
                    Some(c.expose()),
                )
                .await?;
            let active = v["active"].as_bool().ok_or(DownstreamError::Rejected)?;
            if !active {
                return Err(DownstreamError::Rejected);
            }
            Ok(TokenObservation {
                active,
                issuer: string(&v, "iss")?,
                client: string(&v, "client_id")?,
                audiences: strings(&v, "aud")?,
                subject: string(&v, "sub")?,
                expires_at: v["exp"].as_i64().ok_or(DownstreamError::Rejected)?,
                issued_at: v["iat"].as_i64().ok_or(DownstreamError::Rejected)?,
                not_before: v["nbf"].as_i64().unwrap_or(0),
                grant_id: string(&v["ext"], "identity_grant_id")?,
                version: v["ext"]["identity_version"]
                    .as_u64()
                    .ok_or(DownstreamError::Rejected)?,
                token_use: string(&v, "token_use")?,
                token_type: string(&v, "token_type")?,
                scope: string(&v, "scope")?,
            })
        })
    }
    fn revoke<'a>(&'a self, consent: Option<&'a str>, sid: &'a str) -> ProtocolFuture<'a, ()> {
        Box::pin(async move {
            if let Some(id) = consent {
                self.request(
                    Method::DELETE,
                    "admin/oauth2/auth/sessions/consent",
                    &[("consent_request_id", id)],
                    None,
                    None,
                )
                .await?;
            }
            self.request(
                Method::DELETE,
                "admin/oauth2/auth/sessions/login",
                &[("sid", sid)],
                None,
                None,
            )
            .await?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_requires_exact_host_and_every_address_allowed() {
        let allowed = vec!["127.0.0.1/32".parse().unwrap(), "::1/128".parse().unwrap()];
        let addresses = vec!["127.0.0.1:0".parse().unwrap(), "[::1]:0".parse().unwrap()];
        assert!(resolved_addresses("localhost", "localhost", &allowed, addresses.clone()).is_ok());
        assert!(resolved_addresses("other", "localhost", &allowed, addresses).is_err());
        assert!(resolved_addresses("localhost", "localhost", &allowed, vec![]).is_err());
        for values in [
            vec!["192.0.2.1:0"],
            vec!["127.0.0.1:0", "192.0.2.1:0"],
            vec!["[2001:db8::1]:0"],
        ] {
            assert!(
                resolved_addresses(
                    "localhost",
                    "localhost",
                    &allowed,
                    values.iter().map(|s| s.parse().unwrap()).collect()
                )
                .is_err()
            );
        }
    }
}
