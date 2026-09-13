//! Fixed native CLI redirect and PKCE binding. ref: RFC 8252 section 7.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CliBindingError;
impl std::fmt::Display for CliBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid CLI login binding")
    }
}
impl std::error::Error for CliBindingError {}
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "Input")]
pub struct CliLoginBinding {
    redirect_uri: String,
    code_challenge: String,
    state: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    redirect_uri: String,
    code_challenge: String,
    state: String,
}
impl TryFrom<Input> for CliLoginBinding {
    type Error = CliBindingError;
    fn try_from(v: Input) -> Result<Self, Self::Error> {
        Self::new(v.redirect_uri, v.code_challenge, v.state)
    }
}
impl CliLoginBinding {
    pub fn new(
        redirect_uri: String,
        code_challenge: String,
        state: String,
    ) -> Result<Self, CliBindingError> {
        let u = url::Url::parse(&redirect_uri).map_err(|_| CliBindingError)?;
        if u.scheme() != "http"
            || !matches!(u.host(),Some(url::Host::Ipv4(ip)) if ip==std::net::Ipv4Addr::LOCALHOST)
            || u.port().is_none_or(|p| p == 0)
            || u.path() != "/callback"
            || u.query().is_some()
            || u.fragment().is_some()
            || !u.username().is_empty()
            || u.password().is_some()
            || u.as_str() != redirect_uri
        {
            return Err(CliBindingError);
        }
        for v in [&code_challenge, &state] {
            let raw = URL_SAFE_NO_PAD.decode(v).map_err(|_| CliBindingError)?;
            if raw.len() != 32 || URL_SAFE_NO_PAD.encode(raw) != *v {
                return Err(CliBindingError);
            }
        }
        Ok(Self {
            redirect_uri,
            code_challenge,
            state,
        })
    }
    pub fn challenge_for(verifier: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    }
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
    pub fn challenge(&self) -> &str {
        &self.code_challenge
    }
    pub fn state(&self) -> &str {
        &self.state
    }
    pub fn verifies(&self, verifier: &str, redirect: &str) -> bool {
        (43..=128).contains(&verifier.len())
            && verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
            && redirect == self.redirect_uri
            && URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == self.code_challenge
    }
    pub fn result_url(&self, name: &str, value: &str) -> Result<String, CliBindingError> {
        if !matches!(name, "code" | "error") {
            return Err(CliBindingError);
        }
        let mut u = url::Url::parse(&self.redirect_uri).map_err(|_| CliBindingError)?;
        u.query_pairs_mut()
            .append_pair(name, value)
            .append_pair("state", &self.state);
        Ok(u.to_string())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loopback_and_pkce_are_exact() {
        let verifier = "A".repeat(43);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let state = URL_SAFE_NO_PAD.encode([2; 32]);
        let b = CliLoginBinding::new(
            "http://127.0.0.1:49152/callback".into(),
            challenge.clone(),
            state.clone(),
        )
        .unwrap();
        assert!(b.verifies(&verifier, b.redirect_uri()));
        assert!(!b.verifies(&"B".repeat(43), b.redirect_uri()));
        for uri in [
            "http://localhost:49152/callback",
            "http://127.0.0.2:49152/callback",
            "https://example.test/callback",
            "http://127.0.0.1/callback",
            "http://127.0.0.1:49152/other",
            "http://127.0.0.1:49152/callback?x=1",
        ] {
            assert!(CliLoginBinding::new(uri.into(), challenge.clone(), state.clone()).is_err());
        }
    }
}
