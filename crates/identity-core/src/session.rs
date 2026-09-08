//! Central session policy; one current credential, no refresh-token history.
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid or expired session")]
pub struct SessionError;

/// Owned bearer secret. Never serialize, clone or log it; expose only at the HTTP boundary.
/// ```compile_fail
/// fn copy(s: rss_identity_core::session::SessionSecret) { let _ = s.clone(); }
/// ```
pub struct SessionSecret(Zeroizing<String>);
impl std::fmt::Debug for SessionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionSecret(<redacted>)")
    }
}
impl SessionSecret {
    pub fn generate() -> Result<Self, SessionError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        OsRng
            .try_fill_bytes(bytes.as_mut())
            .map_err(|_| SessionError)?;
        Ok(Self(Zeroizing::new(hex(bytes.as_ref()))))
    }
    pub fn parse(value: String) -> Result<Self, SessionError> {
        let value = Zeroizing::new(value);
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SessionError);
        }
        Ok(Self(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    /// Persistence-only authentication digest; not a bearer credential.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }
    pub fn csrf(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"rss-identity.session.csrf.v1\0");
        hash.update(self.0.as_bytes());
        hex(&hash.finalize())
    }
    pub fn check_csrf(&self, presented: &str) -> bool {
        bool::from(self.csrf().as_bytes().ct_eq(presented.as_bytes()))
    }
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        value.push(DIGITS[(b >> 4) as usize] as char);
        value.push(DIGITS[(b & 15) as usize] as char);
    }
    value
}

/// Policy identity is fixed when the lifetime is created or restored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionClass {
    Ordinary,
    Administrator,
}
impl SessionClass {
    fn for_administrator(administrator: bool) -> Self {
        if administrator {
            Self::Administrator
        } else {
            Self::Ordinary
        }
    }
    fn limits(self) -> (i64, i64) {
        match self {
            Self::Administrator => (900, 14_400),
            Self::Ordinary => (1_800, 28_800),
        }
    }
}

/// Validated times from the authoritative clock. Not an authentication proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLifetime {
    class: SessionClass,
    auth_time: i64,
    idle_expires_at: i64,
    absolute_expires_at: i64,
}
impl SessionLifetime {
    pub fn new(now: i64, administrator: bool) -> Result<Self, SessionError> {
        let (idle, absolute) = SessionClass::for_administrator(administrator).limits();
        Self::restore(
            now,
            now.checked_add(idle).ok_or(SessionError)?,
            now.checked_add(absolute).ok_or(SessionError)?,
            administrator,
        )
    }
    pub fn restore(
        auth_time: i64,
        idle_expires_at: i64,
        absolute_expires_at: i64,
        administrator: bool,
    ) -> Result<Self, SessionError> {
        let class = SessionClass::for_administrator(administrator);
        if auth_time <= 0
            || idle_expires_at <= auth_time
            || idle_expires_at > absolute_expires_at
            || auth_time.checked_add(class.limits().1) != Some(absolute_expires_at)
        {
            return Err(SessionError);
        }
        Ok(Self {
            class,
            auth_time,
            idle_expires_at,
            absolute_expires_at,
        })
    }
    pub fn valid_at(self, now: i64) -> bool {
        now >= self.auth_time && now < self.idle_expires_at && now < self.absolute_expires_at
    }
    /// Renew within the policy bound at creation; callers cannot switch session class.
    /// ```compile_fail
    /// let mut admin = rss_identity_core::session::SessionLifetime::new(1000, true).unwrap();
    /// admin.renew(1800, false);
    /// ```
    pub fn renew(&mut self, now: i64) -> Result<(), SessionError> {
        if !self.valid_at(now) {
            return Err(SessionError);
        }
        self.idle_expires_at = self.idle_expires_at.max(
            now.checked_add(self.class.limits().0)
                .ok_or(SessionError)?
                .min(self.absolute_expires_at),
        );
        Ok(())
    }
    pub fn auth_time(self) -> i64 {
        self.auth_time
    }
    pub fn idle_expires_at(self) -> i64 {
        self.idle_expires_at
    }
    pub fn absolute_expires_at(self) -> i64 {
        self.absolute_expires_at
    }
}
