//! Tenant-local account values and bounded password computation.
//! ref: RustCrypto/password-hashes argon2/src/{lib,params}.rs @ argon2-v0.5.3.
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand_core::OsRng;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq)]
pub struct LoginKey(String);
impl LoginKey {
    pub fn parse(value: &str) -> Result<Self, PasswordError> {
        if value.is_empty()
            || value.len() > 128
            || !value.is_ascii()
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(PasswordError::Invalid);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for LoginKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LoginKey(<redacted>)")
    }
}

/// No Clone or serialization: callers must deliberately supply each secret.
pub struct Password(Zeroizing<String>);
impl Password {
    pub fn new(value: String) -> Result<Self, PasswordError> {
        let value = Zeroizing::new(value);
        if value.len() > 1024 || value.chars().count() < 15 {
            return Err(PasswordError::Invalid);
        }
        Ok(Self(value))
    }
}
impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

/// Bounded, redacted PHC storage representation; not an authentication proof.
#[derive(Clone)]
pub struct PasswordEncoding(Zeroizing<String>);
impl PasswordEncoding {
    pub fn from_storage(value: String) -> Result<Self, PasswordError> {
        let value = Zeroizing::new(value);
        if value.len() > 256 {
            return Err(PasswordError::Unavailable);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for PasswordEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordEncoding(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PasswordError {
    #[error("invalid account input")]
    Invalid,
    #[error("password computation capacity exhausted")]
    Busy,
    #[error("password computation unavailable")]
    Unavailable,
}

const DUMMY: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[derive(Clone)]
pub struct PasswordKdf {
    gate: Arc<Semaphore>,
    admission: Arc<Mutex<bool>>,
    tasks: tokio_util::task::TaskTracker,
}
impl Default for PasswordKdf {
    fn default() -> Self {
        Self::new()
    }
}
impl PasswordKdf {
    pub fn new() -> Self {
        Self {
            gate: Arc::new(Semaphore::new(4)),
            admission: Arc::new(Mutex::new(true)),
            tasks: tokio_util::task::TaskTracker::new(),
        }
    }
    /// Permanently close work admission. Existing blocking closures retain their tokens.
    pub fn close(&self) {
        let mut open = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        *open = false;
        self.tasks.close();
    }
    /// Wait for real closure completion after close; the application supplies the drain budget.
    pub async fn wait_closed(&self) {
        self.tasks.wait().await;
    }
    async fn compute<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T, PasswordError> + Send + 'static,
    ) -> Result<T, PasswordError> {
        let (permit, tracked) = {
            let open = self
                .admission
                .lock()
                .map_err(|_| PasswordError::Unavailable)?;
            if !*open {
                return Err(PasswordError::Unavailable);
            }
            let permit = self
                .gate
                .clone()
                .try_acquire_owned()
                .map_err(|_| PasswordError::Busy)?;
            (permit, self.tasks.token())
        };
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _tracked = tracked;
            work()
        })
        .await
        .map_err(|_| PasswordError::Unavailable)?
    }
    pub async fn hash(&self, secret: Password) -> Result<PasswordEncoding, PasswordError> {
        self.compute(move || {
            let salt = SaltString::generate(&mut OsRng);
            Argon2::default()
                .hash_password(secret.0.as_bytes(), &salt)
                .map(|h| PasswordEncoding(Zeroizing::new(h.to_string())))
                .map_err(|_| PasswordError::Unavailable)
        })
        .await
    }
    pub async fn verify(
        &self,
        secret: Password,
        encoded: PasswordEncoding,
    ) -> Result<bool, PasswordError> {
        self.compute(move || {
            let hash =
                PasswordHash::new(encoded.as_str()).map_err(|_| PasswordError::Unavailable)?;
            if encoded.as_str().len() > 256
                || hash.algorithm.as_str() != "argon2id"
                || hash.version != Some(19)
                || hash.params.to_string() != "m=19456,t=2,p=1"
                || hash.hash.as_ref().map(|h| h.len()) != Some(32)
                || hash.salt.as_ref().map(|s| s.as_str().len()) != Some(22)
            {
                return Err(PasswordError::Unavailable);
            }
            Ok(Argon2::default()
                .verify_password(secret.0.as_bytes(), &hash)
                .is_ok())
        })
        .await
    }
    pub async fn dummy(&self, secret: Password) -> Result<(), PasswordError> {
        self.verify(secret, PasswordEncoding::from_storage(DUMMY.into())?)
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn closing_kdf_waits_for_actual_work_and_rejects_new_work() {
        let kdf = Arc::new(PasswordKdf::new());
        let (started, seen) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let worker = kdf.clone();
        let caller = tokio::spawn(async move {
            worker
                .compute(move || {
                    started.send(()).unwrap();
                    wait.recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                    Ok(())
                })
                .await
        });
        seen.await.unwrap();
        caller.abort();
        kdf.close();
        assert!(matches!(
            kdf.compute(|| Ok(())).await,
            Err(PasswordError::Unavailable)
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), kdf.wait_closed())
                .await
                .is_err()
        );
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), kdf.wait_closed())
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn cancelled_waiter_does_not_release_running_work() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (end_tx, end_rx) = std::sync::mpsc::channel();
        let kdf = Arc::new(PasswordKdf::new());
        let worker = kdf.clone();
        let task = tokio::spawn(async move {
            worker
                .compute(move || {
                    started_tx.send(()).unwrap();
                    end_rx
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        task.abort();
        let remaining = kdf.gate.clone().try_acquire_many_owned(3).unwrap();
        assert!(matches!(
            kdf.compute(|| Ok(())).await,
            Err(PasswordError::Busy)
        ));
        end_tx.send(()).unwrap();
        drop(remaining);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while kdf.gate.available_permits() != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            kdf.compute::<()>(|| panic!("test worker failure")).await,
            Err(PasswordError::Unavailable)
        ));
        assert_eq!(kdf.gate.available_permits(), 4);
    }
}

mod policy;
pub use policy::{
    AccountChange, AccountKey, AccountRuleError, AccountState, LocalChange, SecurityAction,
};
