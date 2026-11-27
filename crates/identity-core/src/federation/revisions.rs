//! Configuration snapshots are registered while their authority still owns the read.
//! A delayed caller pins the version fence independently of the HTTP cache.
use super::{FederationError, ProviderId, ProviderReason, ProviderRevision, ProviderStage};
use rss_request_context::TenantId;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicI64, Ordering},
    },
};
type Key = (uuid::Uuid, TenantId, ProviderId);
fn key(r: ProviderRevision) -> Key {
    (r.instance.as_uuid(), r.tenant, r.provider)
}

/// Local registry for authoritative configuration reads and committed change notifications.
pub struct ProviderRevisions {
    entries: Arc<Mutex<HashMap<Key, Weak<AtomicI64>>>>,
    limit: usize,
}
impl ProviderRevisions {
    pub fn new(max_live: usize) -> Self {
        Self {
            entries: Arc::default(),
            limit: max_live,
        }
    }

    /// Call under the authoritative read lock or serialized host configuration installation.
    /// Keep the returned snapshot with the settings until all their operations have finished.
    pub fn install(
        &self,
        revision: ProviderRevision,
    ) -> Result<InstalledRevision, FederationError> {
        if revision.version <= 0 {
            return Err(FederationError::Configuration);
        }
        let mut entries = self.entries.lock().unwrap();
        let id = key(revision);
        let current = if let Some(active) = entries.get(&id).and_then(Weak::upgrade) {
            if active.fetch_max(revision.version, Ordering::AcqRel) > revision.version {
                return Err(FederationError::StaleConfiguration);
            }
            active
        } else {
            if entries.len() >= self.limit {
                entries.retain(|_, v| v.strong_count() > 0);
            }
            if entries.len() >= self.limit {
                return Err(FederationError::provider(
                    ProviderStage::Binding,
                    ProviderReason::Unavailable,
                ));
            }
            let active = Arc::new(AtomicI64::new(revision.version));
            entries.insert(id, Arc::downgrade(&active));
            active
        };
        Ok(InstalledRevision {
            revision,
            current,
            owner: Arc::downgrade(&self.entries),
        })
    }

    /// Notify after the authoritative commit. A still-usable older snapshot pins its entry.
    pub fn observe(&self, revision: ProviderRevision) {
        if let Some(active) = self
            .entries
            .lock()
            .unwrap()
            .get(&key(revision))
            .and_then(Weak::upgrade)
        {
            active.fetch_max(revision.version, Ordering::AcqRel);
        }
    }
    pub fn check(&self, installed: &InstalledRevision) -> Result<(), FederationError> {
        if !installed.owner.ptr_eq(&Arc::downgrade(&self.entries)) {
            return Err(FederationError::Configuration);
        }
        installed.check()
    }
}

#[derive(Clone)]
pub struct InstalledRevision {
    revision: ProviderRevision,
    current: Arc<AtomicI64>,
    owner: Weak<Mutex<HashMap<Key, Weak<AtomicI64>>>>,
}
impl InstalledRevision {
    pub fn revision(&self) -> ProviderRevision {
        self.revision
    }
    pub fn check(&self) -> Result<(), FederationError> {
        if self.current.load(Ordering::Acquire) == self.revision.version {
            Ok(())
        } else {
            Err(FederationError::StaleConfiguration)
        }
    }
    pub fn bind<'a>(
        &self,
        settings: &'a super::ProviderSettings,
        credentials: &'a super::ProviderCredentials,
    ) -> super::BoundProvider<'a> {
        super::BoundProvider {
            installed: self.clone(),
            settings,
            credentials,
        }
    }
}
