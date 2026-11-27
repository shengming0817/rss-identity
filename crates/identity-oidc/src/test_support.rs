use rss_identity_core::{InstanceId, federation::*};
use rss_request_context::TenantId;

/// Bind a fixture configuration to a stable instance and provider for repeated operations.
pub fn fixture_provider<'a>(
    adapter: &crate::HttpOidc,
    tenant: TenantId,
    settings: &'a ProviderSettings,
    credentials: &'a ProviderCredentials,
) -> BoundProvider<'a> {
    adapter
        .revisions()
        .install(ProviderRevision {
            tenant,
            instance: InstanceId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            provider: ProviderId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            version: 1,
        })
        .unwrap()
        .bind(settings, credentials)
}

use crate::ReusePolicy;
#[path = "../tests/support/policy.rs"]
mod policy;
pub use policy::reuse_policy;
