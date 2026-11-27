use rss_identity_core::{InstanceId, federation::*};
use rss_request_context::TenantId;

/// Bind a fixture configuration to a stable instance and provider for repeated operations.
pub fn fixture_provider<'a>(tenant: TenantId, settings: &'a ProviderSettings, credentials: &'a ProviderCredentials) -> BoundProvider<'a> {
    BoundProvider { revision: ProviderRevision {
        tenant, instance: InstanceId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        provider: ProviderId::parse("22222222-2222-4222-8222-222222222222").unwrap(), version: 1,
    }, settings, credentials }
}
