identity_personnel AS NOT MATERIALIZED (
 SELECT a.tenant_id,a.principal_id,a.enabled AND m.active AS active,
 CASE WHEN {logins} AND a.enabled AND m.active THEN l.login_key END AS login,
 o.source,
 CASE WHEN NOT (a.enabled AND m.active) OR NOT ({profiles}) OR
   (o.source <> 'local' AND NOT (p.enabled AND p.config_version=o.config_version AND p.revocation_epoch=o.source_epoch
     AND EXISTS(SELECT FROM identity_authority.external_identities e WHERE e.tenant_id=o.tenant_id AND e.principal_id=o.principal_id AND e.provider_id=o.provider_id))) THEN 'unavailable'
   WHEN o.snapshot_id IS NULL THEN 'missing'
   WHEN LEAST(o.expires_at,o.observed_at+{max_age}) <= {now} THEN 'expired'
   ELSE 'available' END AS status,
 CASE WHEN a.enabled AND m.active AND ({profiles}) AND LEAST(o.expires_at,o.observed_at+{max_age}) > {now}
   AND (o.source='local' OR (p.enabled AND p.config_version=o.config_version AND p.revocation_epoch=o.source_epoch
     AND EXISTS(SELECT FROM identity_authority.external_identities e WHERE e.tenant_id=o.tenant_id AND e.principal_id=o.principal_id AND e.provider_id=o.provider_id)))
   AND o.value->'displayName'->>'status'='available' THEN o.value->'displayName'->>'value' END AS display_name,
 CASE WHEN a.enabled AND m.active AND ({profiles}) AND LEAST(o.expires_at,o.observed_at+{max_age}) > {now}
   AND (o.source='local' OR (p.enabled AND p.config_version=o.config_version AND p.revocation_epoch=o.source_epoch
     AND EXISTS(SELECT FROM identity_authority.external_identities e WHERE e.tenant_id=o.tenant_id AND e.principal_id=o.principal_id AND e.provider_id=o.provider_id)))
   AND o.value->'username'->>'status'='available' THEN o.value->'username'->>'value' END AS username,
 CASE WHEN ({profiles}) THEN LEAST(o.expires_at,o.observed_at+{max_age}) END AS expires_at
 FROM identity_authority.accounts a
 JOIN identity_authority.memberships m USING(tenant_id,principal_id)
 LEFT JOIN identity_authority.local_credentials l USING(tenant_id,principal_id)
 LEFT JOIN identity_authority.profile_observations o ON o.tenant_id=a.tenant_id AND o.principal_id=a.principal_id AND ({profiles})
 LEFT JOIN identity_authority.providers p ON p.tenant_id=o.tenant_id AND p.provider_id=o.provider_id
 WHERE a.tenant_id='{tenant}'::uuid
)
