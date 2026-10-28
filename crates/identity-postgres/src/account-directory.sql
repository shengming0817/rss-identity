WITH account_rows AS (
 SELECT a.principal_id::text AS "principalId",l.login_key AS login,a.enabled AS enabled,
 m.active AS "memberActive",l.principal_id IS NOT NULL AS "hasLocalPassword",
 CASE WHEN pv.status='available' AND o.value->'displayName'->>'status'='available' THEN o.value->'displayName'->>'value' END AS "displayName",
 CASE WHEN pv.status='available' AND o.value->'email'->>'status'='available' THEN o.value->'email'->>'value' END AS email,
 pv.status AS "profileStatus",dv.status AS "departmentStatus",
 CASE WHEN dv.status='available' THEN ds.auth_facts->'department_snapshot'->'snapshot' END AS "departmentSnapshot"
 FROM identity_authority.accounts a
 JOIN identity_authority.memberships m USING(tenant_id,principal_id)
 LEFT JOIN identity_authority.local_credentials l USING(tenant_id,principal_id)
 LEFT JOIN identity_authority.profile_observations o ON o.tenant_id=a.tenant_id AND o.principal_id=a.principal_id AND o.source=$2
 LEFT JOIN identity_authority.providers p ON p.tenant_id=o.tenant_id AND p.provider_id=o.provider_id
 LEFT JOIN LATERAL (
  SELECT s.auth_facts,s.auth_epoch,s.membership_epoch,s.provider_epoch,s.external_identity_id
  FROM identity_authority.sessions s
  JOIN identity_authority.external_identities e ON e.tenant_id=s.tenant_id AND e.identity_id=s.external_identity_id
  WHERE s.tenant_id=a.tenant_id AND s.principal_id=a.principal_id AND e.provider_id::text=$2
  ORDER BY s.facts_sequence DESC LIMIT 1
 ) ds ON $5
 LEFT JOIN identity_authority.external_identities de ON de.tenant_id=a.tenant_id AND de.principal_id=a.principal_id AND de.identity_id=ds.external_identity_id
 LEFT JOIN identity_authority.providers dp ON dp.tenant_id=de.tenant_id AND dp.provider_id=de.provider_id
 CROSS JOIN LATERAL (SELECT CASE
  WHEN NOT $4 THEN 'unavailable'
  WHEN NOT (a.enabled AND m.active) THEN 'unavailable'
  WHEN o.snapshot_id IS NULL THEN 'missing'
  WHEN o.source<>'local' AND NOT COALESCE(p.enabled AND p.config_version=o.config_version AND p.revocation_epoch=o.source_epoch AND EXISTS(SELECT FROM identity_authority.external_identities e WHERE e.tenant_id=o.tenant_id AND e.principal_id=o.principal_id AND e.provider_id=o.provider_id),false) THEN 'unavailable'
  WHEN o.observed_at>$3 THEN 'unavailable'
  WHEN LEAST(o.expires_at,o.observed_at+$6)<=$3 THEN 'expired'
  ELSE 'available' END AS status) pv
 CROSS JOIN LATERAL (SELECT CASE
  WHEN NOT $5 OR NOT (a.enabled AND m.active) THEN 'unavailable'
  WHEN ds.auth_facts IS NULL THEN 'missing'
  WHEN NOT COALESCE(dp.enabled AND dp.config_version=(ds.auth_facts->>'provider_config_version')::bigint AND dp.revocation_epoch=ds.provider_epoch AND ds.auth_epoch=a.auth_epoch AND ds.membership_epoch=m.epoch,false) THEN 'unavailable'
  WHEN ds.auth_facts->'department_snapshot'->>'status'<>'available' THEN COALESCE(ds.auth_facts->'department_snapshot'->>'reason','unavailable')
  WHEN (ds.auth_facts->'department_snapshot'->>'observed_at')::bigint>$3 THEN 'not_yet_valid'
  WHEN (ds.auth_facts->'department_snapshot'->>'expires_at')::bigint<=$3 THEN 'expired'
  ELSE 'available' END AS status) dv
 WHERE a.tenant_id=$1::uuid
)
