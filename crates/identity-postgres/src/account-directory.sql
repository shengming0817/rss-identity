, account_rows AS (
 SELECT a.principal_id AS "principalId",l.login_key AS login,a.enabled AS enabled,
 m.active AS "memberActive",l.principal_id IS NOT NULL AS "hasLocalPassword",
 CASE WHEN pv.status='available' AND o.value->'displayName'->>'status'='available' THEN o.value->'displayName'->>'value' END AS "displayName",
 CASE WHEN pv.status='available' AND o.value->'email'->>'status'='available' THEN o.value->'email'->>'value' END AS email,
 pv.status AS "profileStatus",dv.status AS "departmentStatus",
 CASE WHEN dv.status='available' THEN ds.fact->'snapshot' END AS "departmentSnapshot"
 FROM identity_authority.accounts a
 JOIN identity_authority.memberships m USING(tenant_id,principal_id)
 LEFT JOIN identity_authority.local_credentials l USING(tenant_id,principal_id)
 LEFT JOIN identity_authority.profile_observations o ON o.tenant_id=a.tenant_id AND o.principal_id=a.principal_id AND o.source=$4
 LEFT JOIN identity_authority.providers p ON p.tenant_id=o.tenant_id AND p.provider_id=o.provider_id
 LEFT JOIN department_facts ds ON ds.tenant_id=a.tenant_id AND ds.principal_id=a.principal_id
 LEFT JOIN identity_authority.providers dp ON dp.tenant_id=a.tenant_id AND dp.provider_id=$2
 CROSS JOIN LATERAL (SELECT CASE
  WHEN $4::text IS NULL THEN 'unavailable'
  WHEN NOT (a.enabled AND m.active) THEN 'unavailable'
  WHEN o.snapshot_id IS NULL THEN 'missing'
  WHEN o.source<>'local' AND NOT COALESCE(p.enabled AND p.config_version=o.config_version AND p.revocation_epoch=o.source_epoch AND EXISTS(SELECT FROM identity_authority.external_identities e WHERE e.tenant_id=o.tenant_id AND e.principal_id=o.principal_id AND e.provider_id=o.provider_id),false) THEN 'unavailable'
  WHEN o.observed_at>$3 THEN 'unavailable'
  WHEN LEAST(o.expires_at,o.observed_at+$5)<=$3 THEN 'expired'
  ELSE 'available' END AS status) pv
 CROSS JOIN LATERAL (SELECT CASE
  WHEN $2::uuid IS NULL OR NOT (a.enabled AND m.active) THEN 'unavailable'
  WHEN ds.principal_id IS NULL THEN 'missing'
  WHEN NOT COALESCE(dp.enabled AND dp.config_version=ds.config_version::bigint AND dp.revocation_epoch=ds.provider_epoch AND ds.auth_epoch=a.auth_epoch AND ds.membership_epoch=m.epoch,false) THEN 'unavailable'
  WHEN ds.fact->>'status'<>'available' THEN COALESCE(ds.fact->>'reason','unavailable')
  WHEN (ds.fact->>'observed_at')::bigint>$3 THEN 'not_yet_valid'
  WHEN (ds.fact->>'expires_at')::bigint<=$3 THEN 'expired'
  ELSE 'available' END AS status) dv
 WHERE a.tenant_id=$1::uuid
)
