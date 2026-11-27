-- $1 is the tenant and $2 the optional department source UUID. A subject may have
-- multiple external identities at one provider. Read its latest acceptance exactly once.
WITH department_facts AS (
 SELECT owners.tenant_id,owners.principal_id,latest.*
 FROM (
  SELECT DISTINCT e.tenant_id,e.principal_id FROM identity_authority.external_identities e
  WHERE e.tenant_id=$1::uuid AND e.provider_id=$2
 ) owners
 CROSS JOIN LATERAL (
  SELECT s.auth_facts->'department_snapshot' AS fact,s.auth_facts->>'provider_config_version' AS config_version,
   s.auth_epoch,s.membership_epoch,s.provider_epoch
  FROM identity_authority.sessions s
  WHERE s.tenant_id=owners.tenant_id AND s.principal_id=owners.principal_id AND s.source_provider_id=$2
  ORDER BY s.facts_sequence DESC,s.auth_epoch DESC,s.membership_epoch DESC,s.session_id LIMIT 1
 ) latest
)
