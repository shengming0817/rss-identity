WITH latest AS (
 SELECT DISTINCT ON (s.principal_id) s.auth_facts->'department_snapshot' AS fact
 FROM identity_authority.sessions s
 JOIN identity_authority.external_identities e ON e.tenant_id=s.tenant_id AND e.identity_id=s.external_identity_id
 WHERE s.tenant_id=$1::uuid AND e.provider_id::text=$2
 ORDER BY s.principal_id,s.facts_sequence DESC
), boundaries AS (
 SELECT (fact->>'observed_at')::bigint AS until FROM latest WHERE fact->>'status'='available'
 UNION ALL
 SELECT (fact->>'expires_at')::bigint FROM latest WHERE fact->>'status'='available'
)
SELECT min(until) FROM boundaries WHERE until>$3
