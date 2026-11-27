-- Enumerate this source's linked subjects once. Multiple external IDs can belong to one subject.
WITH subjects AS (
 SELECT DISTINCT e.principal_id
 FROM identity_authority.external_identities e
 WHERE e.tenant_id=$1::uuid AND e.provider_id=$2
)
SELECT least(min((fact->>'observed_at')::bigint) FILTER (WHERE (fact->>'observed_at')::bigint>$3),
             min((fact->>'expires_at')::bigint) FILTER (WHERE (fact->>'expires_at')::bigint>$3))
FROM subjects
CROSS JOIN LATERAL (
 SELECT s.auth_facts->'department_snapshot' AS fact
 FROM identity_authority.sessions s
 WHERE s.tenant_id=$1::uuid AND s.source_provider_id=$2 AND s.principal_id=subjects.principal_id
 ORDER BY s.facts_sequence DESC,s.auth_epoch DESC,s.membership_epoch DESC,s.session_id
 LIMIT 1
) latest
WHERE fact->>'status'='available'
