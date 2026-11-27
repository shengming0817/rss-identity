SELECT min(CASE WHEN observed_at>$2 THEN observed_at ELSE least(expires_at,observed_at+$3) END)
FROM profile_facts
WHERE tenant_id=$1::uuid AND eligible AND least(expires_at,observed_at+$3)>$2
