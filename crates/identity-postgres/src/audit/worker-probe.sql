-- Check every role the worker can SET, including NOINHERIT memberships.
WITH reachable AS (
    SELECT * FROM pg_roles WHERE pg_has_role($1::name,oid,'SET')
)
SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1 AND rolcanlogin)
AND NOT EXISTS(SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)
AND NOT EXISTS(
    SELECT FROM reachable r CROSS JOIN pg_namespace n
    WHERE n.nspname IN ('identity_authority','rss_audit')
    AND has_schema_privilege(r.oid,n.oid,'CREATE')
)
AND NOT EXISTS(
    SELECT FROM reachable r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='identity_authority' AND c.relkind IN ('r','p','v','m')
    AND (has_table_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
         OR has_any_column_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
)
AND NOT EXISTS(
    SELECT FROM reachable r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='rss_audit' AND c.relkind='r'
    AND (has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
         OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES'))
)

AND NOT EXISTS(
    SELECT FROM reachable r CROSS JOIN pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='rss_transactional_messaging' AND p.proname IN ('append_outbox','prepare_outbox_partitions')
    AND has_function_privilege(r.oid,p.oid,'EXECUTE')
)
