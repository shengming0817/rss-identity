WITH reachable AS (
 SELECT * FROM pg_roles WHERE pg_has_role(current_user, oid, 'SET') OR pg_has_role(current_user, oid, 'USAGE')
), namespace AS (
 SELECT oid FROM pg_namespace WHERE nspname='identity_authority'
), reader AS (
 SELECT to_regprocedure('identity_authority.personnel_facts(uuid,uuid,uuid[],text,text,text[],bigint)') AS oid
)
SELECT coalesce(has_schema_privilege(current_user,n.oid,'USAGE')
 AND has_function_privilege(current_user,reader.oid,'EXECUTE')
 AND NOT EXISTS (SELECT FROM pg_proc p, LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl
  WHERE p.oid=reader.oid AND acl.grantee=0 AND acl.privilege_type='EXECUTE')
 AND NOT EXISTS (
  SELECT FROM reachable r WHERE r.rolsuper OR r.rolbypassrls OR r.rolcreaterole
    OR has_schema_privilege(r.oid,n.oid,'CREATE')
    OR EXISTS (SELECT FROM pg_class c WHERE c.relnamespace=n.oid AND c.relkind='r' AND
     (has_any_column_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')
      OR has_table_privilege(r.oid,c.oid,'DELETE,TRUNCATE,TRIGGER,MAINTAIN')))
    OR EXISTS (SELECT FROM pg_proc p WHERE p.pronamespace=n.oid AND p.oid<>reader.oid
     AND has_function_privilege(r.oid,p.oid,'EXECUTE'))
 ),false)
FROM namespace n CROSS JOIN reader
