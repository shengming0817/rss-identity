WITH required_privileges AS (
 SELECT * FROM (VALUES ('runtime','schema_version','SELECT'),('runtime','deployment','SELECT'),('runtime','guard','SELECT'),('runtime','guard','UPDATE'),('runtime','accounts','SELECT'),('runtime','accounts','INSERT'),('runtime','accounts','UPDATE'),('runtime','memberships','SELECT'),('runtime','memberships','INSERT'),('runtime','memberships','UPDATE'),('runtime','local_credentials','SELECT'),('runtime','local_credentials','INSERT'),('runtime','local_credentials','UPDATE'),('runtime','attempts','SELECT'),('runtime','attempts','INSERT'),('runtime','attempts','UPDATE'),('runtime','attempts','DELETE'),('runtime','sessions','SELECT'),('runtime','sessions','INSERT'),('runtime','sessions','UPDATE'),('runtime','providers','SELECT'),('runtime','providers','INSERT'),('runtime','providers','UPDATE'),('runtime','provider_credentials','SELECT'),('runtime','provider_credentials','INSERT'),('runtime','provider_credentials','UPDATE'),('runtime','external_identities','SELECT'),('runtime','external_identities','INSERT'),('runtime','external_identities','UPDATE'),('runtime','link_intents','SELECT'),('runtime','link_intents','INSERT'),('runtime','link_intents','UPDATE'),('runtime','link_intents','DELETE'),('runtime','oidc_transactions','SELECT'),('runtime','oidc_transactions','INSERT'),('runtime','oidc_transactions','UPDATE'),('runtime','oidc_transactions','DELETE'),('maintenance','schema_version','SELECT'),('maintenance','deployment','SELECT'),('maintenance','guard','SELECT'),('maintenance','guard','INSERT'),('maintenance','guard','UPDATE'),('maintenance','accounts','SELECT'),('maintenance','accounts','INSERT'),('maintenance','memberships','SELECT'),('maintenance','memberships','INSERT'),('maintenance','local_credentials','SELECT'),('maintenance','local_credentials','INSERT')) r(profile,tab,privilege)
), required_columns AS (
 SELECT * FROM (VALUES ('maintenance', 'accounts', 'auth_epoch', 'UPDATE'),('maintenance', 'local_credentials', 'password_hash', 'UPDATE')) r(profile,tab,col,privilege)
), tables AS (
 SELECT c.oid,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='identity_authority' AND c.relkind='r'
), checks AS (
 SELECT
 (SELECT count(*)=1 AND bool_and(version=10) FROM identity_authority.schema_version) AS version_ok,
 (NOT EXISTS(SELECT FROM pg_roles WHERE pg_has_role(current_user,oid,'MEMBER') AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))) AS role_ok,
 (has_schema_privilege(current_user,'identity_authority','USAGE')
 AND NOT has_schema_privilege(current_user,'identity_authority','CREATE')
 AND NOT has_schema_privilege(current_user,'identity_authority','USAGE WITH GRANT OPTION')
 AND (SELECT bool_and(coalesce(has_table_privilege(current_user,t.oid,r.privilege),false)) FROM required_privileges r LEFT JOIN tables t ON t.relname=r.tab WHERE r.profile=$1)
 AND NOT EXISTS (
   SELECT FROM tables t CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER'),('MAINTAIN')) p(privilege)
   WHERE has_table_privilege(current_user,t.oid,p.privilege) IS DISTINCT FROM
     EXISTS(SELECT FROM required_privileges r WHERE r.profile=$1 AND r.tab=t.relname AND r.privilege=p.privilege)
     OR has_table_privilege(current_user,t.oid,p.privilege||' WITH GRANT OPTION')
 )
 AND NOT EXISTS (
   SELECT FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
   CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) p(privilege)
   WHERE has_column_privilege(current_user,t.oid,a.attnum,p.privilege) IS DISTINCT FROM
     (EXISTS(SELECT FROM required_privileges r WHERE r.profile=$1 AND r.tab=t.relname AND r.privilege=p.privilege)
      OR EXISTS(SELECT FROM required_columns r WHERE r.profile=$1 AND r.tab=t.relname AND r.col=a.attname AND r.privilege=p.privilege))
     OR has_column_privilege(current_user,t.oid,a.attnum,p.privilege||' WITH GRANT OPTION')
 )
 AND NOT EXISTS(SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='identity_authority' AND has_function_privilege(current_user,p.oid,'EXECUTE'))
) AS privileges_ok
)
SELECT CASE
 WHEN version_ok IS NOT TRUE THEN 'schema-version'
 WHEN role_ok IS NOT TRUE THEN 'role'
 WHEN privileges_ok IS NOT TRUE THEN 'privileges'
 ELSE 'ok' END FROM checks
