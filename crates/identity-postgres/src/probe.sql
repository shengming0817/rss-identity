WITH protected AS (
 SELECT c.oid,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='identity_authority' AND c.relname IN ('guard','local_credentials','accounts','memberships','attempts','sessions')
), policies AS (
 SELECT p.*,pg_get_expr(p.polqual,p.polrelid) AS predicate,pg_get_expr(p.polwithcheck,p.polrelid) AS check_predicate
 FROM pg_policy p JOIN protected t ON t.oid=p.polrelid
), groups AS (
 SELECT * FROM pg_roles WHERE rolname IN ('identity_account_runtime','identity_account_maintenance')
), required_privileges AS (
 SELECT * FROM (VALUES
 ('runtime','cli_grants','SELECT'),('runtime','cli_grants','INSERT'),('runtime','cli_grants','UPDATE'),('runtime','cli_grants','DELETE'),
 ('runtime','provider_credentials','SELECT'),('runtime','provider_credentials','INSERT'),('runtime','provider_credentials','UPDATE'),
 ('runtime','platform_administrators','SELECT'),('runtime','platform_administrators','INSERT'),('runtime','platform_administrators','DELETE'),
 ('maintenance','platform_administrators','SELECT'),('maintenance','platform_administrators','INSERT'),
 ('runtime','tenant_registry','SELECT'),('runtime','tenant_registry','INSERT'),('runtime','platform_operations','SELECT'),('runtime','platform_operations','INSERT'),
 ('runtime','local_credentials','SELECT'),('runtime','local_credentials','INSERT'),('runtime','local_credentials','UPDATE'),
 ('maintenance','local_credentials','SELECT'),('maintenance','local_credentials','INSERT'),
 ('runtime','providers','SELECT'),('runtime','providers','INSERT'),('runtime','providers','UPDATE'),('runtime','external_identities','SELECT'),('runtime','external_identities','INSERT'),('runtime','external_identities','UPDATE'),('runtime','link_intents','SELECT'),('runtime','link_intents','INSERT'),('runtime','link_intents','UPDATE'),('runtime','link_intents','DELETE'),('runtime','oidc_transactions','SELECT'),('runtime','oidc_transactions','INSERT'),('runtime','oidc_transactions','UPDATE'),('runtime','oidc_transactions','DELETE'),
 ('runtime','product_subjects','SELECT'),('runtime','product_subjects','INSERT'),
 ('runtime','downstream_grants','SELECT'),('runtime','downstream_grants','INSERT'),('runtime','downstream_grants','UPDATE'),('runtime','downstream_grants','DELETE'),
 ('runtime','accounts','SELECT'),('runtime','accounts','INSERT'),('runtime','accounts','UPDATE'),
 ('runtime','memberships','SELECT'),('runtime','memberships','INSERT'),('runtime','memberships','UPDATE'),
 ('runtime','attempts','SELECT'),('runtime','attempts','INSERT'),('runtime','attempts','UPDATE'),('runtime','attempts','DELETE'),
 ('runtime','sessions','SELECT'),('runtime','sessions','INSERT'),('runtime','sessions','UPDATE'),
 ('runtime','deployment','SELECT'),('runtime','schema_version','SELECT'),
 ('maintenance','schema_version','SELECT'),('maintenance','deployment','SELECT'),
 ('maintenance','accounts','SELECT'),('maintenance','accounts','INSERT'),
 ('maintenance','memberships','SELECT'),('maintenance','memberships','INSERT'),
 ('runtime','guard','SELECT'),('runtime','guard','INSERT'),('runtime','guard','UPDATE'),
 ('maintenance','guard','SELECT'),('maintenance','guard','INSERT'),('maintenance','guard','UPDATE')
 ) AS r(profile,tab,privilege)
), required_columns AS (
 SELECT * FROM (VALUES
 ('maintenance','deployment','system_domain','UPDATE'),
 ('maintenance','local_credentials','password_hash','UPDATE'),
 ('maintenance','accounts','auth_epoch','UPDATE')
 ) AS r(profile,tab,col,privilege)
), tables AS (
 SELECT c.oid,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='identity_authority' AND c.relkind='r'
), checks AS (
 SELECT
 (SELECT count(*)=1 AND bool_and(version=8) FROM identity_authority.schema_version) AS version_ok,
 ((SELECT count(*)=2 AND bool_and(NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication) FROM groups)
 AND (SELECT NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication FROM pg_roles WHERE rolname=current_user)
 AND NOT EXISTS(SELECT FROM pg_roles WHERE pg_has_role(current_user,oid,'MEMBER') AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
 AND CASE WHEN $1='runtime' THEN
   pg_has_role(current_user,(SELECT oid FROM groups WHERE rolname='identity_account_runtime'),'USAGE') AND NOT pg_has_role(current_user,(SELECT oid FROM groups WHERE rolname='identity_account_maintenance'),'MEMBER')
 ELSE
   $1='maintenance' AND pg_has_role(current_user,(SELECT oid FROM groups WHERE rolname='identity_account_maintenance'),'USAGE') AND NOT pg_has_role(current_user,(SELECT oid FROM groups WHERE rolname='identity_account_runtime'),'MEMBER')
 END) AS role_ok,
 (NOT has_schema_privilege(current_user,(SELECT oid FROM pg_namespace WHERE nspname='identity_authority'),'CREATE')
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
) AS privileges_ok,
 (EXISTS(SELECT FROM pg_roles WHERE rolname='identity_tenant_registrar' AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication)
 AND NOT EXISTS(SELECT FROM pg_auth_members WHERE roleid=(SELECT oid FROM pg_roles WHERE rolname='identity_tenant_registrar') OR member=(SELECT oid FROM pg_roles WHERE rolname='identity_tenant_registrar'))
 AND (SELECT count(*)=2 AND bool_and(p.prosecdef AND p.proowner=(SELECT oid FROM pg_roles WHERE rolname='identity_tenant_registrar') AND has_function_privilege(current_user,p.oid,'EXECUTE')=($1='runtime') AND NOT EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')) FROM pg_proc p JOIN pg_namespace n ON p.pronamespace=n.oid WHERE n.nspname='identity_authority' AND p.proname IN ('register_tenant','insert_tenant_administrator'))) AS contract_ok
)
SELECT CASE
 WHEN version_ok IS NOT TRUE THEN 'schema-version'
 WHEN role_ok IS NOT TRUE THEN 'role'
 WHEN contract_ok IS NOT TRUE THEN 'schema-contract'
 WHEN privileges_ok IS NOT TRUE THEN 'privileges'
 ELSE 'ok' END
FROM checks
