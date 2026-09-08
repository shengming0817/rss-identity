WITH protected AS (
 SELECT c.oid,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='access_authority' AND c.relname IN ('guard','accounts','memberships','authorizations','attempts')
), policies AS (
 SELECT p.*,pg_get_expr(p.polqual,p.polrelid) AS predicate,pg_get_expr(p.polwithcheck,p.polrelid) AS check_predicate
 FROM pg_policy p JOIN protected t ON t.oid=p.polrelid
), groups AS (
 SELECT * FROM pg_roles WHERE rolname IN ('access_account_runtime','access_authorization_issuer')
), required_privileges AS (
 SELECT * FROM (VALUES
 ('runtime','accounts','SELECT'),('runtime','accounts','INSERT'),('runtime','accounts','UPDATE'),
 ('runtime','memberships','SELECT'),('runtime','memberships','INSERT'),('runtime','memberships','UPDATE'),
 ('runtime','attempts','SELECT'),('runtime','attempts','INSERT'),('runtime','attempts','UPDATE'),('runtime','attempts','DELETE'),
 ('runtime','authorizations','SELECT'),('runtime','deployment','SELECT'),('runtime','schema_version','SELECT'),('issuer','schema_version','SELECT'),
 ('issuer','authorizations','SELECT'),('issuer','authorizations','INSERT'),('issuer','authorizations','UPDATE'),('issuer','authorizations','DELETE'),('issuer','deployment','SELECT'),
 ('runtime','guard','SELECT'),('runtime','guard','INSERT'),('runtime','guard','UPDATE'),
 ('issuer','guard','SELECT'),('issuer','guard','INSERT'),('issuer','guard','UPDATE')
 ) AS r(profile,tab,privilege)
), required_columns AS (
 SELECT * FROM (VALUES
 ('runtime','authorizations','consumed','UPDATE'),('runtime','deployment','initialized','UPDATE'),
 ('issuer','deployment','bootstrap_tenant','UPDATE'),
 ('issuer','accounts','tenant_id','SELECT'),('issuer','accounts','principal_id','SELECT'),
 ('issuer','accounts','administrator','SELECT'),('issuer','accounts','auth_epoch','SELECT')
 ) AS r(profile,tab,col,privilege)
), tables AS (
 SELECT c.oid,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='access_authority' AND c.relkind='r'
)
SELECT
 (SELECT count(*)=1 AND bool_and(version=1) FROM access_authority.schema_version)
 AND (SELECT count(*)=5 AND bool_and(relrowsecurity AND relforcerowsecurity) FROM protected)
 AND (SELECT count(*)=5 AND bool_and(polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
   AND predicate='(tenant_id = (NULLIF(current_setting(''rss.tenant_id''::text, true), ''''::text))::uuid)' AND predicate=check_predicate) FROM policies)
 AND (SELECT count(*)=2 AND bool_and(NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication) FROM groups)
 AND (SELECT NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication FROM pg_roles WHERE rolname=current_user)
 AND NOT EXISTS(SELECT FROM pg_roles WHERE pg_has_role(current_user,oid,'MEMBER') AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
 AND NOT has_schema_privilege(current_user,'access_authority','CREATE')
 AND (SELECT bool_and(has_table_privilege(current_user,'access_authority.'||tab,privilege)) FROM required_privileges WHERE profile=$1)
 AND EXISTS(SELECT FROM pg_constraint WHERE conrelid='access_authority.accounts'::regclass AND pg_get_constraintdef(oid)='UNIQUE (tenant_id, login_key)')
 AND EXISTS(SELECT FROM pg_constraint WHERE conrelid='access_authority.accounts'::regclass AND pg_get_constraintdef(oid)='PRIMARY KEY (tenant_id, principal_id)')
 AND EXISTS(SELECT FROM pg_constraint WHERE conrelid='access_authority.accounts'::regclass AND pg_get_constraintdef(oid)='CHECK ((auth_epoch > 0))')
 AND EXISTS(SELECT FROM pg_constraint WHERE conrelid='access_authority.accounts'::regclass AND pg_get_constraintdef(oid)='CHECK ((credential_version > 0))')
 AND EXISTS(SELECT FROM pg_constraint WHERE conrelid='access_authority.memberships'::regclass AND pg_get_constraintdef(oid)='CHECK ((epoch > 0))')
 -- Compare every effective table/column privilege, including PUBLIC and inherited grants.
 AND (SELECT count(*)=7 FROM tables)
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
 AND CASE WHEN $1='runtime' THEN
   pg_has_role(current_user,'access_account_runtime','USAGE') AND NOT pg_has_role(current_user,'access_authorization_issuer','MEMBER')
 ELSE
   $1='issuer' AND pg_has_role(current_user,'access_authorization_issuer','USAGE') AND NOT pg_has_role(current_user,'access_account_runtime','MEMBER')
 END
