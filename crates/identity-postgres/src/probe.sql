WITH protected AS (
 SELECT c.oid,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='identity_authority' AND c.relname IN ('guard','accounts','memberships','attempts','sessions')
), policies AS (
 SELECT p.*,pg_get_expr(p.polqual,p.polrelid) AS predicate,pg_get_expr(p.polwithcheck,p.polrelid) AS check_predicate
 FROM pg_policy p JOIN protected t ON t.oid=p.polrelid
), groups AS (
 SELECT * FROM pg_roles WHERE rolname IN ('identity_account_runtime','identity_account_maintenance')
), required_privileges AS (
 SELECT * FROM (VALUES
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
 ('maintenance','deployment','bootstrap_tenant','UPDATE'),
 ('maintenance','accounts','password_hash','UPDATE'),
 ('maintenance','accounts','auth_epoch','UPDATE'),
 ('maintenance','accounts','credential_version','UPDATE')
 ) AS r(profile,tab,col,privilege)
), tables AS (
 SELECT c.oid,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='identity_authority' AND c.relkind='r'
), checks AS (
 SELECT
 (SELECT count(*)=1 AND bool_and(version=3) FROM identity_authority.schema_version) AS version_ok,
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
 ((SELECT count(*)=5 AND bool_and(relrowsecurity AND relforcerowsecurity) FROM protected)
 AND (SELECT count(*)=5 AND bool_and(polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
   AND predicate='(tenant_id = (NULLIF(current_setting(''rss.tenant_id''::text, true), ''''::text))::uuid)' AND predicate=check_predicate) FROM policies)
 AND EXISTS(SELECT FROM pg_constraint WHERE conrelid=to_regclass('identity_authority.accounts') AND pg_get_constraintdef(oid)='UNIQUE (tenant_id, login_key)')
 AND EXISTS(SELECT FROM pg_constraint WHERE conrelid=to_regclass('identity_authority.accounts') AND pg_get_constraintdef(oid)='PRIMARY KEY (tenant_id, principal_id)')
 AND EXISTS(SELECT FROM pg_constraint WHERE conrelid=to_regclass('identity_authority.accounts') AND pg_get_constraintdef(oid)='CHECK ((auth_epoch > 0))')
 AND EXISTS(SELECT FROM pg_constraint WHERE conrelid=to_regclass('identity_authority.accounts') AND pg_get_constraintdef(oid)='CHECK ((credential_version > 0))')
 AND EXISTS(SELECT FROM pg_constraint WHERE conrelid=to_regclass('identity_authority.memberships') AND pg_get_constraintdef(oid)='CHECK ((epoch > 0))')
 AND (SELECT count(*)=11 AND bool_and(convalidated AND NOT condeferrable AND NOT condeferred) FROM pg_constraint WHERE conrelid=to_regclass('identity_authority.sessions'))
 AND NOT EXISTS (SELECT FROM (VALUES
   ('CHECK ((((absolute_expires_at)::numeric - (auth_time)::numeric) = ANY (ARRAY[(14400)::numeric, (28800)::numeric])))'),
   ('CHECK (((auth_time < idle_expires_at) AND (idle_expires_at <= absolute_expires_at)))'),
   ('CHECK (((revoked_at IS NULL) OR (revoked_at >= auth_time)))'),
   ('CHECK ((auth_epoch > 0))'),
   ('CHECK ((auth_time > 0))'),
   ('CHECK ((membership_epoch > 0))'),
   ('PRIMARY KEY (tenant_id, session_id)'),
   ('CHECK ((session_id <> ''00000000-0000-0000-0000-000000000000''::uuid))'),
   ('FOREIGN KEY (tenant_id, principal_id) REFERENCES identity_authority.accounts(tenant_id, principal_id)'),
   ('UNIQUE (tenant_id, token_hash)'),
   ('CHECK ((octet_length(token_hash) = 32))')
 ) expected(definition) WHERE NOT EXISTS (SELECT FROM pg_constraint WHERE conrelid=to_regclass('identity_authority.sessions') AND pg_get_constraintdef(oid)=definition))
 AND (SELECT count(*)=10 FROM pg_attribute WHERE attrelid=to_regclass('identity_authority.sessions') AND attnum>0 AND NOT attisdropped)
 AND NOT EXISTS(SELECT FROM (VALUES
   ('tenant_id','uuid',true),
   ('principal_id','uuid',true),
   ('session_id','uuid',true),
   ('token_hash','bytea',true),
   ('auth_epoch','bigint',true),
   ('membership_epoch','bigint',true),
   ('auth_time','bigint',true),
   ('idle_expires_at','bigint',true),
   ('absolute_expires_at','bigint',true),
   ('revoked_at','bigint',false)
 ) expected(col,typ,nonnull) LEFT JOIN pg_attribute a ON a.attrelid=to_regclass('identity_authority.sessions') AND a.attname=col AND a.attnum>0 AND NOT a.attisdropped
 WHERE a.attnum IS NULL OR a.atttypid <> to_regtype(typ) OR a.attnotnull <> nonnull)
 AND (SELECT count(*)=7 FROM tables)
 AND NOT EXISTS(SELECT FROM required_privileges r WHERE NOT EXISTS(SELECT FROM tables t WHERE t.relname=r.tab))
 AND NOT EXISTS(SELECT FROM required_columns r LEFT JOIN tables t ON t.relname=r.tab
   LEFT JOIN pg_attribute a ON a.attrelid=t.oid AND a.attname=r.col AND a.attnum>0 AND NOT a.attisdropped
   WHERE a.attnum IS NULL)) AS contract_ok
)
SELECT CASE
 WHEN version_ok IS NOT TRUE THEN 'schema-version'
 WHEN role_ok IS NOT TRUE THEN 'role'
 WHEN contract_ok IS NOT TRUE THEN 'schema-contract'
 WHEN privileges_ok IS NOT TRUE THEN 'privileges'
 ELSE 'ok' END
FROM checks
