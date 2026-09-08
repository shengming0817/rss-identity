-- Identity owns this migration identity; RSS message schema is installed separately.
CREATE SCHEMA identity_authority;
CREATE TABLE identity_authority.schema_version(version integer PRIMARY KEY CHECK(version=3));
INSERT INTO identity_authority.schema_version VALUES(3);
CREATE ROLE identity_account_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
CREATE ROLE identity_account_maintenance NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
CREATE TABLE identity_authority.deployment (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 authority_id uuid NOT NULL DEFAULT gen_random_uuid(),
 bootstrap_tenant uuid
);
INSERT INTO identity_authority.deployment DEFAULT VALUES;
CREATE FUNCTION identity_authority.protect_deployment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.authority_id <> OLD.authority_id
 OR (OLD.bootstrap_tenant IS NOT NULL AND NEW.bootstrap_tenant IS DISTINCT FROM OLD.bootstrap_tenant) THEN
 RAISE EXCEPTION 'immutable authority state'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER protect_deployment BEFORE UPDATE ON identity_authority.deployment FOR EACH ROW EXECUTE FUNCTION identity_authority.protect_deployment();
CREATE TABLE identity_authority.guard(tenant_id uuid PRIMARY KEY);
CREATE TABLE identity_authority.accounts (
 tenant_id uuid NOT NULL,
 principal_id uuid NOT NULL CHECK(principal_id <> '00000000-0000-0000-0000-000000000000'),
 login_key text NOT NULL CHECK(octet_length(login_key) BETWEEN 1 AND 128 AND login_key=lower(login_key COLLATE "C") AND login_key !~ '[^\x20-\x7e]' AND login_key=btrim(login_key)),
 password_hash text NOT NULL CHECK(octet_length(password_hash) BETWEEN 80 AND 256 AND password_hash ~ '^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{21}[AQgw]\$[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$'),
 enabled boolean NOT NULL DEFAULT true,
 administrator boolean NOT NULL DEFAULT false,
 emergency boolean NOT NULL DEFAULT false,
 auth_epoch bigint NOT NULL DEFAULT 1 CHECK(auth_epoch>0),
 credential_version bigint NOT NULL DEFAULT 1 CHECK(credential_version>0),
 PRIMARY KEY(tenant_id,principal_id), UNIQUE(tenant_id,login_key)
);
CREATE TABLE identity_authority.memberships (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL, active boolean NOT NULL DEFAULT true,
 epoch bigint NOT NULL DEFAULT 1 CHECK(epoch>0),
 PRIMARY KEY(tenant_id,principal_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts
);
CREATE TABLE identity_authority.attempts (
 tenant_id uuid NOT NULL, key text NOT NULL CHECK(octet_length(key) BETWEEN 1 AND 300),
 count integer NOT NULL CHECK(count>0), expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,key)
);
CREATE INDEX attempts_expiry ON identity_authority.attempts(tenant_id,expires_at);
CREATE TABLE identity_authority.sessions (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL,
 session_id uuid NOT NULL CHECK(session_id <> '00000000-0000-0000-0000-000000000000'),
 token_hash bytea NOT NULL CHECK(octet_length(token_hash)=32),
 auth_epoch bigint NOT NULL CHECK(auth_epoch>0),
 membership_epoch bigint NOT NULL CHECK(membership_epoch>0),
 auth_time bigint NOT NULL CHECK(auth_time>0),
 idle_expires_at bigint NOT NULL,
 absolute_expires_at bigint NOT NULL,
 revoked_at bigint,
 PRIMARY KEY(tenant_id,session_id),
 UNIQUE(tenant_id,token_hash),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts,
 CONSTRAINT session_lifetime CHECK(auth_time < idle_expires_at AND idle_expires_at <= absolute_expires_at),
 CONSTRAINT session_duration CHECK(absolute_expires_at::numeric-auth_time::numeric IN (14400,28800)),
 CONSTRAINT session_revocation CHECK(revoked_at IS NULL OR revoked_at >= auth_time)
);
CREATE INDEX sessions_principal ON identity_authority.sessions(tenant_id,principal_id,session_id);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['guard','accounts','memberships','attempts','sessions'] LOOP
 EXECUTE format('ALTER TABLE identity_authority.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE identity_authority.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON identity_authority.%I USING (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
REVOKE ALL ON SCHEMA identity_authority FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA identity_authority FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA identity_authority FROM PUBLIC;
GRANT USAGE ON SCHEMA identity_authority TO identity_account_runtime,identity_account_maintenance;
GRANT SELECT ON identity_authority.schema_version,identity_authority.deployment TO identity_account_runtime,identity_account_maintenance;
GRANT UPDATE(bootstrap_tenant) ON identity_authority.deployment TO identity_account_maintenance;
GRANT SELECT,INSERT,UPDATE ON identity_authority.guard TO identity_account_runtime,identity_account_maintenance;
GRANT SELECT,INSERT,UPDATE ON identity_authority.accounts,identity_authority.memberships TO identity_account_runtime;
GRANT SELECT,INSERT ON identity_authority.accounts,identity_authority.memberships TO identity_account_maintenance;
GRANT UPDATE(password_hash,auth_epoch,credential_version) ON identity_authority.accounts TO identity_account_maintenance;
GRANT SELECT,INSERT,UPDATE,DELETE ON identity_authority.attempts TO identity_account_runtime;

GRANT SELECT,INSERT,UPDATE ON identity_authority.sessions TO identity_account_runtime;
