-- Access owns this migration identity; RSS message schema is installed separately.
CREATE SCHEMA access_authority;
CREATE TABLE access_authority.schema_version(version integer PRIMARY KEY CHECK(version=1));
INSERT INTO access_authority.schema_version VALUES(1);
CREATE ROLE access_account_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
CREATE ROLE access_authorization_issuer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
CREATE TABLE access_authority.deployment (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 authority_id uuid NOT NULL DEFAULT gen_random_uuid(),
 bootstrap_tenant uuid,
 initialized boolean NOT NULL DEFAULT false
);
INSERT INTO access_authority.deployment DEFAULT VALUES;
CREATE FUNCTION access_authority.protect_deployment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.authority_id <> OLD.authority_id OR (OLD.initialized AND NOT NEW.initialized)
 OR (OLD.bootstrap_tenant IS NOT NULL AND NEW.bootstrap_tenant IS DISTINCT FROM OLD.bootstrap_tenant) THEN
 RAISE EXCEPTION 'immutable authority state'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER protect_deployment BEFORE UPDATE ON access_authority.deployment FOR EACH ROW EXECUTE FUNCTION access_authority.protect_deployment();
CREATE TABLE access_authority.guard(tenant_id uuid PRIMARY KEY);
CREATE TABLE access_authority.accounts (
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
CREATE TABLE access_authority.memberships (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL, active boolean NOT NULL DEFAULT true,
 epoch bigint NOT NULL DEFAULT 1 CHECK(epoch>0),
 PRIMARY KEY(tenant_id,principal_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES access_authority.accounts
);
CREATE TABLE access_authority.authorizations (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL,
 purpose text NOT NULL CHECK(purpose IN ('initialize','recover')),
 authorization_id uuid NOT NULL UNIQUE,
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 account_epoch bigint NOT NULL CHECK(account_epoch>=0),
 expires_at timestamptz NOT NULL, consumed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,principal_id,purpose)
);
CREATE TABLE access_authority.attempts (
 tenant_id uuid NOT NULL, key text NOT NULL CHECK(octet_length(key) BETWEEN 1 AND 300),
 count integer NOT NULL CHECK(count>0), expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,key)
);
CREATE INDEX attempts_expiry ON access_authority.attempts(tenant_id,expires_at);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['guard','accounts','memberships','authorizations','attempts'] LOOP
 EXECUTE format('ALTER TABLE access_authority.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE access_authority.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON access_authority.%I USING (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
REVOKE ALL ON SCHEMA access_authority FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA access_authority FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA access_authority FROM PUBLIC;
GRANT USAGE ON SCHEMA access_authority TO access_account_runtime,access_authorization_issuer;
GRANT SELECT ON access_authority.schema_version,access_authority.deployment TO access_account_runtime,access_authorization_issuer;
GRANT UPDATE(initialized) ON access_authority.deployment TO access_account_runtime;
GRANT UPDATE(bootstrap_tenant) ON access_authority.deployment TO access_authorization_issuer;
GRANT SELECT,INSERT,UPDATE ON access_authority.guard TO access_account_runtime,access_authorization_issuer;
GRANT SELECT,INSERT,UPDATE ON access_authority.accounts,access_authority.memberships TO access_account_runtime;
GRANT SELECT(tenant_id,principal_id,administrator,auth_epoch) ON access_authority.accounts TO access_authorization_issuer;
GRANT SELECT,INSERT,UPDATE,DELETE ON access_authority.attempts TO access_account_runtime;
GRANT SELECT,UPDATE(consumed) ON access_authority.authorizations TO access_account_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON access_authority.authorizations TO access_authorization_issuer;
