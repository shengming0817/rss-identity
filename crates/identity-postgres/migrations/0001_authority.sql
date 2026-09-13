-- Identity owns this migration identity; RSS message schema is installed separately.
CREATE SCHEMA identity_authority;
CREATE TABLE identity_authority.schema_version(version integer PRIMARY KEY CHECK(version=8));
INSERT INTO identity_authority.schema_version VALUES(8);
CREATE ROLE identity_account_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
CREATE ROLE identity_account_maintenance NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
CREATE TABLE identity_authority.deployment (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 authority_id uuid NOT NULL DEFAULT gen_random_uuid(),
 system_domain uuid,
 environment_id text,
 identity_config_version bigint,
 identity_public_origin text,
 product_public_origin text,
 CONSTRAINT complete_deployment_identity CHECK (
 (environment_id IS NULL AND identity_config_version IS NULL AND identity_public_origin IS NULL AND product_public_origin IS NULL)
 OR (environment_id IS NOT NULL AND environment_id ~ '^[A-Za-z0-9_-]{1,128}$' AND identity_config_version IS NOT NULL AND identity_config_version>0 AND identity_public_origin IS NOT NULL AND product_public_origin IS NOT NULL AND identity_public_origin<>product_public_origin))
);
INSERT INTO identity_authority.deployment DEFAULT VALUES;
CREATE FUNCTION identity_authority.protect_deployment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (OLD.environment_id IS NOT NULL AND (NEW.environment_id,NEW.identity_config_version,NEW.identity_public_origin,NEW.product_public_origin) IS DISTINCT FROM (OLD.environment_id,OLD.identity_config_version,OLD.identity_public_origin,OLD.product_public_origin))
 OR NEW.authority_id <> OLD.authority_id
 OR (OLD.system_domain IS NOT NULL AND NEW.system_domain IS DISTINCT FROM OLD.system_domain) THEN
 RAISE EXCEPTION 'immutable authority state'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER protect_deployment BEFORE UPDATE ON identity_authority.deployment FOR EACH ROW EXECUTE FUNCTION identity_authority.protect_deployment();
CREATE TABLE identity_authority.guard(tenant_id uuid PRIMARY KEY);
CREATE TABLE identity_authority.accounts (
 tenant_id uuid NOT NULL,
 principal_id uuid NOT NULL CHECK(principal_id <> '00000000-0000-0000-0000-000000000000'),
 enabled boolean NOT NULL DEFAULT true,
 administrator boolean NOT NULL DEFAULT false,
 emergency boolean NOT NULL DEFAULT false,
 auth_epoch bigint NOT NULL DEFAULT 1 CHECK(auth_epoch>0),
 PRIMARY KEY(tenant_id,principal_id)
);
CREATE TABLE identity_authority.local_credentials (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL,
 login_key text NOT NULL CHECK(octet_length(login_key) BETWEEN 1 AND 128 AND login_key=lower(login_key COLLATE "C") AND login_key !~ '[^\x20-\x7e]' AND login_key=btrim(login_key)),
 password_hash text NOT NULL CHECK(octet_length(password_hash) BETWEEN 80 AND 256 AND password_hash ~ '^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{21}[AQgw]\$[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$'),
 PRIMARY KEY(tenant_id,principal_id), UNIQUE(tenant_id,login_key),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts
);
CREATE TABLE identity_authority.memberships (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL, active boolean NOT NULL DEFAULT true,
 epoch bigint NOT NULL DEFAULT 1 CHECK(epoch>0),
 PRIMARY KEY(tenant_id,principal_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts
);
CREATE TABLE identity_authority.platform_administrators (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,principal_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts
);
CREATE TABLE identity_authority.tenant_registry (
 tenant_id uuid NOT NULL,
 business_tenant uuid NOT NULL UNIQUE CHECK(business_tenant<>tenant_id AND business_tenant<>'00000000-0000-0000-0000-000000000000'),
 name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 128 AND name=btrim(name)),
 initial_principal uuid NOT NULL,
 PRIMARY KEY(tenant_id,business_tenant)
);
CREATE TABLE identity_authority.platform_operations (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 kind text NOT NULL CHECK(kind IN ('tenant_created','administrator_added')),
 business_tenant uuid NOT NULL, principal_id uuid NOT NULL,
 created_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp())),
 PRIMARY KEY(tenant_id,operation_id),
 FOREIGN KEY(tenant_id,business_tenant) REFERENCES identity_authority.tenant_registry
);
CREATE TABLE identity_authority.attempts (
 tenant_id uuid NOT NULL, key text NOT NULL CHECK(octet_length(key) BETWEEN 1 AND 300),
 count integer NOT NULL CHECK(count>0), expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,key)
);
CREATE INDEX attempts_expiry ON identity_authority.attempts(tenant_id,expires_at);
CREATE TABLE identity_authority.providers (
 tenant_id uuid NOT NULL REFERENCES identity_authority.guard,
 provider_id uuid NOT NULL CHECK(provider_id <> '00000000-0000-0000-0000-000000000000'),
 config_version bigint NOT NULL CHECK(config_version>0),
 revocation_epoch bigint NOT NULL CHECK(revocation_epoch>0),
 enabled boolean NOT NULL,
 settings jsonb NOT NULL CHECK(jsonb_typeof(settings)='object' AND octet_length(settings::text)<=16384),
 PRIMARY KEY(tenant_id,provider_id),
 assurance_profile bytea NOT NULL CHECK(octet_length(assurance_profile)=32),
 credential_version bigint NOT NULL CHECK(credential_version>0)
);
CREATE TABLE identity_authority.provider_credentials (
 tenant_id uuid NOT NULL, provider_id uuid NOT NULL, credential_version bigint NOT NULL CHECK(credential_version>0),
 sealed jsonb NOT NULL CHECK(jsonb_typeof(sealed)='object' AND octet_length(sealed::text)<=131072),
 PRIMARY KEY(tenant_id,provider_id), FOREIGN KEY(tenant_id,provider_id) REFERENCES identity_authority.providers
);
CREATE TABLE identity_authority.external_identities (
 tenant_id uuid NOT NULL, identity_id uuid NOT NULL, principal_id uuid NOT NULL, provider_id uuid NOT NULL,
 issuer text NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 2048),
 subject text NOT NULL CHECK(octet_length(subject) BETWEEN 1 AND 255),
 PRIMARY KEY(tenant_id,identity_id), UNIQUE(tenant_id,principal_id,identity_id), UNIQUE(tenant_id,provider_id,issuer,subject),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts,
 FOREIGN KEY(tenant_id,provider_id) REFERENCES identity_authority.providers
);
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
 external_identity_id uuid,
 provider_epoch bigint,
 auth_facts jsonb,
 CONSTRAINT session_source CHECK((external_identity_id IS NULL AND provider_epoch IS NULL AND auth_facts IS NULL) OR (external_identity_id IS NOT NULL AND provider_epoch IS NOT NULL AND provider_epoch>0 AND auth_facts IS NOT NULL AND jsonb_typeof(auth_facts)='object' AND octet_length(auth_facts::text)<=32768)),
 FOREIGN KEY(tenant_id,principal_id,external_identity_id) REFERENCES identity_authority.external_identities(tenant_id,principal_id,identity_id),
 PRIMARY KEY(tenant_id,session_id),
 UNIQUE(tenant_id,token_hash), UNIQUE(tenant_id,principal_id,session_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts,
 CONSTRAINT session_lifetime CHECK(auth_time < idle_expires_at AND idle_expires_at <= absolute_expires_at),
 CONSTRAINT session_duration CHECK(absolute_expires_at::numeric-auth_time::numeric IN (14400,28800)),
 CONSTRAINT session_revocation CHECK(revoked_at IS NULL OR revoked_at >= auth_time)
);
CREATE INDEX sessions_principal ON identity_authority.sessions(tenant_id,principal_id,session_id);
CREATE TABLE identity_authority.link_intents (
 tenant_id uuid NOT NULL, intent_id uuid NOT NULL, principal_id uuid NOT NULL, session_id uuid NOT NULL,
 auth_epoch bigint NOT NULL CHECK(auth_epoch>0), membership_epoch bigint NOT NULL CHECK(membership_epoch>0),
 source_identity uuid, source_epoch bigint, source_facts jsonb,
 target_provider uuid NOT NULL, target_version bigint NOT NULL CHECK(target_version>0),
 browser_hash bytea NOT NULL CHECK(octet_length(browser_hash)=32),
 stage smallint NOT NULL CHECK(stage BETWEEN 0 AND 2),
 created_at bigint NOT NULL, expires_at bigint NOT NULL CHECK(expires_at>created_at),
 PRIMARY KEY(tenant_id,intent_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts,
 FOREIGN KEY(tenant_id,session_id) REFERENCES identity_authority.sessions,
 FOREIGN KEY(tenant_id,target_provider) REFERENCES identity_authority.providers,
 FOREIGN KEY(tenant_id,source_identity) REFERENCES identity_authority.external_identities,
 CHECK((source_identity IS NULL AND source_epoch IS NULL AND source_facts IS NULL) OR (source_identity IS NOT NULL AND source_epoch IS NOT NULL AND source_epoch>0 AND source_facts IS NOT NULL))
);
CREATE TABLE identity_authority.oidc_transactions (
 tenant_id uuid NOT NULL, attempt_id bytea NOT NULL CHECK(octet_length(attempt_id)=32),
 provider_id uuid NOT NULL, config_version bigint NOT NULL CHECK(config_version>0),
 state_hash bytea NOT NULL CHECK(octet_length(state_hash)=32), browser_hash bytea NOT NULL CHECK(octet_length(browser_hash)=32),
 purpose smallint NOT NULL CHECK(purpose BETWEEN 0 AND 3),
 authentication_mode smallint NOT NULL CHECK(authentication_mode BETWEEN 0 AND 2),
 nonce text, verifier text, claimed boolean NOT NULL DEFAULT false,
 created_at bigint NOT NULL, expires_at bigint NOT NULL CHECK(expires_at>created_at),
 target_client text NOT NULL CHECK(octet_length(target_client) BETWEEN 1 AND 128),
 return_url text NOT NULL CHECK(octet_length(return_url) BETWEEN 1 AND 2048),
 link_intent uuid, replacement_session uuid,
 cli_binding jsonb CHECK((purpose=3 AND cli_binding IS NOT NULL AND jsonb_typeof(cli_binding)='object' AND octet_length(cli_binding::text)<=2048) OR (purpose<>3 AND cli_binding IS NULL)),
 PRIMARY KEY(tenant_id,attempt_id), UNIQUE(tenant_id,state_hash),
 FOREIGN KEY(tenant_id,provider_id) REFERENCES identity_authority.providers,
 FOREIGN KEY(tenant_id,link_intent) REFERENCES identity_authority.link_intents,
 FOREIGN KEY(tenant_id,replacement_session) REFERENCES identity_authority.sessions,
 CHECK((purpose=1 AND authentication_mode=1) OR (purpose=2 AND authentication_mode=0) OR (purpose=3 AND authentication_mode=0) OR (purpose=0 AND (authentication_mode=0 OR (authentication_mode=2 AND replacement_session IS NOT NULL)))),
 CHECK((purpose IN(0,3) AND link_intent IS NULL) OR (purpose IN(1,2) AND link_intent IS NOT NULL)),
 CHECK((claimed AND nonce IS NULL AND verifier IS NULL) OR (NOT claimed AND octet_length(nonce)=43 AND octet_length(verifier)=43))
);
CREATE INDEX oidc_expiry ON identity_authority.oidc_transactions(tenant_id,expires_at);
CREATE INDEX link_expiry ON identity_authority.link_intents(tenant_id,expires_at);
CREATE TABLE identity_authority.cli_grants (
 tenant_id uuid NOT NULL, code_hash bytea NOT NULL CHECK(octet_length(code_hash)=32),
 binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object' AND octet_length(binding::text)<=2048),
 principal_id uuid NOT NULL, auth_epoch bigint NOT NULL CHECK(auth_epoch>0),membership_epoch bigint NOT NULL CHECK(membership_epoch>0),
 external_identity_id uuid NOT NULL, provider_epoch bigint NOT NULL CHECK(provider_epoch>0),auth_facts jsonb NOT NULL,
 created_at bigint NOT NULL, expires_at bigint NOT NULL CHECK(expires_at>created_at AND expires_at-created_at<=60),
 PRIMARY KEY(tenant_id,code_hash), FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts,
 FOREIGN KEY(tenant_id,external_identity_id) REFERENCES identity_authority.external_identities(tenant_id,identity_id)
);
CREATE TABLE identity_authority.product_subjects (
 tenant_id uuid NOT NULL, client_id text NOT NULL CHECK(octet_length(client_id) BETWEEN 1 AND 256),
 principal_id uuid NOT NULL, subject text NOT NULL CHECK(octet_length(subject)=64),
 PRIMARY KEY(tenant_id,client_id,principal_id), UNIQUE(tenant_id,client_id,subject), UNIQUE(tenant_id,client_id,principal_id,subject),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts
);
CREATE TABLE identity_authority.downstream_grants (
 tenant_id uuid NOT NULL REFERENCES identity_authority.guard, grant_id uuid NOT NULL CHECK(grant_id <> '00000000-0000-0000-0000-000000000000'),
 client_id text NOT NULL CHECK(octet_length(client_id) BETWEEN 1 AND 256), config_version bigint NOT NULL CHECK(config_version>0),
 registration_hash bytea NOT NULL CHECK(octet_length(registration_hash)=32),
 principal_id uuid, session_id uuid, subject text,
 login_hash bytea NOT NULL CHECK(octet_length(login_hash)=32), consent_hash bytea CHECK(octet_length(consent_hash)=32),
 browser_hash bytea NOT NULL CHECK(octet_length(browser_hash)=32),
 hydra_sid text NOT NULL CHECK(octet_length(hydra_sid) BETWEEN 1 AND 512), consent_id text CHECK(octet_length(consent_id) BETWEEN 1 AND 512),
 state smallint NOT NULL CHECK(state BETWEEN 0 AND 5),
 created_at bigint NOT NULL CHECK(created_at>0), expires_at bigint NOT NULL, horizon bigint NOT NULL,
 next_attempt bigint NOT NULL, lease_until bigint NOT NULL DEFAULT 0,
 PRIMARY KEY(tenant_id,grant_id), UNIQUE(tenant_id,login_hash), UNIQUE(tenant_id,consent_hash), UNIQUE(tenant_id,consent_id),
 FOREIGN KEY(tenant_id,session_id) REFERENCES identity_authority.sessions,
 FOREIGN KEY(tenant_id,client_id,principal_id,subject) REFERENCES identity_authority.product_subjects(tenant_id,client_id,principal_id,subject),
 FOREIGN KEY(tenant_id,principal_id,session_id) REFERENCES identity_authority.sessions(tenant_id,principal_id,session_id),
 CHECK((principal_id IS NULL AND session_id IS NULL AND subject IS NULL) OR (principal_id IS NOT NULL AND session_id IS NOT NULL AND subject IS NOT NULL)),
 CHECK(state IN(0,5) OR session_id IS NOT NULL),
 CHECK(state NOT IN(3,4) OR (consent_id IS NOT NULL AND consent_hash IS NOT NULL)),
 CHECK(created_at<expires_at AND expires_at<=horizon), CHECK(next_attempt>=created_at AND lease_until>=0)
);
CREATE INDEX downstream_client ON identity_authority.downstream_grants(tenant_id,client_id);
CREATE INDEX downstream_sweep ON identity_authority.downstream_grants(tenant_id,next_attempt,grant_id);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['cli_grants','provider_credentials','platform_administrators','tenant_registry','platform_operations','guard','local_credentials','accounts','memberships','attempts','sessions','providers','external_identities','link_intents','oidc_transactions','product_subjects','downstream_grants'] LOOP
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
GRANT UPDATE(system_domain) ON identity_authority.deployment TO identity_account_maintenance;
GRANT SELECT,INSERT,UPDATE ON identity_authority.guard TO identity_account_runtime,identity_account_maintenance;
GRANT SELECT,INSERT,UPDATE ON identity_authority.accounts,identity_authority.memberships TO identity_account_runtime;
GRANT SELECT,INSERT ON identity_authority.accounts,identity_authority.memberships TO identity_account_maintenance;
GRANT UPDATE(auth_epoch) ON identity_authority.accounts TO identity_account_maintenance;
GRANT SELECT,INSERT,UPDATE ON identity_authority.local_credentials TO identity_account_runtime;
GRANT SELECT,INSERT ON identity_authority.local_credentials TO identity_account_maintenance;
GRANT UPDATE(password_hash) ON identity_authority.local_credentials TO identity_account_maintenance;
GRANT SELECT,INSERT,UPDATE,DELETE ON identity_authority.attempts TO identity_account_runtime;

GRANT SELECT,INSERT,UPDATE ON identity_authority.sessions TO identity_account_runtime;

GRANT SELECT,INSERT,UPDATE ON identity_authority.providers,identity_authority.external_identities TO identity_account_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON identity_authority.link_intents,identity_authority.oidc_transactions TO identity_account_runtime;

GRANT SELECT,INSERT ON identity_authority.product_subjects TO identity_account_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON identity_authority.downstream_grants TO identity_account_runtime;

GRANT SELECT,INSERT,DELETE ON identity_authority.platform_administrators TO identity_account_runtime;
GRANT SELECT,INSERT ON identity_authority.platform_administrators TO identity_account_maintenance;
GRANT SELECT,INSERT ON identity_authority.tenant_registry,identity_authority.platform_operations TO identity_account_runtime;
CREATE ROLE identity_tenant_registrar NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
GRANT USAGE,CREATE ON SCHEMA identity_authority TO identity_tenant_registrar;
GRANT SELECT ON identity_authority.deployment,identity_authority.tenant_registry TO identity_tenant_registrar;
GRANT SELECT,INSERT,UPDATE ON identity_authority.guard TO identity_tenant_registrar;
GRANT INSERT ON identity_authority.accounts,identity_authority.local_credentials,identity_authority.memberships TO identity_tenant_registrar;

-- The caller holds the system guard, rechecks its actor, and appends the system event in this transaction.
CREATE FUNCTION identity_authority.register_tenant(target uuid, generation bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity_authority AS $$
DECLARE system uuid := nullif(current_setting('rss.tenant_id',true),'')::uuid;
BEGIN
 IF system IS NULL OR system IS DISTINCT FROM (SELECT system_domain FROM identity_authority.deployment)
 OR target=system OR generation<1 OR generation IS DISTINCT FROM nullif(current_setting('rss.execution_epoch',true),'')::bigint
 OR NOT EXISTS(SELECT FROM identity_authority.tenant_registry WHERE tenant_id=system AND business_tenant=target)
 THEN RAISE EXCEPTION 'platform operation rejected'; END IF;
 PERFORM rss_transactional_messaging.check_execution();
 PERFORM set_config('rss.tenant_id',target::text,true);
 INSERT INTO rss_transactional_messaging.tenant_epoch VALUES(target,generation);
 PERFORM rss_transactional_messaging.check_execution();
 INSERT INTO identity_authority.guard VALUES(target);
 PERFORM set_config('rss.tenant_id',system::text,true);
END $$;
ALTER FUNCTION identity_authority.register_tenant(uuid,bigint) OWNER TO identity_tenant_registrar;
CREATE FUNCTION identity_authority.insert_tenant_administrator(target uuid, principal uuid, login text, phc text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity_authority AS $$
DECLARE system uuid := nullif(current_setting('rss.tenant_id',true),'')::uuid;
BEGIN
 IF system IS NULL OR system IS DISTINCT FROM (SELECT system_domain FROM identity_authority.deployment)
 OR target=system OR NOT EXISTS(SELECT FROM identity_authority.tenant_registry WHERE tenant_id=system AND business_tenant=target)
 THEN RAISE EXCEPTION 'platform operation rejected'; END IF;
 PERFORM rss_transactional_messaging.check_execution();
 PERFORM set_config('rss.tenant_id',target::text,true);
 PERFORM rss_transactional_messaging.check_execution();
 PERFORM tenant_id FROM identity_authority.guard WHERE tenant_id=target FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'unregistered tenant'; END IF;
 INSERT INTO identity_authority.accounts(tenant_id,principal_id,administrator) VALUES(target,principal,true);
 INSERT INTO identity_authority.local_credentials VALUES(target,principal,login,phc);
 INSERT INTO identity_authority.memberships(tenant_id,principal_id) VALUES(target,principal);
 PERFORM set_config('rss.tenant_id',system::text,true);
END $$;
ALTER FUNCTION identity_authority.insert_tenant_administrator(uuid,uuid,text,text) OWNER TO identity_tenant_registrar;
REVOKE CREATE ON SCHEMA identity_authority FROM identity_tenant_registrar;
REVOKE ALL ON FUNCTION identity_authority.register_tenant(uuid,bigint),identity_authority.insert_tenant_administrator(uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity_authority.register_tenant(uuid,bigint),identity_authority.insert_tenant_administrator(uuid,uuid,text,text) TO identity_account_runtime;

GRANT SELECT,INSERT,UPDATE ON identity_authority.provider_credentials TO identity_account_runtime;

GRANT SELECT,INSERT,UPDATE,DELETE ON identity_authority.cli_grants TO identity_account_runtime;
