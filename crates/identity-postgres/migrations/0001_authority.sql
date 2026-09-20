-- Fresh schema v11 only. The host installs RSS messaging and admits its tenants separately.
CREATE SCHEMA identity_authority;
CREATE TABLE identity_authority.schema_version(version integer PRIMARY KEY CHECK(version=11));
INSERT INTO identity_authority.schema_version VALUES(11);
CREATE TABLE identity_authority.deployment (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 authority_id uuid NOT NULL CHECK(authority_id <> '00000000-0000-0000-0000-000000000000')
);
CREATE FUNCTION identity_authority.protect_deployment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'immutable authentication instance';
END $$;
CREATE TRIGGER protect_deployment BEFORE UPDATE OR DELETE ON identity_authority.deployment FOR EACH ROW EXECUTE FUNCTION identity_authority.protect_deployment();
CREATE TABLE identity_authority.guard(tenant_id uuid PRIMARY KEY);
CREATE TABLE identity_authority.accounts (
 tenant_id uuid NOT NULL,
 principal_id uuid NOT NULL CHECK(principal_id <> '00000000-0000-0000-0000-000000000000'),
 enabled boolean NOT NULL DEFAULT true,
 auth_epoch bigint NOT NULL DEFAULT 1 CHECK(auth_epoch>0),
 PRIMARY KEY(tenant_id,principal_id)
);
-- Keep composite bounds flat: pg_dump/reparse must preserve structural attestation.
CREATE TABLE identity_authority.local_credentials (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL,
 login_key text NOT NULL CHECK(octet_length(login_key)>=1 AND octet_length(login_key)<=128 AND login_key=lower(login_key COLLATE "C") AND login_key !~ '[^\x20-\x7e]' AND login_key=btrim(login_key)),
 password_hash text NOT NULL CHECK(octet_length(password_hash)>=80 AND octet_length(password_hash)<=256 AND password_hash ~ '^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{21}[AQgw]\$[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$'),
 PRIMARY KEY(tenant_id,principal_id), UNIQUE(tenant_id,login_key),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts
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
 idle_timeout bigint NOT NULL CHECK(idle_timeout>0),
 absolute_timeout bigint NOT NULL CHECK(absolute_timeout>=idle_timeout),
 idle_expires_at bigint NOT NULL,
 absolute_expires_at bigint NOT NULL,
 revoked_at bigint,
 external_identity_id uuid,
 provider_epoch bigint,
 auth_facts jsonb,
 CONSTRAINT session_source CHECK((external_identity_id IS NULL AND provider_epoch IS NULL AND auth_facts IS NULL) OR (external_identity_id IS NOT NULL AND provider_epoch IS NOT NULL AND provider_epoch>0 AND auth_facts IS NOT NULL AND jsonb_typeof(auth_facts)='object' AND octet_length(auth_facts::text)<=32768 AND (auth_facts->'format_version'='3'::jsonb AND jsonb_typeof(auth_facts->'department_snapshot')='object') IS TRUE)),
 FOREIGN KEY(tenant_id,principal_id,external_identity_id) REFERENCES identity_authority.external_identities(tenant_id,principal_id,identity_id),
 PRIMARY KEY(tenant_id,session_id),
 UNIQUE(tenant_id,token_hash), UNIQUE(tenant_id,principal_id,session_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts,
 CONSTRAINT session_lifetime CHECK(auth_time < idle_expires_at AND idle_expires_at <= absolute_expires_at),
 CONSTRAINT session_duration CHECK(absolute_expires_at::numeric-auth_time::numeric=absolute_timeout),
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
 CHECK((source_identity IS NULL AND source_epoch IS NULL AND source_facts IS NULL) OR (source_identity IS NOT NULL AND source_epoch IS NOT NULL AND source_epoch>0 AND source_facts IS NOT NULL AND jsonb_typeof(source_facts)='object' AND octet_length(source_facts::text)<=32768 AND (source_facts->'format_version'='3'::jsonb AND jsonb_typeof(source_facts->'department_snapshot')='object') IS TRUE))
);
CREATE TABLE identity_authority.oidc_transactions (
 tenant_id uuid NOT NULL, attempt_id bytea NOT NULL CHECK(octet_length(attempt_id)=32),
 provider_id uuid NOT NULL, config_version bigint NOT NULL CHECK(config_version>0),
 state_hash bytea NOT NULL CHECK(octet_length(state_hash)=32), browser_hash bytea NOT NULL CHECK(octet_length(browser_hash)=32),
 purpose smallint NOT NULL CHECK(purpose BETWEEN 0 AND 2),
 authentication_mode smallint NOT NULL CHECK(authentication_mode BETWEEN 0 AND 2),
 nonce text, verifier text, claimed boolean NOT NULL DEFAULT false,
 created_at bigint NOT NULL, expires_at bigint NOT NULL CHECK(expires_at>created_at),
 return_url text NOT NULL CHECK(octet_length(return_url) BETWEEN 1 AND 2048),
 link_intent uuid, replacement_session uuid,
 PRIMARY KEY(tenant_id,attempt_id), UNIQUE(tenant_id,state_hash),
 FOREIGN KEY(tenant_id,provider_id) REFERENCES identity_authority.providers,
 FOREIGN KEY(tenant_id,link_intent) REFERENCES identity_authority.link_intents,
 FOREIGN KEY(tenant_id,replacement_session) REFERENCES identity_authority.sessions,
 CHECK((purpose=1 AND authentication_mode=1) OR (purpose=2 AND authentication_mode=0) OR (purpose=0 AND (authentication_mode=0 OR (authentication_mode=2 AND replacement_session IS NOT NULL)))),
 CHECK((purpose=0 AND link_intent IS NULL) OR (purpose IN(1,2) AND link_intent IS NOT NULL)),
 CHECK((claimed AND nonce IS NULL AND verifier IS NULL) OR (NOT claimed AND octet_length(nonce)=43 AND octet_length(verifier)=43))
);
CREATE INDEX oidc_expiry ON identity_authority.oidc_transactions(tenant_id,expires_at);
CREATE INDEX link_expiry ON identity_authority.link_intents(tenant_id,expires_at);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['provider_credentials','guard','local_credentials','accounts','memberships','attempts','sessions','providers','external_identities','link_intents','oidc_transactions'] LOOP
 EXECUTE format('ALTER TABLE identity_authority.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE identity_authority.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON identity_authority.%I USING (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
REVOKE ALL ON SCHEMA identity_authority FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA identity_authority FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA identity_authority FROM PUBLIC;
