-- Fresh schema v17 only. The host installs RSS messaging and admits its tenants separately.
CREATE SCHEMA identity_authority;
CREATE TABLE identity_authority.schema_version(version integer PRIMARY KEY CHECK(version=17));
INSERT INTO identity_authority.schema_version VALUES(17);
CREATE TABLE identity_authority.deployment (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 authority_id uuid NOT NULL CHECK(authority_id <> '00000000-0000-0000-0000-000000000000')
);
CREATE FUNCTION identity_authority.protect_deployment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'immutable authentication instance';
END $$;
CREATE TRIGGER protect_deployment BEFORE UPDATE OR DELETE ON identity_authority.deployment FOR EACH ROW EXECUTE FUNCTION identity_authority.protect_deployment();
CREATE TABLE identity_authority.guard(tenant_id uuid PRIMARY KEY, profile_sequence bigint NOT NULL DEFAULT 0 CHECK(profile_sequence>=0), personnel_revision bigint NOT NULL DEFAULT 0 CHECK(personnel_revision>=0));
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
CREATE TABLE identity_authority.password_attempts (
 tenant_id uuid NOT NULL,
 login_digest bytea NOT NULL CHECK(octet_length(login_digest)=32),
 failures integer NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 5),
 window_until timestamptz,
 claim_token uuid CHECK(claim_token <> '00000000-0000-0000-0000-000000000000'),
 claim_until timestamptz,
 PRIMARY KEY(tenant_id,login_digest),
 CHECK((failures=0) = (window_until IS NULL)),
 CHECK((claim_token IS NULL) = (claim_until IS NULL))
);
CREATE INDEX password_attempts_expiry ON identity_authority.password_attempts(tenant_id,window_until,claim_until);
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
 subject text NOT NULL CHECK(octet_length(subject)>=6 AND octet_length(subject)<=260 AND (subject LIKE 'oidc:%' OR subject ~ '^entra:[0-9a-f-]{36}:[0-9a-f-]{36}$')),
 PRIMARY KEY(tenant_id,identity_id), UNIQUE(tenant_id,principal_id,identity_id), UNIQUE(tenant_id,provider_id,issuer,subject),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts,
 FOREIGN KEY(tenant_id,provider_id) REFERENCES identity_authority.providers
);
CREATE TABLE identity_authority.sessions (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL,
 facts_sequence bigint CHECK(facts_sequence>0),
 session_id uuid NOT NULL CHECK(session_id <> '00000000-0000-0000-0000-000000000000'),
 authentication_source text NOT NULL CHECK(authentication_source IN ('local_password','oidc','platform')),
 local_authenticated_at bigint,
 platform_authentication jsonb,
 credential_kind text NOT NULL CHECK(credential_kind IN ('cookie','bearer')),
 token_hash bytea NOT NULL CHECK(octet_length(token_hash)=32),
 auth_epoch bigint NOT NULL CHECK(auth_epoch>0),
 membership_epoch bigint NOT NULL CHECK(membership_epoch>0),
 issued_at bigint NOT NULL CHECK(issued_at>0),
 idle_timeout bigint NOT NULL CHECK(idle_timeout>0),
 absolute_timeout bigint NOT NULL CHECK(absolute_timeout>=idle_timeout),
 idle_expires_at bigint NOT NULL,
 absolute_expires_at bigint NOT NULL,
 revoked_at bigint,
 profile_source text,
 profile_snapshot uuid,
 CHECK ((profile_source IS NULL) = (profile_snapshot IS NULL)),
 external_identity_id uuid,
 provider_epoch bigint,
 auth_facts jsonb,
 CONSTRAINT session_presentation CHECK(credential_kind='cookie' OR authentication_source='local_password'),
 CONSTRAINT authentication_kind CHECK (((authentication_source='local_password' AND local_authenticated_at>0 AND local_authenticated_at<=issued_at AND platform_authentication IS NULL AND external_identity_id IS NULL)
 OR (authentication_source='oidc' AND local_authenticated_at IS NULL AND platform_authentication IS NULL AND external_identity_id IS NOT NULL)
 OR (authentication_source='platform' AND local_authenticated_at IS NULL AND external_identity_id IS NULL AND jsonb_typeof(platform_authentication)='object' AND octet_length(platform_authentication::text)<=4096)) IS TRUE),
 CONSTRAINT session_source CHECK((external_identity_id IS NULL AND provider_epoch IS NULL AND auth_facts IS NULL AND facts_sequence IS NULL) OR (external_identity_id IS NOT NULL AND facts_sequence IS NOT NULL AND provider_epoch IS NOT NULL AND provider_epoch>0 AND auth_facts IS NOT NULL AND jsonb_typeof(auth_facts)='object' AND octet_length(auth_facts::text)<=32768 AND (auth_facts->'format_version'='3'::jsonb AND jsonb_typeof(auth_facts->'department_snapshot')='object') IS TRUE)),
 FOREIGN KEY(tenant_id,principal_id,external_identity_id) REFERENCES identity_authority.external_identities(tenant_id,principal_id,identity_id),
 PRIMARY KEY(tenant_id,session_id),
 UNIQUE(tenant_id,token_hash), UNIQUE(tenant_id,principal_id,session_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts,
 CONSTRAINT session_lifetime CHECK(issued_at < idle_expires_at AND idle_expires_at <= absolute_expires_at),
 CONSTRAINT session_duration CHECK(absolute_expires_at::numeric-issued_at::numeric=absolute_timeout),
 CONSTRAINT session_revocation CHECK(revoked_at IS NULL OR revoked_at >= issued_at)
);
CREATE INDEX sessions_accepted_facts ON identity_authority.sessions(tenant_id,principal_id,facts_sequence DESC) WHERE external_identity_id IS NOT NULL;
CREATE INDEX sessions_principal ON identity_authority.sessions(tenant_id,principal_id,session_id);
CREATE TABLE identity_authority.link_intents (
 tenant_id uuid NOT NULL, intent_id uuid NOT NULL, principal_id uuid NOT NULL, session_id uuid NOT NULL,
 auth_epoch bigint NOT NULL CHECK(auth_epoch>0), membership_epoch bigint NOT NULL CHECK(membership_epoch>0),
 source_identity uuid, source_epoch bigint, source_facts jsonb, source_facts_sequence bigint CHECK(source_facts_sequence>0), local_authenticated_at bigint,
 CHECK (((source_identity IS NULL AND local_authenticated_at>0) OR (source_identity IS NOT NULL AND local_authenticated_at IS NULL)) IS TRUE),
 target_provider uuid NOT NULL, target_version bigint NOT NULL CHECK(target_version>0),
 browser_hash bytea NOT NULL CHECK(octet_length(browser_hash)=32),
 stage smallint NOT NULL CHECK(stage BETWEEN 0 AND 2),
 created_at bigint NOT NULL, expires_at bigint NOT NULL CHECK(expires_at>created_at),
 PRIMARY KEY(tenant_id,intent_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts,
 FOREIGN KEY(tenant_id,session_id) REFERENCES identity_authority.sessions,
 FOREIGN KEY(tenant_id,target_provider) REFERENCES identity_authority.providers,
 FOREIGN KEY(tenant_id,source_identity) REFERENCES identity_authority.external_identities,
 CHECK((source_identity IS NULL AND source_epoch IS NULL AND source_facts IS NULL AND source_facts_sequence IS NULL) OR (source_identity IS NOT NULL AND source_facts_sequence IS NOT NULL AND source_epoch IS NOT NULL AND source_epoch>0 AND source_facts IS NOT NULL AND jsonb_typeof(source_facts)='object' AND octet_length(source_facts::text)<=32768 AND (source_facts->'format_version'='3'::jsonb AND jsonb_typeof(source_facts->'department_snapshot')='object') IS TRUE))
);
CREATE TABLE identity_authority.oidc_transactions (
 operation_context jsonb,
 tenant_id uuid NOT NULL, attempt_id bytea NOT NULL CHECK(octet_length(attempt_id)=32),
 provider_id uuid NOT NULL, config_version bigint NOT NULL CHECK(config_version>0),
 state_hash bytea NOT NULL CHECK(octet_length(state_hash)=32), browser_hash bytea NOT NULL CHECK(octet_length(browser_hash)=32),
 profile_sequence bigint NOT NULL CHECK(profile_sequence>0),
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
CREATE TABLE identity_authority.platform_challenges (
 purpose jsonb NOT NULL CHECK(jsonb_typeof(purpose)='object' AND octet_length(purpose::text)<=512),
 target jsonb CHECK(target IS NULL OR (jsonb_typeof(target)='object' AND octet_length(target::text)<=8192)),
 tenant_id uuid NOT NULL, challenge_id uuid NOT NULL, principal_id uuid NOT NULL,
 binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object' AND octet_length(binding::text)<=4096),
 audience text NOT NULL CHECK(octet_length(audience) BETWEEN 1 AND 256),
 nonce_hash bytea NOT NULL CHECK(octet_length(nonce_hash)=32), browser_hash bytea NOT NULL CHECK(octet_length(browser_hash)=32),
 auth_epoch bigint NOT NULL CHECK(auth_epoch>0), membership_epoch bigint NOT NULL CHECK(membership_epoch>0),
 created_at bigint NOT NULL CHECK(created_at>0), expires_at bigint NOT NULL CHECK(expires_at>created_at AND expires_at-created_at<=120),
 profile_sequence bigint NOT NULL CHECK(profile_sequence>0),
 PRIMARY KEY(tenant_id,challenge_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE
);
CREATE INDEX platform_challenge_expiry ON identity_authority.platform_challenges(tenant_id,expires_at);
CREATE TABLE identity_authority.local_profiles (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 value jsonb CHECK(value IS NULL OR (jsonb_typeof(value)='object' AND octet_length(value::text)<=98304)),
 PRIMARY KEY(tenant_id,principal_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE
);
CREATE TABLE identity_authority.profile_observations (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL, source text NOT NULL,
 provider_id uuid, config_version bigint, source_epoch bigint, source_revision bigint,
 snapshot_id uuid NOT NULL, sequence bigint NOT NULL CHECK(sequence>0),
 observed_at bigint NOT NULL CHECK(observed_at>0), collected_at bigint NOT NULL CHECK(collected_at>0),
 expires_at bigint NOT NULL CHECK(expires_at>observed_at AND expires_at-observed_at<=86400),
 value jsonb NOT NULL CHECK(jsonb_typeof(value)='object' AND octet_length(value::text)<=98304),
 CHECK (((source='local' AND provider_id IS NULL AND config_version IS NULL AND source_epoch IS NULL)
 OR (provider_id IS NOT NULL AND source=provider_id::text AND config_version>0 AND source_epoch>0 AND source_revision IS NULL)) IS TRUE),
 PRIMARY KEY(tenant_id,principal_id,source),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,provider_id) REFERENCES identity_authority.providers ON DELETE CASCADE
);
CREATE TABLE identity_authority.profile_operations (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, principal_id uuid NOT NULL, actor uuid NOT NULL,
 digest bytea NOT NULL CHECK(octet_length(digest)=32), revision bigint NOT NULL CHECK(revision>0),
 PRIMARY KEY(tenant_id,operation_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE
);
CREATE TABLE identity_authority.webauthn_rp (
 tenant_id uuid NOT NULL, rp text NOT NULL CHECK(octet_length(rp) BETWEEN 1 AND 253),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32), generation bigint NOT NULL CHECK(generation>0),
 PRIMARY KEY(tenant_id,rp)
);
CREATE TABLE identity_authority.webauthn_accounts (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL, user_handle uuid NOT NULL DEFAULT gen_random_uuid(),
 enrolled boolean NOT NULL DEFAULT false, epoch bigint NOT NULL DEFAULT 1 CHECK(epoch>0),
 PRIMARY KEY(tenant_id,principal_id), UNIQUE(user_handle),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE
);
CREATE TABLE identity_authority.webauthn_credentials (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL, id uuid NOT NULL,
 rp text NOT NULL CHECK(octet_length(rp)<=253), rp_config bytea NOT NULL CHECK(octet_length(rp_config)=32),
 credential_hash bytea NOT NULL CHECK(octet_length(credential_hash)=32),
 value jsonb NOT NULL CHECK(jsonb_typeof(value)='object' AND octet_length(value::text)<=16384),
 label text NOT NULL CHECK(octet_length(label) BETWEEN 1 AND 128),
 epoch bigint NOT NULL DEFAULT 1 CHECK(epoch>0), version bigint NOT NULL DEFAULT 1 CHECK(version>0), revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id), UNIQUE(rp,credential_hash),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE
);
CREATE TABLE identity_authority.webauthn_ceremonies (
 tenant_id uuid NOT NULL, id uuid NOT NULL, principal_id uuid NOT NULL, session_id uuid NOT NULL,
 auth_epoch bigint NOT NULL CHECK(auth_epoch>0), membership_epoch bigint NOT NULL CHECK(membership_epoch>0), credential_epoch bigint NOT NULL CHECK(credential_epoch>0),
 rp_config bytea NOT NULL CHECK(octet_length(rp_config)=32), state jsonb NOT NULL CHECK(jsonb_typeof(state)='object' AND octet_length(state::text)<=131072),
 created_at bigint NOT NULL CHECK(created_at>0), expires_at bigint NOT NULL CHECK(expires_at>created_at AND expires_at-created_at<=120),
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE
);
CREATE TABLE identity_authority.step_up_grants (
 tenant_id uuid NOT NULL, token_hash bytea NOT NULL CHECK(octet_length(token_hash)=32), principal_id uuid NOT NULL, session_id uuid NOT NULL,
 auth_epoch bigint NOT NULL CHECK(auth_epoch>0), membership_epoch bigint NOT NULL CHECK(membership_epoch>0),
 context jsonb NOT NULL CHECK(jsonb_typeof(context)='object' AND octet_length(context::text)<=2048),
 source jsonb NOT NULL CHECK(jsonb_typeof(source)='object' AND octet_length(source::text)<=2048),
 authenticated_at bigint NOT NULL CHECK(authenticated_at>0), expires_at bigint NOT NULL CHECK(expires_at>authenticated_at AND expires_at-authenticated_at<=300),
 PRIMARY KEY(tenant_id,token_hash), FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE
);
CREATE INDEX webauthn_ceremony_expiry ON identity_authority.webauthn_ceremonies(tenant_id,expires_at);
CREATE INDEX step_up_subject ON identity_authority.step_up_grants(tenant_id,principal_id);
CREATE INDEX webauthn_ceremony_subject ON identity_authority.webauthn_ceremonies(tenant_id,principal_id);
CREATE INDEX step_up_expiry ON identity_authority.step_up_grants(tenant_id,expires_at);
CREATE INDEX webauthn_account_credentials ON identity_authority.webauthn_credentials(tenant_id,principal_id);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['webauthn_rp','webauthn_accounts','webauthn_credentials','webauthn_ceremonies','step_up_grants','platform_challenges','local_profiles','profile_observations','profile_operations','provider_credentials','guard','local_credentials','accounts','memberships','password_attempts','attempts','sessions','providers','external_identities','link_intents','oidc_transactions'] LOOP
 EXECUTE format('ALTER TABLE identity_authority.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE identity_authority.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON identity_authority.%I USING (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
REVOKE ALL ON SCHEMA identity_authority FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA identity_authority FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA identity_authority FROM PUBLIC;

-- Cursor generation follows every personnel/session-visible mutation, including maintenance.
CREATE FUNCTION identity_authority.advance_personnel_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE identity_authority.guard SET personnel_revision=personnel_revision+1 WHERE tenant_id=COALESCE(NEW.tenant_id,OLD.tenant_id);
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['accounts','memberships','local_credentials','providers','external_identities','profile_observations','local_profiles'] LOOP
 EXECUTE format('CREATE TRIGGER personnel_revision AFTER INSERT OR UPDATE OR DELETE ON identity_authority.%I FOR EACH ROW EXECUTE FUNCTION identity_authority.advance_personnel_revision()',t);
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION identity_authority.advance_personnel_revision() FROM PUBLIC;
CREATE INDEX personnel_observation_expiry ON identity_authority.profile_observations(tenant_id,expires_at);
CREATE INDEX personnel_observation_time ON identity_authority.profile_observations(tenant_id,observed_at);

CREATE TRIGGER personnel_revision AFTER INSERT OR DELETE OR UPDATE OF principal_id,authentication_source,local_authenticated_at,platform_authentication,credential_kind,auth_epoch,membership_epoch,absolute_expires_at,revoked_at,external_identity_id,provider_epoch,auth_facts ON identity_authority.sessions FOR EACH ROW EXECUTE FUNCTION identity_authority.advance_personnel_revision();

CREATE INDEX personnel_session_idle ON identity_authority.sessions(tenant_id,idle_expires_at) WHERE revoked_at IS NULL;
CREATE INDEX personnel_session_absolute ON identity_authority.sessions(tenant_id,absolute_expires_at) WHERE revoked_at IS NULL;
