//! Human CLI login uses one short-lived grant and the existing OIDC transaction owner.
use crate::{
    federation_storage as db,
    storage::*,
    transaction::{MutationError, corrupt, reject},
    *,
};
use rss_identity_contracts::cli::CliLoginBinding;
use rss_identity_core::{account::AccountKey, federation::*};
use rss_transactional_messaging::policy::OperationDeadline;
use sqlx::Row;
use zeroize::Zeroizing;
impl Federation {
    pub async fn begin_cli_login(
        &self,
        provider: ProviderId,
        binding: CliLoginBinding,
        browser: String,
        source: AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<FederatedRedirect, AuthorityError> {
        let request = LoginRequest {
            tenant: self.authority.system_domain(),
            provider,
            browser,
            client: "identity-platform".into(),
            target: String::new(),
            replacement: None,
            source,
        };
        self.begin_authentication(
            request,
            rss_identity_core::assurance::AuthenticationMode::Login,
            Some(binding),
            deadline,
        )
        .await
    }
}
pub(crate) async fn grant(
    c: &mut sqlx::PgConnection,
    key: AccountKey,
    state: rss_identity_core::account::AccountState,
    binding: CliLoginBinding,
    origin: db::Origin,
    now: i64,
) -> Result<String, MutationError> {
    if !crate::platform::platform_role(c, key).await? {
        return Err(rss_identity_core::platform::PlatformError::Forbidden.into());
    }
    sqlx::query("DELETE FROM identity_authority.cli_grants WHERE (tenant_id,code_hash) IN (SELECT tenant_id,code_hash FROM identity_authority.cli_grants WHERE tenant_id=$1::uuid AND expires_at<=$2 LIMIT 128)").bind(key.tenant.to_string()).bind(now).execute(&mut *c).await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.cli_grants WHERE tenant_id=$1::uuid",
    )
    .bind(key.tenant.to_string())
    .fetch_one(&mut *c)
    .await?;
    if count >= 10000 {
        return Err(FederationError::Unavailable.into());
    }
    let code = random_secret()?;
    sqlx::query("INSERT INTO identity_authority.cli_grants(tenant_id,code_hash,binding,principal_id,auth_epoch,membership_epoch,external_identity_id,provider_epoch,auth_facts,created_at,expires_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(key.tenant.to_string()).bind(digest(&code).as_slice()).bind(serde_json::to_value(&binding).map_err(|_|corrupt())?).bind(key.principal.as_uuid()).bind(state.epoch()).bind(state.membership_epoch()).bind(origin.identity).bind(origin.epoch).bind(origin.facts).bind(now).bind(now+60).execute(c).await?;
    Ok(binding
        .result_url("code", &code)
        .map_err(|_| FederationError::Configuration)?)
}
impl Authority {
    pub async fn exchange_cli_login(
        &self,
        code: Zeroizing<String>,
        verifier: Zeroizing<String>,
        redirect_uri: String,
        source: AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<IssuedSession, AuthorityError> {
        self.require_runtime()?;
        if code.len() != 43 {
            return Err(AuthorityError::Rejected);
        }
        let budget = Budget::new(deadline)?;
        let system = self.system_domain;
        self.reserve_source(system, &source, budget.remaining())
            .await?;
        self.mutate(system,budget.remaining(),move|tx|Box::pin(async move{
            transaction::connection(tx,move|c|Box::pin(async move{
                lock_guard(c,system).await?;
                let r=sqlx::query("SELECT * FROM identity_authority.cli_grants WHERE tenant_id=$1::uuid AND code_hash=$2 FOR UPDATE").bind(system.to_string()).bind(digest(&code).as_slice()).fetch_optional(&mut *c).await?.ok_or_else(reject)?;
                let binding:CliLoginBinding=serde_json::from_value(r.try_get("binding")?).map_err(|_|corrupt())?;
                let now=session_storage::now(c).await?;
                if !binding.verifies(&verifier,&redirect_uri) || now<r.try_get::<i64,_>("created_at")? || now>=r.try_get::<i64,_>("expires_at")?{return Err(reject().into());}
                let key=AccountKey{tenant:system,principal:principal(&r.try_get::<uuid::Uuid,_>("principal_id")?.to_string())?};
                let state=load(c,key).await?.state;
                if !state.active() || state.epoch()!=r.try_get::<i64,_>("auth_epoch")? || state.membership_epoch()!=r.try_get::<i64,_>("membership_epoch")? || !crate::platform::platform_role(c,key).await?{return Err(reject().into());}
                let origin=db::Origin{identity:r.try_get("external_identity_id")?,epoch:r.try_get("provider_epoch")?,facts:r.try_get("auth_facts")?};
                db::check_origin(c,system,&origin).await?;
                sqlx::query("DELETE FROM identity_authority.cli_grants WHERE tenant_id=$1::uuid AND code_hash=$2").bind(system.to_string()).bind(digest(&code).as_slice()).execute(&mut *c).await?;
                sessions::insert(c,state,None,Some(origin),now).await
            })).await
        })).await
    }
}
