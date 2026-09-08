use crate::{
    storage::*,
    transaction::{SecurityEvent, reject},
    *,
};
use access_core::account::SecurityAction;
use access_core::account::{LoginKey, Password, PasswordKdf};
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::PgError;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

async fn grant(
    c: &mut PgConnection,
    key: AccountKey,
    purpose: AuthorizationPurpose,
    digest: [u8; 32],
) -> Result<i64, PgError> {
    let row=sqlx::query("SELECT digest,account_epoch FROM access_authority.authorizations WHERE tenant_id=$1::uuid AND principal_id=$2::uuid AND purpose=$3 AND NOT consumed AND expires_at>clock_timestamp() FOR UPDATE")
        .bind(key.tenant.to_string()).bind(key.principal.as_uuid().to_string()).bind(purpose.label()).fetch_optional(&mut *c).await?;
    let (stored, epoch) = match row {
        Some(r) => (
            r.try_get::<Vec<u8>, _>("digest")?,
            r.try_get::<i64, _>("account_epoch")?,
        ),
        None => (vec![0; 32], -1),
    };
    if !constant_time_eq::constant_time_eq_32(
        &digest,
        stored.as_slice().try_into().map_err(|_| reject())?,
    ) || epoch < 0
    {
        return Err(reject());
    }
    if purpose == AuthorizationPurpose::Recover {
        let account = load(c, key).await?.state;
        if !account.administrator() || account.epoch() != epoch {
            return Err(reject());
        }
    }
    Ok(epoch)
}
async fn consume(
    c: &mut PgConnection,
    key: AccountKey,
    purpose: AuthorizationPurpose,
) -> Result<(), PgError> {
    sqlx::query("UPDATE access_authority.authorizations SET consumed=true WHERE tenant_id=$1::uuid AND principal_id=$2::uuid AND purpose=$3").bind(key.tenant.to_string()).bind(key.principal.as_uuid().to_string()).bind(purpose.label()).execute(c).await?;
    Ok(())
}
impl Authority {
    /// Requires the independent access_authorization_issuer database role, not runtime privileges.
    pub async fn issue_authorization(
        &self,
        key: AccountKey,
        purpose: AuthorizationPurpose,
        deadline: OperationDeadline,
    ) -> Result<IssuedAuthorization, AuthorityError> {
        if self.profile != AuthorityProfile::Issuer {
            return Err(AuthorityError::Rejected);
        }
        let secret = AuthorizationSecret::generate();
        let id = Uuid::new_v4();
        let digest = Sha256::digest(secret.expose()).to_vec();
        self.mutate(key.tenant,deadline,move|tx|Box::pin(async move {
            crate::transaction::connection(tx,move|c|Box::pin(async move {
                if purpose==AuthorizationPurpose::Initialize {
                    let r=sqlx::query("SELECT initialized,bootstrap_tenant::text AS tenant FROM access_authority.deployment FOR UPDATE").fetch_one(&mut *c).await?;
                    if r.try_get::<bool,_>("initialized")? || r.try_get::<Option<String>,_>("tenant")?.is_some_and(|t|t!=key.tenant.to_string()) {return Err(reject().into());}
                    sqlx::query("UPDATE access_authority.deployment SET bootstrap_tenant=$1::uuid").bind(key.tenant.to_string()).execute(&mut *c).await?;
                }
                guard(c,key.tenant).await?;
                let epoch=if purpose==AuthorizationPurpose::Recover {
                    let r=sqlx::query("SELECT auth_epoch FROM access_authority.accounts WHERE tenant_id=$1::uuid AND principal_id=$2::uuid AND administrator").bind(key.tenant.to_string()).bind(key.principal.as_uuid().to_string()).fetch_optional(&mut *c).await?.ok_or_else(reject)?;
                    r.try_get::<i64,_>("auth_epoch")?
                }else{
                    // Initializer identity may be replaced before the single deployment initialization.
                    sqlx::query("DELETE FROM access_authority.authorizations WHERE tenant_id=$1::uuid AND purpose='initialize'").bind(key.tenant.to_string()).execute(&mut *c).await?;
                    0
                };
                sqlx::query("INSERT INTO access_authority.authorizations VALUES($1::uuid,$2::uuid,$3,$4::uuid,$5,$6,clock_timestamp()+interval '15 minutes',false) ON CONFLICT(tenant_id,principal_id,purpose) DO UPDATE SET authorization_id=excluded.authorization_id,digest=excluded.digest,account_epoch=excluded.account_epoch,expires_at=excluded.expires_at,consumed=false")
                    .bind(key.tenant.to_string()).bind(key.principal.as_uuid().to_string()).bind(purpose.label()).bind(id.to_string()).bind(digest).bind(epoch).execute(&mut *c).await?;
                Ok((IssuedAuthorization {secret},SecurityEvent::new(if purpose == AuthorizationPurpose::Initialize { SecurityAction::InitializationAuthorized } else { SecurityAction::RecoveryAuthorized },key,None,epoch)))
            })).await
        })).await
    }

    async fn check_authorization(
        &self,
        key: AccountKey,
        purpose: AuthorizationPurpose,
        secret: &AuthorizationSecret,
        source: &AttemptSource,
        budget: &Budget,
    ) -> Result<(), AuthorityError> {
        self.reserve(
            key.tenant,
            format!("g:{}:{}", purpose.label(), key.principal.as_uuid()),
            source,
            budget.remaining(),
        )
        .await?;
        let digest = Sha256::digest(secret.expose()).into();
        self.read(key.tenant, budget.remaining(), move |tx| {
            Box::pin(async move {
                crate::transaction::connection(tx, move |c| {
                    Box::pin(async move {
                        guard(c, key.tenant).await?;
                        grant(c, key, purpose, digest).await?;
                        Ok(())
                    })
                })
                .await
            })
        })
        .await
    }

    pub async fn initialize(
        &self,
        key: AccountKey,
        login: LoginKey,
        password: Password,
        secret: AuthorizationSecret,
        source: AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.require_runtime()?;
        let budget = Budget::new(deadline)?;
        self.check_authorization(
            key,
            AuthorizationPurpose::Initialize,
            &secret,
            &source,
            &budget,
        )
        .await?;
        let hash = budget.password(PasswordKdf::new().hash(password)).await?;
        self.mutate(key.tenant,budget.remaining(),move|tx|Box::pin(async move {
            crate::transaction::connection(tx,move|c|Box::pin(async move {
                let r=sqlx::query("SELECT initialized,bootstrap_tenant::text AS tenant FROM access_authority.deployment FOR UPDATE").fetch_one(&mut *c).await?;
                if r.try_get::<bool,_>("initialized")? || r.try_get::<Option<String>,_>("tenant")?.as_deref()!=Some(key.tenant.to_string().as_str()) {return Err(reject().into());}
                guard(c,key.tenant).await?;
                grant(c,key,AuthorizationPurpose::Initialize,Sha256::digest(secret.expose()).into()).await?;
                insert_account(c,key,login.as_str(),hash.as_str(),true,false).await?;
                consume(c,key,AuthorizationPurpose::Initialize).await?;
                sqlx::query("UPDATE access_authority.deployment SET initialized=true").execute(&mut *c).await?;
                let state=load(c,key).await?.state;
                Ok((state,SecurityEvent::account(SecurityAction::Initialized,state,None)))
            })).await
        })).await
    }

    pub async fn recover_administrator(
        &self,
        key: AccountKey,
        password: Password,
        secret: AuthorizationSecret,
        source: AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.require_runtime()?;
        let budget = Budget::new(deadline)?;
        self.check_authorization(
            key,
            AuthorizationPurpose::Recover,
            &secret,
            &source,
            &budget,
        )
        .await?;
        let hash = budget.password(PasswordKdf::new().hash(password)).await?;
        self.mutate(key.tenant,budget.remaining(),move|tx|Box::pin(async move {
            crate::transaction::connection(tx,move|c|Box::pin(async move {
                guard(c,key.tenant).await?;
                grant(c,key,AuthorizationPurpose::Recover,Sha256::digest(secret.expose()).into()).await?;
                let old=load(c,key).await?.state;
                let (next,action)=old.recover()?;
                sqlx::query("UPDATE access_authority.accounts SET password_hash=$3,auth_epoch=$4,credential_version=$5 WHERE tenant_id=$1::uuid AND principal_id=$2::uuid")
                    .bind(key.tenant.to_string()).bind(key.principal.as_uuid().to_string()).bind(hash.as_str()).bind(next.epoch()).bind(next.credential_version()).execute(&mut *c).await?;
                consume(c,key,AuthorizationPurpose::Recover).await?;
                let state=load(c,key).await?.state;
                Ok((state,SecurityEvent::account(action,state,None)))
            })).await
        })).await
    }
}
