use crate::{
    federation::{Action, event},
    federation_login::{check_actor, check_browser},
    federation_storage as db,
    storage::*,
    transaction::{corrupt, reject},
    *,
};
use rss_identity_core::assurance::AuthenticationMode;
use rss_identity_core::{PrincipalId, SessionId, account::LoginKey, federation::*};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use sqlx::Row;
use uuid::Uuid;
pub(crate) struct Intent {
    pub browser: Vec<u8>,
    pub id: Uuid,
    pub principal: PrincipalId,
    pub session: SessionId,
    pub epoch: i64,
    pub member_epoch: i64,
    pub origin: Option<db::Origin>,
    pub target: ProviderId,
    pub version: i64,
    pub stage: LinkStage,
    pub created: i64,
    pub expiry: i64,
}
pub(crate) async fn intent(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> Result<Intent, rss_transactional_messaging_postgres::PgError> {
    let r = sqlx::query(concat!(
        "SELECT * FROM identity_authority.link_intents WHERE tenant_id=$1::uuid AND inten",
        "t_id=$2 FOR UPDATE"
    ))
    .bind(tenant.to_string())
    .bind(id)
    .fetch_optional(c)
    .await?
    .ok_or_else(reject)?;
    let origin = r
        .try_get::<Option<Uuid>, _>("source_identity")?
        .map(|identity| {
            Ok::<_, rss_transactional_messaging_postgres::PgError>(db::Origin {
                identity,
                epoch: r.try_get("source_epoch")?,
                facts: crate::auth_facts::AuthenticationFacts::decode(r.try_get("source_facts")?)?,
            })
        })
        .transpose()?;
    Ok(Intent {
        browser: r.try_get("browser_hash")?,
        id,
        principal: PrincipalId::parse(&r.try_get::<Uuid, _>("principal_id")?.to_string())
            .map_err(|_| corrupt())?,
        session: SessionId::parse(&r.try_get::<Uuid, _>("session_id")?.to_string())
            .map_err(|_| corrupt())?,
        epoch: r.try_get("auth_epoch")?,
        member_epoch: r.try_get("membership_epoch")?,
        origin,
        target: ProviderId::parse(&r.try_get::<Uuid, _>("target_provider")?.to_string())
            .map_err(|_| corrupt())?,
        version: r.try_get("target_version")?,
        stage: LinkStage::restore(r.try_get("stage")?)?,
        created: r.try_get("created_at")?,
        expiry: r.try_get("expires_at")?,
    })
}
impl Federation {
    pub async fn begin_link(
        &self,
        request: LinkRequest,
        deadline: OperationDeadline,
    ) -> Result<FederatedRedirect, AuthorityError> {
        let LinkRequest {
            actor,
            target_provider,
            password,
            browser,
            client,
            target,
            source,
        } = request;
        check_browser(&browser)?;
        let tenant = actor.key.tenant;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        let return_url = self.target(&client, &target)?;
        let (actor,account,origin,login)=self.authority.read_sql(tenant,budget.remaining(),move |c| { Box::pin(async move {
                    let loaded = session_storage::recheck(c, &actor).await?;
                    let origin = db::origin(c, tenant, actor.view.id).await?;
                    let login: Option<String> = sqlx::query_scalar(concat!(
                        "SELECT login_key FROM identity_authority.local_credentials WHERE tenant_id=$1::u",
                        "uid AND principal_id=$2::uuid"
                    ))
                    .bind(tenant.to_string())
                    .bind(actor.key.principal.as_uuid().to_string())
                    .fetch_optional(c)
                    .await?;
                    Ok((actor, loaded.state, origin, login))
                }) }).await?;
        let candidate = if let Some(login) = login {
            let candidate = self
                .authority
                .verify_password(
                    tenant,
                    LoginKey::parse(&login).map_err(|_| AuthorityError::Rejected)?,
                    password.ok_or(AuthorityError::Rejected)?,
                    source,
                    budget.remaining(),
                )
                .await?;
            if candidate.state.key() != account.key() {
                return Err(AuthorityError::Rejected);
            }
            Some(candidate)
        } else {
            if password.is_some() {
                return Err(AuthorityError::Rejected);
            }
            self.authority
                .reserve(
                    tenant,
                    format!("link:{}", actor.key.principal.as_uuid()),
                    &source,
                    budget.remaining(),
                )
                .await?;
            None
        };
        let target =
            db::read_provider(&self.authority, tenant, target_provider, budget.remaining()).await?;
        if !target.enabled {
            return Err(AuthorityError::Rejected);
        }
        let (provider, purpose) = if candidate.is_some() {
            (target.clone(), Purpose::Link)
        } else {
            let origin = origin.as_ref().ok_or(AuthorityError::Rejected)?.clone();
            let id = self
                .authority
                .read_sql(tenant, budget.remaining(), move |c| {
                    Box::pin(async move { Ok(db::identity(c, tenant, origin.identity).await?.0) })
                })
                .await?;
            (
                db::read_provider(&self.authority, tenant, id, budget.remaining()).await?,
                Purpose::Reauthenticate,
            )
        };
        let state = self.signer.issue(tenant, purpose)?;
        let locator = self.signer.verify(&state)?;
        let material = ProtocolMaterial::new(state)?;
        self.check_assurance_profile(tenant, &provider)?;
        let credentials = self
            .authority
            .provider_credentials(
                tenant,
                provider.id,
                provider.credential_version,
                budget.remaining(),
            )
            .await?;
        let url = self
            .upstream(
                &budget,
                self.oidc.prepare(
                    tenant,
                    &provider.settings,
                    &credentials,
                    &material,
                    if purpose == Purpose::Reauthenticate {
                        AuthenticationMode::Reauthenticate
                    } else {
                        AuthenticationMode::Login
                    },
                ),
            )
            .await?;
        self.authority.read_sql(tenant,budget.remaining(),move |c| { Box::pin(async move {
                    let loaded = session_storage::recheck(c, &actor).await?;
                    if !loaded.state.matches_verification(account) {
                        return Err(reject().into());
                    }
                    let target_now = db::provider(c, tenant, target.id).await?;
                    db::exact(&target_now, target.version)?;
                    let origin = if let Some(candidate) = candidate {
                        current(c, &candidate, false).await?;
                        None
                    } else {
                        origin
                    };
                    let now = session_storage::now(c).await?;
                    let id = Uuid::new_v4();
                    let expiry = now + 300;
                    sqlx::query(concat!(
                        "INSERT INTO identity_authority.link_intents(tenant_id,intent_id,principal_id,session_id,auth_epoch,membership_epoch,source_identity,source_epoch,source_facts,target_provider,target_version,browser_hash,stage,created_at,expires_at) VALUES($1::uuid,$2,$3,$4::uuid,$5,$6",
                        ",$7,$8,$9,$10::uuid,$11,$12,$13,$14,$15)"
                    ))
                    .bind(tenant.to_string())
                    .bind(id)
                    .bind(account.key().principal.as_uuid())
                    .bind(actor.view.id.to_string())
                    .bind(account.epoch())
                    .bind(account.membership_epoch())
                    .bind(origin.as_ref().map(|o| o.identity))
                    .bind(origin.as_ref().map(|o| o.epoch))
                    .bind(match &origin { Some(o) => Some(o.facts.encode(c).await?), None => None })
                    .bind(target.id.to_string())
                    .bind(target.version)
                    .bind(digest(&browser).as_slice())
                    .bind(if purpose == Purpose::Link {
                        LinkStage::TargetReady.code()
                    } else {
                        LinkStage::ReauthenticationRequired.code()
                    })
                    .bind(now)
                    .bind(expiry)
                    .execute(&mut *c)
                    .await?;
                    db::insert_attempt(
                        c,
                        db::NewAttempt {
                            cli: None,
                            mode: if purpose == Purpose::Reauthenticate { AuthenticationMode::Reauthenticate } else { AuthenticationMode::Login },
                            locator,
                            material,
                            provider,
                            browser,
                            client,
                            return_url,
                            link: Some(id),
                            replacement: None,
                            expiry: Some(expiry),
                        },
                    )
                    .await
                }) }).await?;
        Ok(FederatedRedirect { url })
    }
    pub(crate) async fn finish_reauthentication(
        &self,
        input: Reauthentication,
        budget: &Budget,
    ) -> Result<FederatedOutcome, AuthorityError> {
        let Reauthentication {
            state,
            browser,
            session,
            old,
            source,
            claims,
        } = input;
        let locator = self.signer.verify(&state)?;
        let tenant = locator.tenant();
        let intent_id = old.link.ok_or(AuthorityError::Rejected)?;
        let target = self
            .authority
            .read_sql(tenant, budget.remaining(), move |c| {
                Box::pin(async move {
                    let i = intent(c, tenant, intent_id).await?;
                    let target = db::provider(c, tenant, i.target).await?;
                    db::exact(&target, i.version)?;
                    Ok(target)
                })
            })
            .await?;
        let new_state = self.signer.issue(tenant, Purpose::Link)?;
        let new_locator = self.signer.verify(&new_state)?;
        let material = ProtocolMaterial::new(new_state)?;
        self.check_assurance_profile(tenant, &target)?;
        let credentials = self
            .authority
            .provider_credentials(
                tenant,
                target.id,
                target.credential_version,
                budget.remaining(),
            )
            .await?;
        let url = self
            .upstream(
                budget,
                self.oidc.prepare(
                    tenant,
                    &target.settings,
                    &credentials,
                    &material,
                    AuthenticationMode::Login,
                ),
            )
            .await?;
        let group_policy = self.group_policy;
        self.authority
            .write_sql(tenant, budget.remaining(), move |c| {
                Box::pin(async move {
                    lock_guard(c, tenant).await?;
                    let (attempt, _) = db::attempt(c, &locator, &state, &browser, true).await?;
                    let current_source = db::provider(c, tenant, source.id).await?;
                    db::exact(&current_source, source.version)?;
                    check_actor(c, tenant, &attempt, session).await?;
                    let i = intent(c, tenant, intent_id).await?;
                    let origin = i.origin.as_ref().ok_or_else(reject)?;
                    db::check_origin(
                        c,
                        rss_identity_core::account::AccountKey {
                            tenant,
                            principal: i.principal,
                        },
                        origin,
                    )
                    .await?;
                    let (source_id, issuer, subject) =
                        db::identity(c, tenant, origin.identity).await?;
                    let now = session_storage::now(c).await?;
                    if source_id != source.id
                        || issuer != claims.issuer
                        || subject != claims.subject
                        || claims
                            .assurance
                            .check(AuthenticationMode::Reauthenticate, attempt.created, now)
                            .is_err()
                    {
                        return Err(FederationError::Claims.into());
                    }
                    sqlx::query(concat!(
                        "UPDATE identity_authority.link_intents SET source_facts=$3 WHERE tenant_",
                        "id=$1::uuid AND intent_id=$2"
                    ))
                    .bind(tenant.to_string())
                    .bind(intent_id)
                    .bind(
                        crate::auth_facts::AuthenticationFacts::collect(
                            &claims,
                            source.version,
                            group_policy,
                            now,
                        )?
                        .encode(c)
                        .await?,
                    )
                    .execute(&mut *c)
                    .await?;
                    advance(c, tenant, intent_id, LinkStage::ReauthenticationRequired).await?;
                    db::consume(c, &locator).await?;
                    db::insert_attempt(
                        c,
                        db::NewAttempt {
                            cli: None,
                            mode: AuthenticationMode::Login,
                            locator: new_locator,
                            material,
                            provider: target,
                            browser,
                            client: attempt.client,
                            return_url: attempt.return_url,
                            link: Some(intent_id),
                            replacement: None,
                            expiry: Some(i.expiry),
                        },
                    )
                    .await?;
                    Ok((
                        (),
                        vec![event(
                            tenant,
                            Action::Reauthenticated,
                            &source,
                            Some(i.principal),
                        )],
                    ))
                })
            })
            .await?;
        Ok(FederatedOutcome::Redirect(FederatedRedirect { url }))
    }
}
pub(crate) struct Reauthentication {
    pub state: String,
    pub browser: String,
    pub session: Option<[u8; 32]>,
    pub old: db::Attempt,
    pub source: ProviderView,
    pub claims: UpstreamClaims,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkStage {
    ReauthenticationRequired,
    TargetReady,
    Completed,
}
impl LinkStage {
    fn restore(value: i16) -> Result<Self, rss_transactional_messaging_postgres::PgError> {
        match value {
            0 => Ok(Self::ReauthenticationRequired),
            1 => Ok(Self::TargetReady),
            2 => Ok(Self::Completed),
            _ => Err(corrupt()),
        }
    }
    fn code(self) -> i16 {
        match self {
            Self::ReauthenticationRequired => 0,
            Self::TargetReady => 1,
            Self::Completed => 2,
        }
    }
}
pub(crate) async fn advance(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    id: Uuid,
    from: LinkStage,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    let next = match from {
        LinkStage::ReauthenticationRequired => LinkStage::TargetReady,
        LinkStage::TargetReady => LinkStage::Completed,
        LinkStage::Completed => return Err(corrupt()),
    };
    let result=sqlx::query("UPDATE identity_authority.link_intents SET stage=$4 WHERE tenant_id=$1::uuid AND intent_id=$2 AND stage=$3").bind(tenant.to_string()).bind(id).bind(from.code()).bind(next.code()).execute(c).await?;
    if result.rows_affected() != 1 {
        return Err(reject());
    }
    Ok(())
}
