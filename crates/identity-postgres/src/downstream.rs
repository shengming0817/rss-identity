//! Single durable downstream coordinator; Hydra never participates in a PG transaction.
use crate::{downstream_storage as db, storage::lock_guard, transaction::SecurityEvent, *};
use rss_identity_core::assurance::{Acr, Amr};
use rss_identity_core::downstream::*;
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;

/// Authority-issued facts for this validation only; no public construction or deserialization.
/// ```compile_fail
/// let proof: rss_identity_postgres::ValidatedIdentity = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug)]
pub struct ValidatedIdentity {
    subject: String,
    tenant_id: String,
    session_id: String,
    client_id: String,
    audience: String,
    issuer: String,
    auth_time: i64,
    amr: Vec<Amr>,
    acr: Acr,
    expires_at: i64,
}
impl ValidatedIdentity {
    /// Validated subject for the current request.
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// Validated tenant_id for the current request.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    /// Validated session_id for the current request.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    /// Validated client_id for the current request.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    /// Validated audience for the current request.
    pub fn audience(&self) -> &str {
        &self.audience
    }
    /// Validated issuer for the current request.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    /// Validated auth_time for the current request.
    pub fn auth_time(&self) -> i64 {
        self.auth_time
    }
    /// Validated amr for the current request.
    pub fn amr(&self) -> &[Amr] {
        &self.amr
    }
    /// Validated acr for the current request.
    pub fn acr(&self) -> Acr {
        self.acr
    }
    /// Validated expires_at for the current request.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}
#[derive(Clone)]
pub struct Downstream {
    pub(crate) authority: Authority,
    pub(crate) protocol: Arc<dyn DownstreamProtocol>,
    pub(crate) registrations: Arc<BTreeMap<String, Registration>>,
    pub(crate) lifetimes: Lifetimes,
    admission: Arc<PrepareAdmission>,
}
/// Shared process admission for unauthenticated prepare calls, before any protocol work.
/// Composition supplies one instance to every coordinator using the same Hydra service.
pub struct PrepareAdmission {
    concurrent: tokio::sync::Semaphore,
    rate: std::sync::Mutex<(std::time::Instant, u32)>,
    burst: u32,
    window: std::time::Duration,
}
impl PrepareAdmission {
    pub fn new(
        concurrent: u16,
        burst: u32,
        window: std::time::Duration,
    ) -> Result<Self, AuthorityError> {
        if concurrent == 0
            || concurrent > 128
            || burst == 0
            || burst > 10000
            || window.is_zero()
            || window > std::time::Duration::from_secs(60)
        {
            return Err(AuthorityError::Invalid);
        }
        Ok(Self {
            concurrent: tokio::sync::Semaphore::new(usize::from(concurrent)),
            rate: std::sync::Mutex::new((std::time::Instant::now(), 0)),
            burst,
            window,
        })
    }
    fn enter(&self) -> Result<tokio::sync::SemaphorePermit<'_>, AuthorityError> {
        let permit = self
            .concurrent
            .try_acquire()
            .map_err(|_| AuthorityError::RateLimited)?;
        let mut rate = self.rate.lock().map_err(|_| AuthorityError::RateLimited)?;
        let now = std::time::Instant::now();
        if now.duration_since(rate.0) >= self.window {
            *rate = (now, 0);
        }
        if rate.1 >= self.burst {
            return Err(AuthorityError::RateLimited);
        }
        rate.1 += 1;
        Ok(permit)
    }
}
/// A locator only; all operations also require the bound browser and authoritative session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowHandle {
    pub tenant_id: String,
    pub grant_id: Uuid,
}
impl FlowHandle {
    pub(crate) fn tenant(&self) -> Result<TenantId, AuthorityError> {
        TenantId::parse(&self.tenant_id).map_err(|_| AuthorityError::Invalid)
    }
}
#[derive(Serialize)]
pub(crate) struct DownstreamEvent {
    pub tenant: String,
    grant_id: Uuid,
    action: &'static str,
}
pub(crate) fn event(t: TenantId, id: Uuid, action: &'static str) -> SecurityEvent {
    SecurityEvent::Downstream(DownstreamEvent {
        tenant: t.to_string(),
        grant_id: id,
        action,
    })
}
pub(crate) fn digest(s: &str) -> Vec<u8> {
    Sha256::digest(s.as_bytes()).to_vec()
}
impl Downstream {
    pub fn new(
        authority: Authority,
        protocol: Arc<dyn DownstreamProtocol>,
        registrations: Vec<Registration>,
        lifetimes: Lifetimes,
        admission: Arc<PrepareAdmission>,
    ) -> Result<Self, AuthorityError> {
        authority.require_runtime()?;
        if registrations.is_empty() || registrations.len() > 128 {
            return Err(AuthorityError::Invalid);
        }
        let mut entries = BTreeMap::new();
        for r in registrations {
            if r.issuer() != protocol.issuer() {
                return Err(AuthorityError::Invalid);
            }
            if entries.insert(r.client().to_owned(), r).is_some() {
                return Err(AuthorityError::Invalid);
            }
        }
        Ok(Self {
            authority,
            protocol,
            registrations: Arc::new(entries),
            lifetimes,
            admission,
        })
    }
    pub fn clients(&self) -> impl Iterator<Item = &str> {
        self.registrations.keys().map(String::as_str)
    }
    pub fn authority(&self) -> Authority {
        self.authority.clone()
    }
    pub(crate) fn registration(&self, client: &str) -> Result<Registration, AuthorityError> {
        self.registrations
            .get(client)
            .cloned()
            .ok_or(DownstreamError::Rejected.into())
    }
    pub(crate) async fn remote<T>(
        &self,
        b: &Budget,
        f: ProtocolFuture<'_, T>,
    ) -> Result<T, AuthorityError> {
        tokio::time::timeout_at(b.0.into(), f)
            .await
            .map_err(|_| DownstreamError::Unavailable)?
            .map_err(Into::into)
    }
    pub async fn begin_login(
        &self,
        challenge: Secret,
        browser: BrowserBindingSecret,
        deadline: OperationDeadline,
    ) -> Result<FlowHandle, AuthorityError> {
        let b = Budget::new(deadline)?;
        let permit = self.admission.enter()?;
        let request = self.remote(&b, self.protocol.login(&challenge)).await?;
        drop(permit);
        let r = self.registration(&request.client)?;
        r.check(&request)?;
        let t = r.tenant();
        self.authority
            .reserve_downstream(t, r.client().to_owned(), b.remaining())
            .await?;
        let id = Uuid::new_v4();
        let login = digest(challenge.expose());
        let browser = browser.digest();
        let life = self.lifetimes;
        self.authority.write_sql(t,b.remaining(),move|c|Box::pin(async move{
            lock_guard(c,t).await?;let now=crate::session_storage::now(c).await?;
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM identity_authority.downstream_grants WHERE tenant_id=$1::uuid AND client_id=$2").bind(t.to_string()).bind(r.client()).fetch_one(&mut*c).await?;
            if count>=1000{return Err(DownstreamError::Unavailable.into());}
            sqlx::query("INSERT INTO identity_authority.downstream_grants(tenant_id,grant_id,client_id,config_version,login_hash,browser_hash,hydra_sid,state,created_at,expires_at,horizon,next_attempt,registration_hash) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,0,$8,$9,$10,$8,$11)")
                .bind(t.to_string()).bind(id).bind(r.client()).bind(r.version()).bind(login).bind(browser.as_slice()).bind(request.login_session_id).bind(now).bind(now+life.request()).bind(now+life.request()).bind(r.fingerprint().as_slice()).execute(c).await?;
            Ok((FlowHandle{tenant_id:t.to_string(),grant_id:id},vec![event(t,id,"prepared")]))
        })).await
    }
    pub async fn accept_login(
        &self,
        handle: FlowHandle,
        challenge: Secret,
        browser: BrowserBindingSecret,
        actor: AuthenticatedSession,
        deadline: OperationDeadline,
    ) -> Result<Secret, AuthorityError> {
        let b = Budget::new(deadline)?;
        let t = handle.tenant()?;
        let id = handle.grant_id;
        let request = self.remote(&b, self.protocol.login(&challenge)).await?;
        let r = self.registration(&request.client)?;
        r.check(&request)?;
        if t != r.tenant() || t != actor.account().tenant {
            return Err(DownstreamError::Rejected.into());
        }
        let hash = digest(challenge.expose());
        let browser = browser.digest();
        let registration = r.clone();
        let life = self.lifetimes;
        let decision=self.authority.write_sql(t,b.remaining(),move|c|Box::pin(async move{
            let g=db::load_grant(c,t,id).await?;db::binding(&g,&registration)?;
            let loaded=crate::session_storage::recheck(c,&actor).await?;
            if g.state!=FlowState::AwaitingLogin || loaded.now>=g.expiry || g.browser_hash!=browser || g.login_hash!=hash || g.sid!=request.login_session_id{return Err(DownstreamError::Rejected.into());}
            let generated=db::ProductSubject::generate()?;
            sqlx::query("INSERT INTO identity_authority.product_subjects VALUES($1::uuid,$2,$3,$4) ON CONFLICT DO NOTHING")
                .bind(t.to_string()).bind(registration.client()).bind(loaded.state.key().principal.as_uuid()).bind(generated.as_str()).execute(&mut*c).await?;
            let subject:String=sqlx::query_scalar("SELECT subject FROM identity_authority.product_subjects WHERE tenant_id=$1::uuid AND client_id=$2 AND principal_id=$3")
                .bind(t.to_string()).bind(registration.client()).bind(loaded.state.key().principal.as_uuid()).fetch_one(&mut*c).await?;
            sqlx::query("UPDATE identity_authority.downstream_grants SET principal_id=$3,session_id=$4,subject=$5,horizon=created_at+$6 WHERE tenant_id=$1::uuid AND grant_id=$2")
                .bind(t.to_string()).bind(id).bind(loaded.state.key().principal.as_uuid()).bind(loaded.view.id.as_uuid()).bind(&subject).bind(life.horizon()).execute(&mut*c).await?;
            db::state(c,t,&g,FlowState::LoginAccepting,loaded.now).await?;
            Ok((LoginDecision{grant_id:id.to_string(),subject},vec![event(t,id,"login_claimed")]))
        })).await?;
        let result = self
            .remote(&b, self.protocol.accept_login(&challenge, decision))
            .await;
        self.finish(id, r, FlowState::AwaitingConsent, result, b)
            .await
    }
    pub async fn inspect_consent(
        &self,
        challenge: &Secret,
        browser: &BrowserBindingSecret,
        deadline: OperationDeadline,
    ) -> Result<FlowHandle, AuthorityError> {
        let b = Budget::new(deadline)?;
        let request = self.remote(&b, self.protocol.consent(challenge)).await?;
        let r = self.registration(&request.client)?;
        r.check(&request)?;
        let t = r.tenant();
        let grant = Uuid::parse_str(
            request
                .login_binding
                .as_deref()
                .ok_or(DownstreamError::Rejected)?,
        )
        .map_err(|_| DownstreamError::Rejected)?;
        let browser = browser.digest();
        self.authority.read_sql(t,b.remaining(),move|c|Box::pin(async move{
            lock_guard(c,t).await?;
            let id:Uuid=sqlx::query_scalar("SELECT grant_id FROM identity_authority.downstream_grants WHERE tenant_id=$1::uuid AND grant_id=$2 AND browser_hash=$3")
                .bind(t.to_string()).bind(grant).bind(browser.as_slice()).fetch_optional(&mut*c).await?.ok_or(DownstreamError::Rejected)?;
            let g=db::load_grant(c,t,id).await?;db::binding(&g,&r)?;
            if g.state!=FlowState::AwaitingConsent || g.subject!=request.subject || g.sid!=request.login_session_id{return Err(DownstreamError::Rejected.into());}
            let loaded=db::session(c,&g).await?;if loaded.now>=g.expiry{return Err(DownstreamError::Rejected.into());}
            Ok(FlowHandle{tenant_id:t.to_string(),grant_id:id})
        })).await
    }
    pub async fn accept_consent(
        &self,
        handle: FlowHandle,
        challenge: Secret,
        browser: BrowserBindingSecret,
        actor: AuthenticatedSession,
        deadline: OperationDeadline,
    ) -> Result<Secret, AuthorityError> {
        let b = Budget::new(deadline)?;
        let t = handle.tenant()?;
        let id = handle.grant_id;
        let request = self.remote(&b, self.protocol.consent(&challenge)).await?;
        let r = self.registration(&request.client)?;
        r.check(&request)?;
        if t != r.tenant() || t != actor.account().tenant {
            return Err(DownstreamError::Rejected.into());
        }
        let login = Uuid::parse_str(
            request
                .login_binding
                .as_deref()
                .ok_or(DownstreamError::Rejected)?,
        )
        .map_err(|_| DownstreamError::Rejected)?;
        let consent = request
            .consent_request_id
            .ok_or(DownstreamError::Rejected)?;
        bounded(&consent, 512)?;
        let hash = digest(challenge.expose());
        let browser = browser.digest();
        let registration = r.clone();
        self.authority.write_sql(t,b.remaining(),move|c|Box::pin(async move{
            let g=db::load_grant(c,t,id).await?;db::binding(&g,&registration)?;
            let loaded=crate::session_storage::recheck(c,&actor).await?;
            if g.state!=FlowState::AwaitingConsent || loaded.now>=g.expiry || g.session!=Some(loaded.view.id) || g.key!=Some(loaded.state.key()) || g.browser_hash!=browser || g.id!=login || g.subject!=request.subject || g.sid!=request.login_session_id{return Err(DownstreamError::Rejected.into());}
            sqlx::query("UPDATE identity_authority.downstream_grants SET consent_hash=$3,consent_id=$4 WHERE tenant_id=$1::uuid AND grant_id=$2")
                .bind(t.to_string()).bind(id).bind(hash).bind(consent).execute(&mut*c).await?;
            db::state(c,t,&g,FlowState::ConsentAccepting,loaded.now).await?;
            Ok(((),vec![event(t,id,"consent_claimed")]))
        })).await?;
        let decision = ConsentDecision {
            grant_id: id.to_string(),
            audience: r.audience().into(),
        };
        let result = self
            .remote(&b, self.protocol.accept_consent(&challenge, decision))
            .await;
        self.finish(id, r, FlowState::Active, result, b).await
    }
    async fn finish(
        &self,
        id: Uuid,
        r: Registration,
        to: FlowState,
        result: Result<Secret, AuthorityError>,
        b: Budget,
    ) -> Result<Secret, AuthorityError> {
        let t = r.tenant();
        let from = if to == FlowState::Active {
            FlowState::ConsentAccepting
        } else {
            FlowState::LoginAccepting
        };
        let redirect = match result {
            Ok(v) => v,
            Err(e) => {
                let _ = self.revoke_local(t, id, b.remaining()).await;
                return Err(e);
            }
        };
        let settled = self
            .authority
            .write_sql(t, b.remaining(), move |c| {
                Box::pin(async move {
                    let g = db::load_grant(c, t, id).await?;
                    db::binding(&g, &r)?;
                    let loaded = db::session(c, &g).await?;
                    if g.state != from || loaded.now >= g.expiry || loaded.now >= g.lease {
                        return Err(DownstreamError::Rejected.into());
                    }
                    db::state(c, t, &g, to, loaded.now).await?;
                    Ok((
                        (),
                        vec![event(
                            t,
                            id,
                            if to == FlowState::Active {
                                "active"
                            } else {
                                "login_accepted"
                            },
                        )],
                    ))
                })
            })
            .await;
        if let Err(e) = settled {
            let _ = self.revoke_local(t, id, b.remaining()).await;
            return Err(e);
        }
        Ok(redirect)
    }
    pub(crate) async fn revoke_local(
        &self,
        t: TenantId,
        id: Uuid,
        d: OperationDeadline,
    ) -> Result<(), AuthorityError> {
        self.authority
            .conditional_write_sql(t, d, move |c| {
                Box::pin(async move {
                    let g = db::load_grant(c, t, id).await?;
                    let now = crate::session_storage::now(c).await?;
                    let events = if g.state != FlowState::Revoking {
                        db::state(c, t, &g, FlowState::Revoking, now).await?;
                        vec![event(t, id, "revoking")]
                    } else {
                        vec![]
                    };
                    Ok(((), events))
                })
            })
            .await
    }
    /// Read-only online identity check. Caller identity must be authenticated by the transport.
    pub async fn validate(
        &self,
        client: &str,
        t: TenantId,
        audience: &str,
        credential: Secret,
        d: OperationDeadline,
    ) -> Result<ValidatedIdentity, AuthorityError> {
        let b = Budget::new(d)?;
        let r = self.registration(client)?;
        if t != r.tenant() || audience != r.audience() {
            return Err(DownstreamError::Rejected.into());
        }
        let token = self
            .remote(&b, self.protocol.introspect(&credential))
            .await?;
        if !token.active
            || token.version != 1
            || token.issuer != r.issuer()
            || token.client != r.client()
            || token.audiences != [r.audience().to_string()]
            || token.token_use != "access_token"
            || !token.token_type.eq_ignore_ascii_case("bearer")
            || token.scope != "openid"
        {
            return Err(DownstreamError::Rejected.into());
        }
        let skew = self.lifetimes.clock_skew();
        let id = Uuid::parse_str(&token.grant_id).map_err(|_| DownstreamError::Rejected)?;
        self.authority
            .read_sql(t, b.remaining(), move |c| {
                Box::pin(async move {
                    let g = db::load_grant(c, t, id).await?;
                    db::binding(&g, &r)?;
                    if g.state != FlowState::Active || g.subject.as_deref() != Some(&token.subject)
                    {
                        return Err(DownstreamError::Rejected.into());
                    }
                    let loaded = db::session(c, &g).await?;
                    if loaded.now >= g.horizon
                        || loaded.now >= token.expires_at
                        || token.not_before > loaded.now.saturating_add(skew)
                        || token.issued_at > loaded.now.saturating_add(skew)
                        || token.issued_at <= 0
                        || token.expires_at <= token.issued_at
                    {
                        return Err(DownstreamError::Rejected.into());
                    }
                    Ok(ValidatedIdentity {
                        subject: token.subject,
                        tenant_id: t.to_string(),
                        session_id: loaded.view.id.to_string(),
                        client_id: r.client().into(),
                        audience: r.audience().into(),
                        issuer: r.issuer().into(),
                        auth_time: loaded
                            .assurance
                            .auth_time()
                            .unwrap_or(loaded.view.auth_time),
                        amr: loaded.assurance.amr().to_vec(),
                        acr: loaded.assurance.acr(),
                        expires_at: token
                            .expires_at
                            .min(g.horizon)
                            .min(loaded.view.idle_expires_at)
                            .min(loaded.view.absolute_expires_at),
                    })
                })
            })
            .await
    }
}
