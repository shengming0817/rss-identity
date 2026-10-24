//! Real PG, TLS Keycloak and two HTTP RP sessions. Software device key is a fixture only.
#[path = "../../identity-postgres/tests/support/mod.rs"]
mod support;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use rss_identity_core::{enterprise::EnterpriseTarget, federation::*};
use rss_identity_oidc::{HttpOidc, enterprise::Es256EnterpriseSigner};
use rss_identity_postgres::{platform::*, *};
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use support::*;
use uuid::Uuid;
struct Device {
    binding: PlatformBinding,
    key: Ed25519KeyPair,
}
impl PlatformVerifier for Device {
    fn audience(&self) -> &str {
        "identity-enterprise-test"
    }
    fn authorize_purpose<'a>(
        &'a self,
        b: &'a PlatformBinding,
        p: &'a PlatformPurpose,
        c: &'a mut sqlx::PgConnection,
    ) -> futures::future::BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            if !matches!(p,PlatformPurpose::EnterpriseRp(id) if id=="rp-a" || id=="rp-b") {
                return Err(PlatformError::Rejected);
            }
            self.recheck(b, c).await
        })
    }
    fn resolve<'a>(
        &'a self,
        i: rss_identity_core::InstanceId,
        t: rss_request_context::TenantId,
        b: Uuid,
        c: &'a mut sqlx::PgConnection,
    ) -> futures::future::BoxFuture<'a, Result<PlatformBinding, PlatformError>> {
        Box::pin(async move {
            if i != self.binding.instance
                || t != self.binding.account.tenant
                || b != self.binding.binding_id
            {
                return Err(PlatformError::Rejected);
            }
            self.recheck(&self.binding, c).await?;
            Ok(self.binding.clone())
        })
    }
    fn verify<'a>(
        &'a self,
        ctx: &'a PlatformChallengeContext,
        e: &'a [u8],
    ) -> futures::future::BoxFuture<'a, Result<PlatformEvidence, PlatformError>> {
        Box::pin(async move {
            UnparsedPublicKey::new(&ED25519, self.key.public_key().as_ref())
                .verify(&ctx.signing_payload()?, e)
                .map_err(|_| PlatformError::Rejected)?;
            Ok(PlatformEvidence {
                key_possession: true,
                hardware_key: false,
                user_presence: false,
                user_verification: false,
                authenticated_at: None,
                profile: PlatformProfile::Unavailable,
            })
        })
    }
    fn recheck<'a>(
        &'a self,
        b: &'a PlatformBinding,
        c: &'a mut sqlx::PgConnection,
    ) -> futures::future::BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            if b != &self.binding {
                return Err(PlatformError::Rejected);
            }
            let active: bool = sqlx::query_scalar(
                "SELECT active FROM public.enterprise_fixture WHERE tenant_id=$1::uuid FOR UPDATE",
            )
            .bind(b.account.tenant.to_string())
            .fetch_one(c)
            .await
            .map_err(|_| PlatformError::Unavailable)?;
            if active {
                Ok(())
            } else {
                Err(PlatformError::Rejected)
            }
        })
    }
}
struct Rp {
    authority: Authority,
    target: EnterpriseTarget,
    provider: ProviderSettings,
    credentials: ProviderCredentials,
    oidc: HttpOidc,
    subject: String,
    tenant: rss_request_context::TenantId,
    sessions: std::sync::Mutex<std::collections::BTreeMap<String, SessionReference>>,
}
async fn login(State(rp): State<Arc<Rp>>, Json(input): Json<Value>) -> axum::response::Response {
    let result = async {
        let session = rp
            .authority
            .complete_platform_login(
                rp.tenant,
                serde_json::from_value(input["id"].clone()).map_err(|_| ())?,
                input["nonce"].as_str().ok_or(())?.into(),
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                serde_json::from_value(input["evidence"].clone()).map_err(|_| ())?,
                deadline(),
            )
            .await
            .map_err(|_| ())?;
        let assertion = session.assertion.ok_or(())?;
        if assertion.target != rp.target {
            return Err(());
        }
        rp.oidc
            .exchange_enterprise(
                rp.tenant,
                &rp.provider,
                &rp.credentials,
                &rp.target,
                assertion.expose(),
                assertion.expires_at,
                &rp.subject,
            )
            .await
            .map_err(|_| ())?;
        let proof = rp
            .authority
            .inspect_session(
                rp.tenant,
                rss_identity_core::session::SessionSecret::parse(
                    session.session.secret().expose().into(),
                )
                .map_err(|_| ())?,
                deadline(),
            )
            .await
            .map_err(|_| ())?;
        let reference = proof.reference().map_err(|_| ())?;
        let cookie = random_secret().map_err(|_| ())?.to_string();
        rp.sessions
            .lock()
            .unwrap()
            .insert(cookie.clone(), reference);
        Ok::<_, ()>(cookie)
    }
    .await;
    match result {
        Ok(s) => (
            [(
                "set-cookie",
                format!("rp-session={}; HttpOnly; SameSite=Strict; Path=/", s),
            )],
            Json(json!({"authenticated":true})),
        )
            .into_response(),
        Err(()) => StatusCode::UNAUTHORIZED.into_response(),
    }
}
async fn resource(State(rp): State<Arc<Rp>>, headers: HeaderMap) -> StatusCode {
    let Some(secret) = headers
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("rp-session="))
    else {
        return StatusCode::UNAUTHORIZED;
    };
    let reference = rp.sessions.lock().unwrap().get(secret).cloned();
    let Some(reference) = reference else {
        return StatusCode::UNAUTHORIZED;
    };
    match rp
        .authority
        .recheck_session_reference(rp.tenant, &reference, deadline())
        .await
    {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::UNAUTHORIZED,
    }
}
async fn admin(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> anyhow::Result<Value> {
    let mut req = client
        .request(method, format!("{base}{path}"))
        .bearer_auth(token);
    if let Some(body) = body {
        req = req.json(&body)
    }
    let response = req.send().await?;
    anyhow::ensure!(
        response.status().is_success(),
        "Keycloak fixture administration failed: {} {}",
        path,
        response.status()
    );
    let bytes = response.bytes().await?;
    Ok(if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    })
}
#[tokio::test]
#[ignore = "requires make test-federated"]
async fn real_enterprise_assertions_reach_only_the_registered_rp() -> anyhow::Result<()> {
    use reqwest::Method;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    sqlx::raw_sql("CREATE TABLE public.enterprise_fixture(tenant_id uuid PRIMARY KEY,active boolean NOT NULL);GRANT SELECT,UPDATE ON public.enterprise_fixture TO identity_runtime;").execute(&f.owner).await?;
    sqlx::query("INSERT INTO public.enterprise_fixture VALUES($1::uuid,true)")
        .bind(A)
        .execute(&f.owner)
        .await?;
    let issuer = std::env::var("IDENTITY_TEST_FEDERATED_ISSUER")?;
    let ca = std::fs::read_to_string(std::env::var("IDENTITY_TEST_FEDERATED_CA")?)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.as_bytes())?)
        .timeout(Duration::from_secs(10))
        .build()?;
    let origin = issuer.trim_end_matches("/realms/identity");
    let token: Value = client
        .post(format!(
            "{origin}/realms/master/protocol/openid-connect/token"
        ))
        .form(&[
            ("grant_type", "password"),
            ("client_id", "admin-cli"),
            ("username", "fixture-operator"),
            ("password", "fixture-operator-password"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let token = zeroize::Zeroizing::new(token["access_token"].as_str().unwrap().to_owned());
    let base = format!("{origin}/admin/realms/identity");
    let users = admin(
        &client,
        &base,
        &token,
        Method::GET,
        "/users?username=alice&exact=true",
        None,
    )
    .await?;
    let user = users[0]["id"].as_str().unwrap().to_owned();
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)?;
    let ec = openssl::ec::EcKey::generate(&group)?;
    let key = openssl::pkey::PKey::from_ec_key(ec)?;
    let pem = zeroize::Zeroizing::new(key.private_key_to_pem_pkcs8()?);
    let public = String::from_utf8(key.public_key_to_pem()?)?;
    let signer = Arc::new(
        Es256EnterpriseSigner::new("enterprise-1".into(), &pem).map_err(anyhow::Error::msg)?,
    );
    let targets = vec!["rp-a", "rp-b"]
        .into_iter()
        .map(|id| EnterpriseTarget {
            id: id.into(),
            issuer: format!("https://identity.example.test/{id}"),
            token_endpoint: format!("{issuer}/protocol/openid-connect/token"),
            client_id: id.into(),
            scopes: BTreeSet::from(["openid".into()]),
        })
        .collect::<Vec<_>>();
    let sub = format!(
        "{}/{}/{}",
        f.instance,
        f.key.tenant,
        f.key.principal.as_uuid()
    );
    for target in &targets {
        admin(&client,&base,&token,Method::POST,"/identity-provider/instances",Some(json!({"alias":target.id,"providerId":"jwt-authorization-grant","enabled":true,"config":{"issuer":target.issuer,"jwtAuthorizationGrantEnabled":"true","jwtAuthorizationGrantAssertionReuseAllowed":"false","jwtAuthorizationGrantMaxAllowedAssertionExpiration":"30","jwtAuthorizationGrantAssertionSignatureAlg":"ES256","jwtAuthorizationGrantLimitAccessTokenExp":"true","useJwksUrl":"false","publicKeySignatureVerifier":public,"publicKeySignatureVerifierKeyId":"enterprise-1"}}))).await?;
        admin(&client,&base,&token,Method::POST,"/clients",Some(json!({"clientId":target.client_id,"enabled":true,"protocol":"openid-connect","publicClient":false,"secret":"fixture-enterprise-secret","standardFlowEnabled":false,"attributes":{"oauth2.jwt.authorization.grant.enabled":"true","oauth2.jwt.authorization.grant.idp":target.id},"protocolMappers":[{"name":"rp-audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.client.audience":target.client_id,"access.token.claim":"true","id.token.claim":"false"}}]}))).await?;
        admin(
            &client,
            &base,
            &token,
            Method::POST,
            &format!("/users/{user}/federated-identity/{}", target.id),
            Some(json!({"identityProvider":target.id,"userId":sub,"userName":"fixture-subject"})),
        )
        .await?;
    }
    let device = Arc::new(Device {
        binding: PlatformBinding {
            instance: f.instance,
            account: f.key,
            binding_id: Uuid::new_v4(),
            binding_epoch: 1,
            source_id: Uuid::new_v4(),
            source_version: 1,
            external_identity: None,
        },
        key: Ed25519KeyPair::from_seed_unchecked(&[17; 32]).unwrap(),
    });
    let config = support::config(f.instance)
        .with_platform(device.clone())
        .with_enterprise(EnterpriseConfig::new(targets.clone(), signer)?);
    let authority = Authority::connect_runtime(
        f.runtime.clone(),
        Arc::new(rss_identity_core::account::PasswordKdf::new()),
        config,
        f.policy.clone(),
        deadline(),
    )
    .await?;
    let mut sessions = Vec::new();
    let mut tasks = Vec::new();
    for target in targets.clone() {
        let settings: ProviderSettings = ProviderSettingsInput {
            issuer: issuer.clone(),
            client_id: target.client_id.clone(),
            redirect_uri: "https://identity.example.test/callback".into(),
            scopes: vec!["openid".into()],
            claims: ClaimMapping {
                subject: rss_identity_core::entra::SubjectMapping::Oidc,
                profile: Default::default(),
                groups: None,
                department_snapshot: None,
            },
            jit: false,
        }
        .try_into()?;
        let rp = Arc::new(Rp {
            authority: authority.clone(),
            target: target.clone(),
            provider: settings,
            credentials: ProviderCredentials::new(
                "fixture-enterprise-secret".into(),
                Some(ca.clone()),
            )?,
            oidc: HttpOidc::for_loopback_test(vec![])?,
            subject: user.clone(),
            tenant: f.key.tenant,
            sessions: Default::default(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        tasks.push(tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/login", post(login))
                    .route("/resource", get(resource))
                    .with_state(rp),
            )
            .await
        }));
        let c = authority
            .begin_platform_login(
                f.key.tenant,
                device.binding.binding_id,
                PlatformPurpose::EnterpriseRp(target.id),
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                source(),
                deadline(),
            )
            .await?;
        let evidence = device.key.sign(&c.signing_payload).as_ref().to_vec();
        let body = json!({"id":c.id,"nonce":c.nonce,"evidence":evidence});
        let response = client
            .post(format!("{url}/login"))
            .json(&body)
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "RP login failed: {}",
            response.status()
        );
        let cookie = response.headers()["set-cookie"]
            .to_str()?
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert_eq!(
            client
                .get(format!("{url}/resource"))
                .header("cookie", &cookie)
                .send()
                .await?
                .status(),
            200
        );
        assert_eq!(
            client
                .post(format!("{url}/login"))
                .json(&body)
                .send()
                .await?
                .status(),
            401
        );
        sessions.push((url, cookie));
    }
    assert_eq!(
        client
            .get(format!("{}/resource", sessions[1].0))
            .header("cookie", &sessions[0].1)
            .send()
            .await?
            .status(),
        401
    );

    // Rotate the assertion signing key through the real IdP trust configuration.
    let target = targets[0].clone();
    let stale = assertion(&authority, &device, &f, &target).await?;
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)?;
    let replacement = openssl::pkey::PKey::from_ec_key(openssl::ec::EcKey::generate(&group)?)?;
    let pem = zeroize::Zeroizing::new(replacement.private_key_to_pem_pkcs8()?);
    let mut idp = admin(
        &client,
        &base,
        &token,
        Method::GET,
        "/identity-provider/instances/rp-a",
        None,
    )
    .await?;
    idp["config"]["publicKeySignatureVerifier"] =
        json!(String::from_utf8(replacement.public_key_to_pem()?)?);
    idp["config"]["publicKeySignatureVerifierKeyId"] = json!("enterprise-2");
    admin(
        &client,
        &base,
        &token,
        Method::PUT,
        "/identity-provider/instances/rp-a",
        Some(idp),
    )
    .await?;
    let credentials =
        ProviderCredentials::new("fixture-enterprise-secret".into(), Some(ca.clone()))?;
    let transport = HttpOidc::for_loopback_test(vec![])?;
    let provider = rp_settings(&target, &issuer)?;
    assert!(
        transport
            .exchange_enterprise(
                f.key.tenant,
                &provider,
                &credentials,
                &target,
                stale.assertion.as_ref().unwrap().expose(),
                stale.assertion.as_ref().unwrap().expires_at,
                &user
            )
            .await
            .is_err()
    );
    let rotated = Authority::connect_runtime(
        f.runtime.clone(),
        Arc::new(rss_identity_core::account::PasswordKdf::new()),
        support::config(f.instance)
            .with_platform(device.clone())
            .with_enterprise(EnterpriseConfig::new(
                targets.clone(),
                Arc::new(
                    Es256EnterpriseSigner::new("enterprise-2".into(), &pem)
                        .map_err(anyhow::Error::msg)?,
                ),
            )?),
        f.policy.clone(),
        deadline(),
    )
    .await?;
    let fresh = assertion(&rotated, &device, &f, &target).await?;
    let signed = fresh.assertion.as_ref().unwrap().expose();
    // A different confidential RP cannot exchange this issuer's assertion.
    assert!(
        transport
            .exchange_enterprise(
                f.key.tenant,
                &rp_settings(&targets[1], &issuer)?,
                &credentials,
                &targets[1],
                signed,
                fresh.assertion.as_ref().unwrap().expires_at,
                &user
            )
            .await
            .is_err()
    );
    let fresh = assertion(&rotated, &device, &f, &target).await?;
    let signed = fresh.assertion.as_ref().unwrap().expose();
    transport
        .exchange_enterprise(
            f.key.tenant,
            &provider,
            &credentials,
            &target,
            signed,
            fresh.assertion.as_ref().unwrap().expires_at,
            &user,
        )
        .await?;
    assert!(
        transport
            .exchange_enterprise(
                f.key.tenant,
                &provider,
                &credentials,
                &target,
                signed,
                fresh.assertion.as_ref().unwrap().expires_at,
                &user
            )
            .await
            .is_err()
    );
    sqlx::query("UPDATE public.enterprise_fixture SET active=false")
        .execute(&f.owner)
        .await?;
    for (url, cookie) in sessions {
        assert_eq!(
            client
                .get(format!("{url}/resource"))
                .header("cookie", cookie)
                .send()
                .await?
                .status(),
            401
        );
    }
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    f.close().await;
    Ok(())
}

async fn assertion(
    authority: &Authority,
    device: &Device,
    f: &Fixture,
    target: &EnterpriseTarget,
) -> anyhow::Result<PlatformLogin> {
    let challenge = authority
        .begin_platform_login(
            f.key.tenant,
            device.binding.binding_id,
            PlatformPurpose::EnterpriseRp(target.id.clone()),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            source(),
            deadline(),
        )
        .await?;
    let evidence = device
        .key
        .sign(&challenge.signing_payload)
        .as_ref()
        .to_vec();
    Ok(authority
        .complete_platform_login(
            f.key.tenant,
            challenge.id,
            challenge.nonce,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            evidence,
            deadline(),
        )
        .await?)
}
fn rp_settings(target: &EnterpriseTarget, issuer: &str) -> anyhow::Result<ProviderSettings> {
    Ok(ProviderSettingsInput {
        issuer: issuer.into(),
        client_id: target.client_id.clone(),
        redirect_uri: "https://identity.example.test/callback".into(),
        scopes: vec!["openid".into()],
        claims: ClaimMapping {
            subject: rss_identity_core::entra::SubjectMapping::Oidc,
            profile: Default::default(),
            groups: None,
            department_snapshot: None,
        },
        jit: false,
    }
    .try_into()?)
}
