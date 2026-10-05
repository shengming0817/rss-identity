//! Real loopback JWKS HTTP and RSA signatures. These are synthetic claims, not Entra T3.
#![cfg(feature = "test-support")]
use axum::{Json, Router, routing::get};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rss_identity_core::entra::*;
use rss_identity_oidc::entra::HttpEntra;
use serde_json::{Value, json};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

fn jwt(claims: &Value, kid: Option<&str>, key: &[u8]) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(str::to_owned);
    encode(&header, claims, &EncodingKey::from_rsa_der(key)).unwrap()
}
#[tokio::test]
#[ignore = "requires make test-oidc"]
async fn signed_entra_resource_tokens() -> anyhow::Result<()> {
    let key_a = include_bytes!("fixtures/entra-a.der");
    let key_b = include_bytes!("fixtures/entra-b.der");
    let jwk: Value = serde_json::from_str(include_str!("fixtures/entra-a.json"))?;
    let document = Arc::new(RwLock::new(json!({"keys":[jwk]})));
    let blocked = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let response = document.clone();
    let gate = (blocked.clone(), entered.clone(), resume.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/keys", listener.local_addr()?);
    let app = Router::new().route(
        "/keys",
        get(move || {
            let response = response.clone();
            let (blocked, entered, resume) = gate.clone();
            async move {
                if blocked.load(Ordering::SeqCst) {
                    entered.notify_one();
                    resume.notified().await;
                }
                Json(response.read().unwrap().clone())
            }
        }),
    );
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown.await;
            })
            .await
            .unwrap();
    });
    let p = EntraTokenProfile {
        tenant: Uuid::new_v4(),
        app_id: Uuid::new_v4(),
        authorized_clients: vec![Uuid::new_v4()],
        required_scopes: vec!["mdm.enroll".into()],
        device_claim: "deviceid".into(),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let user = Uuid::new_v4();
    let device = Uuid::new_v4();
    let claims = json!({"iss":p.issuer(),"aud":p.app_id,"ver":"2.0","idtyp":"user","tid":p.tenant,"oid":user,"azp":p.authorized_clients[0],"iat":now-1,"nbf":now-1,"exp":now+300,"scp":"mdm.enroll other","deviceid":device});
    let verifier = Arc::new(HttpEntra::for_loopback_test(endpoint.clone())?);
    let result = verifier
        .verify(&p, Zeroizing::new(jwt(&claims, Some("entra-a"), key_a)))
        .await?;
    assert_eq!(result.user, user);
    assert_eq!(result.device, Some(device));
    let mut tou = claims.clone();
    tou.as_object_mut().unwrap().remove("deviceid");
    assert!(
        verifier
            .verify(&p, Zeroizing::new(jwt(&tou, Some("entra-a"), key_a)))
            .await?
            .device
            .is_none()
    );
    for (field, value) in [
        (
            "iss",
            json!("https://login.microsoftonline.com/common/v2.0"),
        ),
        ("aud", json!(format!("api://{}", p.app_id))),
        ("aud", json!([p.app_id])),
        ("ver", json!("1.0")),
        ("idtyp", json!("app")),
        ("tid", json!(Uuid::new_v4())),
        ("oid", json!(Uuid::nil())),
        ("azp", json!(Uuid::new_v4())),
        ("scp", json!("other")),
        ("exp", json!(now - 1)),
        ("nbf", json!(now + 60)),
        ("iat", json!(now + 60)),
        ("deviceid", json!("invalid-device")),
    ] {
        let mut invalid = claims.clone();
        invalid[field] = value;
        assert!(
            verifier
                .verify(&p, Zeroizing::new(jwt(&invalid, Some("entra-a"), key_a)))
                .await
                .is_err(),
            "field {field}"
        );
    }
    for field in [
        "idtyp", "oid", "tid", "azp", "exp", "nbf", "iss", "aud", "ver",
    ] {
        let mut invalid = claims.clone();
        invalid.as_object_mut().unwrap().remove(field);
        assert!(
            verifier
                .verify(&p, Zeroizing::new(jwt(&invalid, Some("entra-a"), key_a)))
                .await
                .is_err(),
            "missing {field}"
        );
    }
    for (kid, key) in [
        (None, key_a.as_slice()),
        (Some("unknown"), key_a.as_slice()),
        (Some("entra-a"), key_b.as_slice()),
    ] {
        assert!(
            verifier
                .verify(&p, Zeroizing::new(jwt(&claims, kid, key)))
                .await
                .is_err()
        );
    }
    // A slow miss from another tenant must not block this tenant's hot cache.
    blocked.store(true, Ordering::SeqCst);
    let mut other = p.clone();
    other.tenant = Uuid::new_v4();
    let mut other_claims = claims.clone();
    other_claims["tid"] = json!(other.tenant);
    other_claims["iss"] = json!(other.issuer());
    let pending = {
        let verifier = verifier.clone();
        tokio::spawn(async move {
            verifier
                .verify(
                    &other,
                    Zeroizing::new(jwt(&other_claims, Some("entra-a"), key_a)),
                )
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(2), entered.notified()).await?;
    let hot = tokio::time::timeout(
        Duration::from_millis(500),
        verifier.verify(&p, Zeroizing::new(jwt(&claims, Some("entra-a"), key_a))),
    )
    .await;
    blocked.store(false, Ordering::SeqCst);
    resume.notify_one();
    pending.await??;
    assert!(hot??.user == user);
    // A new cache sees rotated public keys, rejects removed keys and duplicate key ids.
    *document.write().unwrap() =
        json!({"keys":[serde_json::from_str::<Value>(include_str!("fixtures/entra-b.json"))?]});
    let rotated = HttpEntra::for_loopback_test(endpoint.clone())?;
    assert!(
        rotated
            .verify(&p, Zeroizing::new(jwt(&claims, Some("entra-b"), key_b)))
            .await
            .is_ok()
    );
    assert!(
        rotated
            .verify(&p, Zeroizing::new(jwt(&claims, Some("entra-a"), key_a)))
            .await
            .is_err()
    );
    let a: Value = serde_json::from_str(include_str!("fixtures/entra-a.json"))?;
    *document.write().unwrap() = json!({"keys":[a,a]});
    assert!(
        HttpEntra::for_loopback_test(endpoint)?
            .verify(&p, Zeroizing::new(jwt(&claims, Some("entra-a"), key_a)))
            .await
            .is_err()
    );
    let _ = stop.send(());
    server.await?;
    Ok(())
}
