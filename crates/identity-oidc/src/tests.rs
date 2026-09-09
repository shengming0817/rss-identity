use super::*;
use openidconnect::core::{
    CoreHmacKey, CoreIdToken, CoreIdTokenClaims, CoreIdTokenVerifier, CoreJsonWebKeySet,
    CoreJwsSigningAlgorithm,
};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::TcpListener,
};

#[test]
fn signed_claims_bind_authorized_party_issuer_audience_and_expiry() {
    let client = ClientId::new("client".into());
    let issuer = IssuerUrl::new("https://issuer.test".into()).unwrap();
    let verifier = CoreIdTokenVerifier::new_confidential_client(
        client.clone(),
        ClientSecret::new("fixture-secret".into()),
        issuer,
        CoreJsonWebKeySet::new(vec![]),
    )
    .set_allowed_algs(vec![CoreJwsSigningAlgorithm::HmacSha256]);
    for (field, value, valid) in [
        ("azp", json!(null), true),
        ("azp", json!("client"), true),
        ("azp", json!("other-client"), false),
        ("iss", json!("https://other.test"), false),
        ("aud", json!(["other-client"]), false),
        ("exp", json!(1), false),
    ] {
        let mut value_claims = json!({"iss":"https://issuer.test","sub":"subject","aud":["client"],"iat":1,"exp":4102444800_i64,"nonce":"nonce"});
        if !value.is_null() {
            value_claims[field] = value;
        }
        let claims: CoreIdTokenClaims = serde_json::from_value(value_claims).unwrap();
        let token = CoreIdToken::new(
            claims,
            &CoreHmacKey::new("fixture-secret"),
            CoreJwsSigningAlgorithm::HmacSha256,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            verify(
                &serde_json::from_value(serde_json::json!(token.to_string())).unwrap(),
                &verifier,
                &Nonce::new("nonce".into()),
                &client
            )
            .is_ok(),
            valid,
            "{field}"
        );
    }
}

fn server(status: &str, extra: &str, body: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
        body.len()
    );
    let handle = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let start = std::time::Instant::now();
        loop {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut request = [0; 8192];
                    assert!(socket.read(&mut request).unwrap() > 0);
                    let _ = socket
                        .write_all(header.as_bytes())
                        .and_then(|_| socket.write_all(&body));
                    return;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        start.elapsed() < Duration::from_secs(5),
                        "fixture request timed out"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });
    (url, handle)
}
fn config(issuer: &str) -> ProviderSettings {
    (rss_identity_core::federation::ProviderSettingsInput {
        issuer: issuer.into(),
        client_id: "client".into(),
        secret_ref: "fixture@1".into(),
        redirect_uri: "http://127.0.0.1/callback".into(),
        scopes: vec!["openid".into()],
        claims: rss_identity_core::federation::ClaimMapping {
            email: None,
            groups: None,
        },
        jit: false,
    })
    .try_into()
    .unwrap()
}
fn adapter(issuer: &str) -> HttpOidc {
    HttpOidc::for_loopback_test(
        vec![ApprovedProvider {
            keycloak_totp: false,
            tenant: tenant(),
            issuer: issuer.into(),
            client_id: "client".into(),
            secret_ref: "fixture@1".into(),
            redirect_uri: "http://127.0.0.1/callback".into(),
            addresses: vec!["127.0.0.0/8".parse().unwrap()],
        }],
        BTreeMap::from([("fixture@1".into(), Zeroizing::new("fixture-secret".into()))]),
    )
    .unwrap()
}
fn transport(origin: &str) -> Transport {
    adapter(origin)
        .transport(tenant(), &config(origin))
        .unwrap()
}
async fn get(t: &Transport, url: &str) -> Result<HttpResponse, FederationError> {
    t.call(
        openidconnect::http::Request::builder()
            .uri(url)
            .body(vec![])
            .unwrap(),
    )
    .await
}
#[tokio::test]
async fn outbound_origin_redirect_and_size_are_enforced() {
    let (url, handle) = server("200 OK", "", b"ok".to_vec());
    assert_eq!(get(&transport(&url), &url).await.unwrap().body(), b"ok");
    handle.join().unwrap();
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let target_url = format!("http://{}", target.local_addr().unwrap());
    assert!(matches!(
        get(&transport("https://issuer.test"), &target_url).await,
        Err(FederationError::Provider(ProviderFailure {
            reason: ProviderReason::EgressDenied,
            ..
        }))
    ));
    let (url, handle) = server("302 Found", &format!("Location: {target_url}\r\n"), vec![]);
    assert_eq!(get(&transport(&url), &url).await.unwrap().status(), 302);
    handle.join().unwrap();
    assert_eq!(
        target.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let (url, handle) = server("200 OK", "", vec![b'x'; 1024 * 1024 + 1]);
    assert!(matches!(
        get(&transport(&url), &url).await,
        Err(FederationError::Provider(ProviderFailure {
            reason: ProviderReason::InvalidResponse,
            ..
        }))
    ));
    handle.join().unwrap();
}

#[tokio::test]
async fn discovery_rejects_external_authorization_and_jwks() {
    for external_jwks in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let forbidden = TcpListener::bind("127.0.0.1:0").unwrap();
        forbidden.set_nonblocking(true).unwrap();
        let external = format!("http://{}", forbidden.local_addr().unwrap());
        let metadata = json!({
            "issuer": issuer,
            "authorization_endpoint": if external_jwks { issuer.clone() } else { external.clone() },
            "token_endpoint": issuer,
            "jwks_uri": if external_jwks { external } else { issuer.clone() },
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        });
        let handle = std::thread::spawn(move || {
            let responses = if external_jwks {
                vec![metadata]
            } else {
                vec![metadata, json!({"keys":[]})]
            };
            for body in responses {
                let start = std::time::Instant::now();
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(start.elapsed() < Duration::from_secs(5));
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("{e}"),
                    }
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                assert!(socket.read(&mut [0; 8192]).unwrap() > 0);
                let body = body.to_string();
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let result = adapter(&issuer).discover(tenant(), &config(&issuer)).await;
        assert!(matches!(
            result,
            Err(FederationError::Provider(ProviderFailure {
                reason: ProviderReason::EgressDenied,
                ..
            }))
        ));
        handle.join().unwrap();
        assert_eq!(
            forbidden.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[tokio::test]
async fn discovery_preserves_unavailable_and_protocol_failure() {
    for (status, body, unavailable) in [
        ("503 Service Unavailable", b"private error".to_vec(), true),
        ("200 OK", b"invalid json".to_vec(), false),
    ] {
        let (issuer, handle) = server(status, "", body);
        let error = adapter(&issuer)
            .discover(tenant(), &config(&issuer))
            .await
            .err()
            .unwrap();
        assert_eq!(
            error,
            failure(
                ProviderStage::Discovery,
                if unavailable {
                    ProviderReason::Unavailable
                } else {
                    ProviderReason::InvalidResponse
                }
            )
        );
        handle.join().unwrap();
    }
}

#[tokio::test]
async fn blocked_dns_resolution_never_connects() {
    use reqwest::dns::Resolve;
    let resolver = Resolver {
        host: "localhost".into(),
        addresses: vec!["192.0.2.0/24".parse().unwrap()],
    };
    assert!(
        resolver
            .resolve("localhost".parse().unwrap())
            .await
            .is_err()
    );
    assert!(
        resolver
            .resolve("other.test".parse().unwrap())
            .await
            .is_err()
    );
}

fn tenant() -> rss_request_context::TenantId {
    rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap()
}
