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

        redirect_uri: "http://127.0.0.1/callback".into(),
        scopes: vec!["openid".into()],
        claims: rss_identity_core::federation::ClaimMapping {
            department: None,
            email: None,
            groups: None,
        },
        jit: false,
    })
    .try_into()
    .unwrap()
}
fn adapter(issuer: &str) -> HttpOidc {
    HttpOidc::for_loopback_test(vec![TrustedAssuranceProfile {
        keycloak_totp: false,
        tenant: tenant(),
        issuer: issuer.into(),
        client_id: "client".into(),
    }])
    .unwrap()
}
fn transport(origin: &str) -> Transport {
    adapter(origin)
        .transport(
            tenant(),
            &config(origin),
            &rss_identity_core::federation::ProviderCredentials::new("fixture-secret".into(), None)
                .unwrap(),
        )
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
        let result = adapter(&issuer)
            .discover(
                tenant(),
                &config(&issuer),
                &rss_identity_core::federation::ProviderCredentials::new(
                    "fixture-secret".into(),
                    None,
                )
                .unwrap(),
            )
            .await;
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
            .discover(
                tenant(),
                &config(&issuer),
                &rss_identity_core::federation::ProviderCredentials::new(
                    "fixture-secret".into(),
                    None,
                )
                .unwrap(),
            )
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

fn tenant() -> rss_request_context::TenantId {
    rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap()
}

#[test]
fn signed_group_claim_presence_and_exact_values_are_distinct() {
    use rss_identity_core::groups::UpstreamGroups;
    use serde_json::json;
    assert!(matches!(
        mapped_groups(None, &json!({"groups":["ignored"]})).unwrap(),
        UpstreamGroups::NotConfigured
    ));
    for claims in [json!({}), json!({"groups":null})] {
        assert!(matches!(
            mapped_groups(Some("groups"), &claims).unwrap(),
            UpstreamGroups::Missing
        ));
    }
    assert_eq!(
        mapped_groups(Some("groups"), &json!({"groups":[]}))
            .unwrap()
            .values(),
        Some([].as_slice())
    );
    assert_eq!(
        mapped_groups(Some("groups"), &json!({"groups":["/a/b"," a ","/a/b"]}))
            .unwrap()
            .values(),
        Some([" a ".to_string(), "/a/b".to_string()].as_slice())
    );
    for value in [json!("group"), json!([null]), json!([1]), json!(["bad\n"])] {
        assert!(mapped_groups(Some("groups"), &json!({"groups":value})).is_err());
    }
}

#[tokio::test]
async fn production_dns_denial_prevents_connecting_to_loopback() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let settings: ProviderSettings = ProviderSettingsInput {
        issuer: format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        ),
        client_id: "fixture".into(),
        redirect_uri: "https://identity.example.test/api/v2/oidc/callback".into(),
        scopes: vec!["openid".into()],
        claims: ClaimMapping {
            department: None,
            email: None,
            groups: None,
        },
        jit: false,
    }
    .try_into()
    .unwrap();
    let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let credentials = ProviderCredentials::new("private-fixture".into(), None).unwrap();
    assert_eq!(
        HttpOidc::new(vec![])
            .unwrap()
            .test(tenant, &settings, &credentials)
            .await
            .unwrap_err(),
        failure(ProviderStage::Discovery, ProviderReason::EgressDenied)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}

#[test]
fn department_mapping_distinguishes_signed_null_missing_and_invalid_values() {
    use rss_identity_core::department::{DepartmentId, UpstreamDepartment};
    assert_eq!(
        mapped_department(None, &json!({"department_id":"ignored"})).unwrap(),
        UpstreamDepartment::NotConfigured
    );
    assert_eq!(
        mapped_department(Some("department_id"), &json!({})).unwrap(),
        UpstreamDepartment::Missing
    );
    assert_eq!(
        mapped_department(Some("department_id"), &json!({"department_id":null})).unwrap(),
        UpstreamDepartment::NoDepartment
    );
    assert_eq!(
        mapped_department(
            Some("department_id"),
            &json!({"department_id":"Engineering"})
        )
        .unwrap(),
        UpstreamDepartment::Present(DepartmentId::new("Engineering".into()).unwrap())
    );
    for value in [
        json!(""),
        json!(" bad"),
        json!("x".repeat(257)),
        json!([]),
        json!({}),
        json!(1),
        json!(true),
    ] {
        assert!(mapped_department(Some("department_id"), &json!({"department_id":value})).is_err());
    }
}

#[test]
fn signed_department_claims_preserve_null_and_reject_invalid_authentication() {
    let client = ClientId::new("client".into());
    let verifier = CoreIdTokenVerifier::new_confidential_client(
        client.clone(),
        ClientSecret::new("fixture-secret".into()),
        IssuerUrl::new("https://issuer.test".into()).unwrap(),
        CoreJsonWebKeySet::new(vec![]),
    )
    .set_allowed_algs(vec![CoreJwsSigningAlgorithm::HmacSha256]);
    for value in [json!(null), json!("dept-01"), json!([])] {
        for (field, bad, accepted) in [
            ("unused", json!(true), true),
            ("iss", json!("https://other.test"), false),
            ("aud", json!(["other"]), false),
            ("nonce", json!("other"), false),
            ("exp", json!(1), false),
        ] {
            let mut raw = json!({"iss":"https://issuer.test","sub":"subject","aud":["client"],"iat":1,"exp":4102444800_i64,"nonce":"nonce","department_id":value});
            raw[field] = bad;
            let claims: openidconnect::IdTokenClaims<Extra, openidconnect::core::CoreGenderClaim> =
                serde_json::from_value(raw).unwrap();
            for secret in ["fixture-secret", "wrong-secret"] {
                let token = MappedToken::new(
                    claims.clone(),
                    &CoreHmacKey::new(secret),
                    CoreJwsSigningAlgorithm::HmacSha256,
                    None,
                    None,
                )
                .unwrap();
                let verified = verify(&token, &verifier, &Nonce::new("nonce".into()), &client);
                assert_eq!(verified.is_ok(), accepted && secret == "fixture-secret");
                if let Ok(verified) = verified {
                    let mapped = mapped_department(
                        Some("department_id"),
                        &serde_json::to_value(verified).unwrap(),
                    );
                    match &value {
                        serde_json::Value::Null => assert_eq!(
                            mapped.unwrap(),
                            rss_identity_core::department::UpstreamDepartment::NoDepartment
                        ),
                        serde_json::Value::String(_) => assert!(matches!(
                            mapped.unwrap(),
                            rss_identity_core::department::UpstreamDepartment::Present(_)
                        )),
                        _ => assert!(mapped.is_err()),
                    }
                }
            }
        }
    }
}
