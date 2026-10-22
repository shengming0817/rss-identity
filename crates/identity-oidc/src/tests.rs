use super::*;
use serde_json::json;
use std::{
    io::{Read, Write},
    net::TcpListener,
};

fn token_metadata() -> Metadata {
    let metadata:Metadata=serde_json::from_value(json!({"issuer":"https://issuer.test","authorization_endpoint":"https://issuer.test/auth","jwks_uri":"https://issuer.test/keys","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]})).unwrap();
    metadata.set_jwks(serde_json::from_value(json!({"keys":[serde_json::from_str::<serde_json::Value>(include_str!("../tests/fixtures/entra-a.json")).unwrap()]})).unwrap())
}
fn signed_token(claims: &serde_json::Value, valid_key: bool) -> String {
    let key = if valid_key {
        include_bytes!("../tests/fixtures/entra-a.der").as_slice()
    } else {
        include_bytes!("../tests/fixtures/entra-b.der").as_slice()
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("entra-a".into());
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_rsa_der(key),
    )
    .unwrap()
}
#[test]
fn signed_claims_bind_authorized_party_issuer_audience_and_expiry() {
    let metadata = token_metadata();
    for (field, value, valid) in [
        ("azp", json!(null), true),
        ("azp", json!("client"), true),
        ("azp", json!("other"), false),
        ("iss", json!("https://other.test"), false),
        ("aud", json!(["other"]), false),
        ("aud", json!(["client", "other"]), false),
        ("nonce", json!("wrong"), false),
        ("exp", json!(1), false),
        ("iat", json!(4102444800_i64), false),
    ] {
        let mut claims = json!({"iss":"https://issuer.test","sub":"subject","aud":["client"],"iat":1,"exp":4102444800_i64,"nonce":"nonce"});
        claims[field] = value;
        for key in [true, false] {
            assert_eq!(
                profile_token::verify(
                    &signed_token(&claims, key),
                    &metadata,
                    &Nonce::new("nonce".into()),
                    "client",
                    "fixture-secret"
                )
                .is_ok(),
                valid && key,
                "{field}"
            );
        }
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
            subject: rss_identity_core::entra::SubjectMapping::Oidc,
            department_snapshot: None,
            profile: rss_identity_core::profile::ProfileSettings::default(),
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
        redirect_uri: "https://identity.example.test/api/v1/identity/oidc/callback".into(),
        scopes: vec!["openid".into()],
        claims: ClaimMapping {
            subject: rss_identity_core::entra::SubjectMapping::Oidc,
            department_snapshot: None,
            profile: rss_identity_core::profile::ProfileSettings::default(),
            groups: None,
        },
        jit: false,
    }
    .try_into()
    .unwrap();
    let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let credentials = ProviderCredentials::new("private-fixture".into(), None).unwrap();
    assert_eq!(
        HttpOidc::new(vec![], vec![])
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

fn department_assertion() -> serde_json::Value {
    json!({"version":1,"sourceRevision":"r1","nodes":[{"id":"dept-01","displayName":"Engineering","parentId":null}],"memberships":["dept-01"]})
}
#[test]
fn department_mapping_withholds_missing_or_invalid_assertions() {
    use rss_identity_core::department::UpstreamDepartmentSnapshot;
    assert_eq!(
        mapped_department(None, &json!({"organization":"ignored"})),
        UpstreamDepartmentSnapshot::NotConfigured
    );
    assert_eq!(
        mapped_department(Some("organization"), &json!({})),
        UpstreamDepartmentSnapshot::Missing
    );
    for value in [
        json!(null),
        json!("dept-01"),
        json!([]),
        json!({}),
        json!(1),
        json!(true),
    ] {
        assert_eq!(
            mapped_department(Some("organization"), &json!({"organization":value})),
            UpstreamDepartmentSnapshot::Invalid
        );
    }
    for members in [json!(["dept-01"]), json!([])] {
        let mut value = department_assertion();
        value["memberships"] = members;
        assert!(matches!(
            mapped_department(Some("organization"), &json!({"organization":value})),
            UpstreamDepartmentSnapshot::Present(_)
        ));
    }
}

#[test]
fn signed_snapshot_withholds_invalid_fact_but_never_bypasses_token_verification() {
    let metadata = token_metadata();
    for value in [json!(null), department_assertion(), json!([])] {
        for (field, bad, accepted) in [
            ("unused", json!(true), true),
            ("iss", json!("https://other.test"), false),
            ("aud", json!(["other"]), false),
            ("nonce", json!("other"), false),
            ("exp", json!(1), false),
        ] {
            let mut raw = json!({"iss":"https://issuer.test","sub":"subject","aud":["client"],"iat":1,"exp":4102444800_i64,"nonce":"nonce","organization_snapshot":value});
            raw[field] = bad;
            for key in [true, false] {
                let verified = profile_token::verify(
                    &signed_token(&raw, key),
                    &metadata,
                    &Nonce::new("nonce".into()),
                    "client",
                    "fixture-secret",
                );
                assert_eq!(verified.is_ok(), accepted && key);
                if let Ok(claims) = verified {
                    assert_eq!(
                        matches!(
                            mapped_department(
                                Some("organization_snapshot"),
                                &serde_json::to_value(claims).unwrap()
                            ),
                            rss_identity_core::department::UpstreamDepartmentSnapshot::Present(_)
                        ),
                        value.is_object()
                    );
                }
            }
        }
    }
}
#[test]
fn malformed_profile_is_independent_of_verified_security_claims() {
    let metadata = token_metadata();
    let raw = json!({"iss":"https://issuer.test","sub":"subject","aud":["client"],"iat":1,"exp":4102444800_i64,"nonce":"nonce","email":42,"name":false,"email_verified":"true","attributes":{"mfa":true,"number":0,"remote":false}});
    let claims = profile_token::verify(
        &signed_token(&raw, true),
        &metadata,
        &Nonce::new("nonce".into()),
        "client",
        "fixture-secret",
    )
    .unwrap();
    let settings = rss_identity_core::profile::ProfileSettings {
        extensions_claim: Some("attributes".into()),
        max_age_seconds: 14400,
    };
    let profile = rss_identity_core::profile::Profile::from_claims(&claims.ordinary, &settings);
    assert!(matches!(
        profile.email,
        rss_identity_core::profile::Attribute::Invalid
    ));
    assert!(matches!(
        profile.email_verified,
        rss_identity_core::profile::Attribute::Invalid
    ));
    assert_eq!(
        profile.extensions.value().unwrap().object()["remote"],
        false
    );
    assert!(
        profile_token::verify(
            &signed_token(&raw, false),
            &metadata,
            &Nonce::new("nonce".into()),
            "client",
            "fixture-secret"
        )
        .is_err()
    );
}

#[test]
fn entra_browser_requires_canonical_subject_without_fallback() {
    use rss_identity_core::entra::{ExternalSubject, SubjectMapping};
    let tenant = uuid::Uuid::new_v4();
    let user = uuid::Uuid::new_v4();
    let mapping = SubjectMapping::Entra { tenant };
    let claims = serde_json::json!({"tid":tenant,"oid":user,"email":"same@example.test"});
    let expected = ExternalSubject::Entra { tenant, user };
    assert_eq!(
        super::mapped_subject(&mapping, "pairwise-one", &claims).unwrap(),
        expected
    );
    assert_eq!(
        super::mapped_subject(&mapping, "pairwise-two", &claims).unwrap(),
        expected
    );
    for invalid in [
        serde_json::json!({"tid":tenant,"email":"same@example.test"}),
        serde_json::json!({"oid":user}),
        serde_json::json!({"tid":uuid::Uuid::new_v4(),"oid":user}),
        serde_json::json!({"tid":tenant,"oid":uuid::Uuid::nil()}),
    ] {
        assert!(super::mapped_subject(&mapping, "valid-pairwise-sub", &invalid).is_err());
    }
}
