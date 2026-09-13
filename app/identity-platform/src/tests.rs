use super::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::{PermissionsExt, symlink},
};
fn directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!("identity-cli-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}
fn session(origin: &str) -> Session {
    Session {
        version: 1,
        origin: origin.into(),
        system_domain_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
        cookie: "a".repeat(64),
        csrf_token: "b".repeat(64),
        identity: Identity {
            principal_id: uuid::Uuid::new_v4().to_string(),
            administrator: false,
            platform_administrator: true,
            has_local_password: true,
        },
        session: SessionInfo {
            id: uuid::Uuid::new_v4().to_string(),
            auth_time: 1,
            idle_expires_at: 900,
            absolute_expires_at: 14400,
        },
        logout_pending: false,
    }
}
fn mock(responses: Vec<Option<&'static str>>) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let thread = std::thread::spawn(move || {
        let mut paths = Vec::new();
        for response in responses {
            let until = std::time::Instant::now() + Duration::from_secs(10);
            let mut socket = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < until);
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = [0; 8192];
            let n = socket.read(&mut bytes).unwrap();
            paths.push(
                String::from_utf8_lossy(&bytes[..n])
                    .lines()
                    .next()
                    .unwrap()
                    .to_owned(),
            );
            if let Some(body) = response {
                let r = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(r.as_bytes()).unwrap();
            }
        }
        paths
    });
    (origin, thread)
}
fn client(origin: String, dir: PathBuf) -> Client {
    Client::new(Config {
        format_version: 1,
        origin,
        system_domain_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
        session_dir: dir,
        ca_file: None,
        request_seconds: 2,
    })
    .unwrap()
}
#[test]
fn private_store_locks_atomically_and_rejects_symlinks() {
    let dir = directory();
    let store = store::Store::lock(&dir).unwrap();
    assert!(matches!(store::Store::lock(&dir), Err(Error::Busy)));
    let mut s = session("https://identity.test");
    store.save(&s).unwrap();
    assert_eq!(store.load().unwrap().unwrap().cookie, s.cookie);
    s.cookie = "c".repeat(64);
    store.save(&s).unwrap();
    assert_eq!(store.load().unwrap().unwrap().cookie, s.cookie);
    assert_eq!(
        std::fs::metadata(dir.join("session.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    store.clear().unwrap();
    let file = dir.join("secret");
    std::fs::write(&file, "private-password").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&file, dir.join("session.json")).unwrap();
    assert!(store.load().is_err());
    drop(store);
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn lost_write_response_is_unknown_and_never_retried() {
    let dir = directory();
    let (origin, thread) = mock(vec![None]);
    let client = client(origin, dir.clone());
    let s = session(&client.config.origin);
    assert!(matches!(
        client
            .request(
                Method::POST,
                "/api/v1/platform/tenants",
                Some(&s),
                Some(json!({"password":"synthetic-secret"})),
                true
            )
            .await,
        Err(Error::Unknown)
    ));
    assert_eq!(
        thread.join().unwrap(),
        ["POST /api/v1/platform/tenants HTTP/1.1"]
    );
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn refresh_failure_discards_local_session_before_any_business_write() {
    let dir = directory();
    let (origin, thread) = mock(vec![Some("{}"), None]);
    let client = client(origin, dir.clone());
    let store = store::Store::lock(&dir).unwrap();
    store.save(&session(&client.config.origin)).unwrap();
    assert!(matches!(
        client.active(&store).await,
        Err(Error::Authentication)
    ));
    assert!(store.load().unwrap().is_none());
    let paths = thread.join().unwrap();
    assert_eq!(paths.len(), 2);
    assert!(paths[1].contains("/session/refresh"));
    drop(store);
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn uncertain_logout_blocks_all_business_use() {
    let dir = directory();
    let (origin, thread) = mock(vec![Some("{}"), None]);
    let client = client(origin, dir.clone());
    let store = store::Store::lock(&dir).unwrap();
    let s = session(&client.config.origin);
    store.save(&s).unwrap();
    assert!(matches!(
        client.logout(&store, s).await,
        Err(Error::LogoutPending)
    ));
    assert!(store.load().unwrap().unwrap().logout_pending);
    assert!(matches!(
        client.active(&store).await,
        Err(Error::LogoutPending)
    ));
    assert_eq!(thread.join().unwrap().len(), 2);
    drop(store);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn public_trust_files_are_readable_but_not_writable_by_other_users() {
    let dir = directory();
    let file = dir.join("public.json");
    std::fs::write(&file, b"{}").unwrap();
    for mode in [0o644, 0o444, 0o600] {
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(store::public(&file, 100).unwrap(), b"{}");
    }
    for mode in [0o664, 0o646, 0o666] {
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(store::public(&file, 100), Err(Error::Input)));
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn response_additions_do_not_change_the_closed_session_file() {
    let dir = directory();
    let client = client("https://identity.test".into(), dir.clone());
    let s = session(&client.config.origin);
    let reply = Reply {
        status: StatusCode::OK,
        cookie: Some(Zeroizing::new("a".repeat(64))),
        value: json!({"identity":{"principal_id":s.identity.principal_id,"administrator":false,"platform_administrator":true,"has_local_password":true,"display_name":"New optional field"},"session":{"id":s.session.id,"auth_time":1,"idle_expires_at":900,"absolute_expires_at":14400,"optional":42},"csrf_token":"b".repeat(64),"added":true}),
    };
    let received = client.issued(reply).unwrap();
    let store = store::Store::lock(&dir).unwrap();
    store.save(&received).unwrap();
    let mut data: Value =
        serde_json::from_slice(&std::fs::read(dir.join("session.json")).unwrap()).unwrap();
    data["identity"]["unknown"] = json!(true);
    std::fs::write(dir.join("session.json"), serde_json::to_vec(&data).unwrap()).unwrap();
    assert!(store.load().is_err());
    drop(store);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn closed_server_rejections_remain_distinguishable_without_raw_error_text() {
    for (status, code) in [
        (400, "invalid_platform_request"),
        (409, "platform_conflict"),
        (409, "tenant_limit_reached"),
        (429, "rate_limited"),
    ] {
        let r = Reply {
            status: StatusCode::from_u16(status).unwrap(),
            cookie: None,
            value: json!({"code":code,"message":"private-provider-marker"}),
        };
        let error = Client::classify(&r, true);
        assert_eq!(error.exit_code(), 11);
        assert_eq!(error.to_string(), code);
        assert!(!format!("{error:?}").contains("private-provider-marker"));
    }
    let r = Reply {
        status: StatusCode::CONFLICT,
        cookie: None,
        value: json!({"code":"private-provider-marker"}),
    };
    let error = Client::classify(&r, true);
    assert_eq!(error.exit_code(), 11);
    assert!(!error.to_string().contains("private-provider-marker"));
}
