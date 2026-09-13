use crate::{Client, Error, Reply};
use rss_identity_core::{cli::CliLoginBinding, federation::random_secret};
use std::{
    process::{Command, Stdio},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use zeroize::Zeroizing;

pub(super) async fn login(client: &Client, provider: &str) -> Result<Reply, Error> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|_| Error::Input)?;
    let address = listener.local_addr().map_err(|_| Error::Input)?;
    let verifier = random_secret().map_err(|_| Error::Unavailable)?;
    let state = random_secret().map_err(|_| Error::Unavailable)?;
    let redirect = format!("http://{address}/callback");
    let binding = CliLoginBinding::new(
        redirect.clone(),
        CliLoginBinding::challenge_for(&verifier),
        state.to_string(),
    )
    .map_err(|_| Error::Input)?;
    let mut authorize = url::Url::parse(&format!(
        "{}/api/v1/cli/sso/authorize",
        client.config.origin
    ))
    .map_err(|_| Error::Input)?;
    authorize
        .query_pairs_mut()
        .append_pair("provider_id", provider)
        .append_pair("redirect_uri", binding.redirect_uri())
        .append_pair("code_challenge", binding.challenge())
        .append_pair("state", binding.state());
    let opener = if cfg!(target_os = "macos") {
        "/usr/bin/open"
    } else {
        "/usr/bin/xdg-open"
    };
    // Only the public local start URL enters process arguments, never state or credentials.
    let mut child = Command::new(opener)
        .arg(format!("http://{address}/start"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::Unavailable)?;
    let wait = async {
        for _ in 0..64 {
            let (mut socket, peer) = listener.accept().await.map_err(|_| Error::Unavailable)?;
            if !peer.ip().is_loopback() {
                continue;
            }
            let mut bytes = Zeroizing::new(Vec::new());
            let read = tokio::time::timeout(Duration::from_secs(5), async {
                let mut part = [0; 1024];
                while bytes.len() < 8192 && !bytes.windows(4).any(|v| v == b"\r\n\r\n") {
                    let n = socket.read(&mut part).await?;
                    if n == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&part[..n]);
                }
                Ok::<_, std::io::Error>(())
            })
            .await;
            if !matches!(read, Ok(Ok(()))) {
                continue;
            }
            let text = match std::str::from_utf8(&bytes) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let mut lines = text.split("\r\n");
            let Some(first) = lines.next() else { continue };
            let parts: Vec<_> = first.split(' ').collect();
            if parts.len() != 3 || parts[0] != "GET" {
                continue;
            }
            let hosts: Vec<_> = lines
                .filter_map(|v| v.split_once(':'))
                .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.trim())
                .collect();
            if hosts != [address.to_string().as_str()] {
                continue;
            }
            if parts[1] == "/start" {
                let response = format!(
                    "HTTP/1.1 303 See Other\r\nLocation: {authorize}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = socket.write_all(response.as_bytes()).await;
                continue;
            }
            let u = match url::Url::parse(&format!("http://{address}{}", parts[1])) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if u.path() != "/callback" {
                continue;
            }
            let pairs: Vec<_> = u.query_pairs().collect();
            let states: Vec<_> = pairs.iter().filter(|(k, _)| k == "state").collect();
            if states.len() != 1 || !bool::from(states[0].1.as_bytes().ct_eq(state.as_bytes())) {
                continue;
            }
            let codes: Vec<_> = pairs.iter().filter(|(k, _)| k == "code").collect();
            let errors: Vec<_> = pairs.iter().filter(|(k, _)| k == "error").collect();
            if pairs.len() != 2 || codes.len() + errors.len() != 1 {
                continue;
            }
            let body = "<!doctype html><title>Identity CLI</title><p>Return to your terminal.</p>";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            if !errors.is_empty() {
                return Err(Error::Authentication);
            }
            return Ok(Zeroizing::new(codes[0].1.to_string()));
        }
        Err(Error::Authentication)
    };
    let result = tokio::select! {r=tokio::time::timeout(Duration::from_secs(300),wait)=>r.map_err(|_|Error::Authentication)?,_=tokio::signal::ctrl_c()=>Err(Error::Authentication)};
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let code = result?;
    client.request(reqwest::Method::POST,"/api/v1/cli/sso/exchange",None,Some(serde_json::json!({"code":code.as_str(),"verifier":verifier.as_str(),"redirect_uri":redirect})),false).await
}
