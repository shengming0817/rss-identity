//! Fixed ingress trust. Accepted TCP peer remains separate from client attribution.
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use rss_identity_service_http::ClientAddress;
use std::net::{IpAddr, SocketAddr};
#[derive(Clone)]
pub struct Ingress {
    pub public: IpAddr,
}
impl Ingress {
    pub fn client(
        &self,
        peer: IpAddr,
        path: &str,
        headers: &axum::http::HeaderMap,
    ) -> Option<IpAddr> {
        if peer != self.public || path.starts_with("/internal/") {
            return None;
        }
        let mut values = headers.get_all("x-forwarded-for").iter();
        let value = values.next()?.to_str().ok()?;
        if values.next().is_some() || value.trim() != value {
            return None;
        }
        value.parse().ok()
    }
}
#[derive(Clone, Copy)]
pub(crate) struct IngressRejected;

pub async fn trusted(State(ingress): State<Ingress>, mut request: Request, next: Next) -> Response {
    let source = request
        .extensions()
        .get::<rss_axum::AcceptedConnectionInfo<()>>()
        .and_then(|p| {
            ingress.client(
                p.socket_peer().ip(),
                request.uri().path(),
                request.headers(),
            )
        });
    let Some(source) = source else {
        return (axum::Extension(IngressRejected), StatusCode::FORBIDDEN).into_response();
    };
    for name in [
        "forwarded",
        "x-forwarded-for",
        "x-real-ip",
        "x-forwarded-host",
        "x-forwarded-proto",
    ] {
        request.headers_mut().remove(name);
    }
    request.extensions_mut().insert(ClientAddress(source));
    next.run(request).await
}
/// Loopback-only health probe sharing one explicit deadline; no config or secret access.
pub fn probe(address: SocketAddr, cutoff: rss_request_context::Deadline) -> bool {
    use std::io::{Read, Write};
    use std::time::Instant;
    if !address.ip().is_loopback() {
        return false;
    }
    let remaining = || {
        cutoff
            .remaining(Instant::now())
            .filter(|left| !left.is_zero())
    };
    let Some(left) = remaining() else {
        return false;
    };
    let Ok(mut socket) = std::net::TcpStream::connect_timeout(&address, left) else {
        return false;
    };
    let Some(left) = remaining() else {
        return false;
    };
    if socket.set_write_timeout(Some(left)).is_err()
        || socket
            .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .is_err()
    {
        return false;
    }
    let mut line = Vec::new();
    while line.len() < 128 && !line.ends_with(b"\r\n") {
        let Some(left) = remaining() else {
            return false;
        };
        if socket.set_read_timeout(Some(left)).is_err() {
            return false;
        }
        let mut byte = [0];
        if socket.read_exact(&mut byte).is_err() {
            return false;
        }
        line.push(byte[0]);
    }
    line.starts_with(b"HTTP/1.1 200 ") || line.starts_with(b"HTTP/1.0 200 ")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_trusted_peer_can_supply_one_ip() {
        let i = Ingress {
            public: "10.0.0.2".parse().unwrap(),
        };
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.5".parse().unwrap());
        assert_eq!(
            i.client(i.public, "/api/v1/identity/login", &h),
            Some("203.0.113.5".parse().unwrap())
        );
        assert!(i.client("10.0.0.4".parse().unwrap(), "/api", &h).is_none());
        assert!(
            i.client(i.public, "/internal/v1/identity/validate", &h)
                .is_none()
        );
        for bad in [
            "203.0.113.5, 127.0.0.1",
            " 203.0.113.5",
            "203.0.113.5:80",
            "",
        ] {
            h.insert("x-forwarded-for", bad.parse().unwrap());
            assert!(i.client(i.public, "/api", &h).is_none());
        }
        h.insert("x-forwarded-for", "203.0.113.5".parse().unwrap());
        h.append("x-forwarded-for", "127.0.0.1".parse().unwrap());
        assert!(i.client(i.public, "/api", &h).is_none());
    }
}
