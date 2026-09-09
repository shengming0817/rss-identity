//! Fixed ingress trust. Accepted TCP peer remains separate from client attribution.
use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use rss_identity_http_axum::ClientAddress;
use std::net::{IpAddr, SocketAddr};
#[derive(Clone)]
pub struct Ingress {
    pub public: IpAddr,
    pub private: IpAddr,
}
impl Ingress {
    pub fn client(
        &self,
        peer: IpAddr,
        path: &str,
        headers: &axum::http::HeaderMap,
    ) -> Option<IpAddr> {
        let internal = path.starts_with("/internal/");
        if (internal && (peer != self.private || path != "/internal/v1/identity/validate"))
            || (!internal && peer != self.public)
        {
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
pub async fn trusted(State(ingress): State<Ingress>, mut request: Request, next: Next) -> Response {
    let source = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .and_then(|p| ingress.client(p.0.ip(), request.uri().path(), request.headers()));
    let Some(source) = source else {
        return StatusCode::FORBIDDEN.into_response();
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_trusted_peer_can_supply_one_ip() {
        let i = Ingress {
            public: "10.0.0.2".parse().unwrap(),
            private: "10.0.0.3".parse().unwrap(),
        };
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.5".parse().unwrap());
        assert_eq!(
            i.client(i.public, "/api/v1/login", &h),
            Some("203.0.113.5".parse().unwrap())
        );
        assert!(i.client("10.0.0.4".parse().unwrap(), "/api", &h).is_none());
        assert!(
            i.client(i.public, "/internal/v1/identity/validate", &h)
                .is_none()
        );
        assert!(i.client(i.private, "/api", &h).is_none());
        assert!(
            i.client(i.private, "/internal/v1/identity/validate", &h)
                .is_some()
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
