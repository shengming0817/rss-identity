#[cfg(test)]
mod host;
#[cfg(test)]
mod tests {
    use super::host::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use rss_identity_core::groups::UnavailableReason;
    use rss_identity_postgres::VerifiedGroups;
    use tower::ServiceExt;
    #[tokio::test]
    async fn local_host_authentication_and_router_composition() -> anyhow::Result<()> {
        let host = Host::start().await?;
        let first = host.login().await?;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let inspected = host
            .authority
            .inspect_session(host.key.tenant, secret(&first), deadline())
            .await?;
        assert_eq!(
            inspected.view().idle_expires_at,
            first.view().idle_expires_at
        );
        let actor = host.actor(&first).await?;
        assert!(actor.view().idle_expires_at > first.view().idle_expires_at);
        assert_eq!(
            actor.view().absolute_expires_at,
            first.view().absolute_expires_at
        );
        assert_eq!(actor.account(), host.key);
        assert!(matches!(
            actor.groups()?,
            VerifiedGroups::Unavailable(UnavailableReason::LocalIdentity)
        ));
        let member = host
            .authority
            .create_local_account(
                host.actor(&first).await?,
                rss_identity_core::account::LoginKey::parse("member")?,
                password(),
                deadline(),
            )
            .await?;
        host.authority
            .set_account_enabled(host.actor(&first).await?, member.key(), false, deadline())
            .await?;
        assert!(
            host.authority
                .login_local(
                    host.key.tenant,
                    rss_identity_core::account::LoginKey::parse("member")?,
                    password(),
                    rss_identity_postgres::AttemptSource::parse("consumer")?,
                    None,
                    deadline()
                )
                .await
                .is_err()
        );
        let routes = rss_identity_http_axum::router(
            host.authority.clone(),
            rss_identity_http_axum::HttpConfig::new(
                "https://local.example.test",
                std::time::Duration::from_secs(10),
            )?,
        )?;
        let login_request = || {
            Request::builder()
                .method("POST")
                .uri(format!("/api/v2/tenants/{}/login", host.key.tenant))
                .header("origin", "https://local.example.test")
                .header("x-identity-request", "1")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "203.0.113.99")
                .extension(axum::extract::ConnectInfo(
                    "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .body(Body::from(format!(
                    r#"{{"login":"operator","password":"{PASSWORD}"}}"#
                )))
                .unwrap()
        };
        let response = routes.clone().oneshot(login_request()).await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        // The accepted connection is host-owned; a browser's forwarded header is ignored.
        let routes = routes.layer(axum::middleware::from_fn(
            |axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
             mut request: axum::extract::Request,
             next: axum::middleware::Next| async move {
                request
                    .extensions_mut()
                    .insert(rss_identity_http_axum::ClientAddress(peer.ip()));
                next.run(request).await
            },
        ));
        let response = routes.clone().oneshot(login_request()).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("set-cookie"));
        let body = String::from_utf8(
            axum::body::to_bytes(response.into_body(), 4096)
                .await?
                .to_vec(),
        )?;
        assert!(body.contains("\"principalId\""));
        assert!(body.contains("\"csrfToken\""));
        assert!(!body.contains("principal_id"));
        // Local auth has no OIDC router, keys, state signer, reference process or network service.
        let response = routes
            .oneshot(
                Request::builder()
                    .uri("/api/v2/oidc/callback")
                    .extension(axum::extract::ConnectInfo(
                        "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                    ))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let next = host
            .authority
            .refresh_session(host.key.tenant, secret(&first), deadline())
            .await?;
        assert_eq!(first.view().auth_time, next.view().auth_time);
        assert_eq!(
            first.view().absolute_expires_at,
            next.view().absolute_expires_at
        );
        assert!(host.actor(&first).await.is_err());
        host.authority
            .revoke_all_sessions(host.actor(&next).await?, deadline())
            .await?;
        assert!(host.actor(&next).await.is_err());
        host.maintenance
            .recover_local_password(host.key, password(), deadline())
            .await?;
        let fresh = host.login().await?;
        assert_eq!(host.actor(&fresh).await?.account(), host.key);
        host.runtime.close().await;
        assert!(host.actor(&fresh).await.is_err());
        host.close().await;
        Ok(())
    }
}
