use super::*;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

async fn login_profile(app: &Router, p: &ProviderView, binding: char) -> anyhow::Result<String> {
    let browser = format!(
        "__Host-identity-oidc-browser={}A",
        binding.to_string().repeat(42)
    );
    let url = begin(app, p, &browser, None, None, false).await?;
    let cb = authorize(&url, "alice").await?;
    let result = callback(app, &cb, &browser).await?;
    anyhow::ensure!(
        result.status() == StatusCode::SEE_OTHER,
        "login did not commit"
    );
    Ok(cookie(&result))
}
async fn profile_http(app: &Router, cookie: &str) -> anyhow::Result<Value> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/identity/tenants/{A}/profile"))
                .header("cookie", cookie)
                .body(Body::empty())?,
        )
        .await?;
    anyhow::ensure!(response.status() == StatusCode::OK, "profile read failed");
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 131072).await?,
    )?)
}
#[tokio::test]
#[ignore = "requires make test-federated"]
async fn real_profile_login_updates_and_removes_values() -> anyhow::Result<()> {
    let admin = keycloak_support::StaffMembership::load().await?;
    let original = admin.user_profile().await?;
    let result = AssertUnwindSafe(async {
        let f = Fixture::new().await?;
        f.bootstrap().await?;
        let service = service(&f, Arc::new(fixture_transport(false)?));
        let provider = provider(&f, &service).await?;
        let mut settings = provider.settings.input();
        settings.claims.profile.extensions_claim = Some("attributes".into());
        let provider = service
            .update_provider(
                federation_support::actor(&f).await?,
                provider.id,
                provider.version,
                settings.try_into()?,
                credentials(true)?,
                deadline(),
            )
            .await?;
        let app = app(&service);
        let first = login_profile(&app, &provider, 'P').await?;
        let first_value = profile_http(&app, &first).await?;
        assert_eq!(first_value["status"], "available");
        assert_eq!(
            first_value["profile"]["extensions"]["value"]["employeeNumber"],
            "E1001"
        );
        assert_eq!(
            first_value["profile"]["extensions"]["value"]["remote"],
            false
        );
        let mut changed = original.clone();
        changed["firstName"] = json!("Updated");
        changed["email"] = json!("updated@example.test");
        changed["attributes"]["profile_attributes"] = json!([serde_json::to_string(
            &json!({"employeeNumber":"E2002","cost":0})
        )?]);
        admin.set_user_profile(&changed).await?;
        let second = login_profile(&app, &provider, 'Q').await?;
        let second_value = profile_http(&app, &second).await?;
        assert_eq!(
            second_value["profile"]["email"]["value"],
            "updated@example.test"
        );
        assert_eq!(
            second_value["profile"]["extensions"]["value"]["employeeNumber"],
            "E2002"
        );
        assert_eq!(second_value["profile"]["extensions"]["value"]["cost"], 0);
        assert!(
            second_value["profile"]["extensions"]["value"]
                .get("remote")
                .is_none()
        );
        assert_eq!(profile_http(&app, &first).await?["status"], "unavailable");
        changed["attributes"]
            .as_object_mut()
            .unwrap()
            .remove("profile_attributes");
        admin.set_user_profile(&changed).await?;
        let third = login_profile(&app, &provider, 'R').await?;
        assert_eq!(
            profile_http(&app, &third).await?["profile"]["extensions"]["status"],
            "missing"
        );
        f.close().await;
        Ok::<_, anyhow::Error>(())
    })
    .catch_unwind()
    .await;
    let restored = admin.set_user_profile(&original).await;
    match result {
        Ok(result) => {
            restored?;
            result
        }
        Err(panic) => {
            if restored.is_err() {
                eprintln!("fixture profile restoration failed");
            }
            std::panic::resume_unwind(panic)
        }
    }
}
