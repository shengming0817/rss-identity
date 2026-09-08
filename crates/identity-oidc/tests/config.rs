use rss_identity_oidc::ProviderConfig;
#[test]
fn rejects_insecure_or_ambiguous_configuration() {
    for issuer in [
        "http://idp.example.test",
        "not a url",
        "https://user:secret@idp.example.test",
        "https://idp.example.test/#fragment",
    ] {
        assert!(
            ProviderConfig::new(
                issuer,
                "client",
                "secret",
                "https://product.example.test/auth/callback"
            )
            .is_err()
        );
    }
    assert!(
        ProviderConfig::new(
            "https://idp.example.test",
            "",
            "secret",
            "https://product.example.test/auth/callback"
        )
        .is_err()
    );
    assert!(
        ProviderConfig::new(
            "https://idp.example.test",
            "client",
            "secret",
            "http://product.example.test/auth/callback"
        )
        .is_err()
    );
    assert!(
        ProviderConfig::new(
            "https://idp.example.test",
            "client",
            "secret",
            "https://product.example.test/auth/callback"
        )
        .is_ok()
    );
}
