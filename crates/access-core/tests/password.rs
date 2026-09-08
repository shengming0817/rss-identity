use access_core::account::{LoginKey, Password, PasswordEncoding, PasswordKdf};
#[tokio::test]
async fn passwords_and_login_keys_are_bounded() {
    assert!(LoginKey::parse(" alice").is_err());
    assert!(LoginKey::parse("Ａlice").is_err());
    assert_eq!(LoginKey::parse("ALICE").unwrap().as_str(), "alice");
    assert!(Password::new("short".into()).is_err());
    let kdf = PasswordKdf::new();
    let hash = kdf
        .hash(Password::new("correct horse battery staple".into()).unwrap())
        .await
        .unwrap();
    assert!(
        kdf.verify(
            Password::new("correct horse battery staple".into()).unwrap(),
            hash.clone()
        )
        .await
        .unwrap()
    );
    assert!(
        !kdf.verify(
            Password::new("different horse battery staple".into()).unwrap(),
            hash
        )
        .await
        .unwrap()
    );
    assert!(kdf.verify(Password::new("correct horse battery staple".into()).unwrap(), PasswordEncoding::from_storage("$argon2id$v=19$m=999999999,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()).unwrap()).await.is_err());
}
