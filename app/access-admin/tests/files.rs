use access_admin::deliver_authorization;
use access_postgres::{AuthorityError, StorageFailure};
#[test]
fn uncertain_issuance_never_opens_a_file() {
    let file = std::env::temp_dir().join(format!("access-unconfirmed-{}", uuid::Uuid::new_v4()));
    assert!(
        deliver_authorization(
            &file,
            Err(AuthorityError::CommitUnknown(StorageFailure::Transient))
        )
        .is_err()
    );
    assert!(!file.exists());
}
#[test]
fn configuration_and_ca_reads_are_bounded() {
    use access_admin::read_public_file;
    let path = std::env::temp_dir().join(format!("access-input-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, [0_u8; 128]).unwrap();
    assert!(read_public_file(&path, 127).is_err());
    assert_eq!(read_public_file(&path, 128).unwrap().len(), 128);
    std::fs::remove_file(&path).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert!(read_public_file(&path, 16384).is_err());
    std::fs::remove_file(path).unwrap();
}
