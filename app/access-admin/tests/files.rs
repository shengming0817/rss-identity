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

#[test]
fn password_files_are_private_regular_and_bounded() {
    use access_admin::read_secret;
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = std::env::temp_dir().join(format!("access-files-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("password");
    std::fs::write(&file, "a private password with spaces\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_secret(&file).unwrap().ends_with('\n'));
    let link = dir.join("link");
    symlink(&file, &link).unwrap();
    assert!(read_secret(&link).is_err());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(read_secret(&file).is_err());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&file, vec![b'x'; 4097]).unwrap();
    assert!(read_secret(&file).is_err());
    assert!(read_secret(&dir).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
