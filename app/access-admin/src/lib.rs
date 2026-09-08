//! Local secret-file boundary; there is no HTTP server or alternative session protocol.
use access_postgres::{AuthorityError, IssuedAuthorization};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("unknown command; use --help")]
    UnknownCommand,
    #[error("wrong number of arguments; use --help")]
    Arguments,
    #[error("invalid configuration JSON or field shape")]
    Json,
    #[error("invalid tenant_id")]
    Tenant,
    #[error("invalid storage identity")]
    StorageIdentity,
    #[error("invalid storage_tenant_epoch")]
    StorageEpoch,
    #[error("invalid account role; expected member, admin or emergency")]
    Role,
    #[error("invalid principal identifier")]
    Principal,
    #[error("invalid login key")]
    Login,
    #[error("invalid password format")]
    Password,
    #[error("invalid operation budget")]
    Budget,
    #[error("configuration file unavailable or unsafe")]
    Configuration,
    #[error("CA file unavailable or unsafe")]
    Ca,
    #[error("secret file unavailable or unsafe")]
    File,
    #[error("database connection unavailable")]
    Connection,
    #[error(transparent)]
    Authority(#[from] AuthorityError),
}
/// Require a regular file inaccessible to group/other; do not follow a final symlink.
pub fn read_secret(path: &Path) -> Result<Zeroizing<String>, AdminError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| AdminError::File)?;
    let meta = file.metadata().map_err(|_| AdminError::File)?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 || meta.len() > 4096 {
        return Err(AdminError::File);
    }
    let mut contents = Zeroizing::new(String::new());
    file.take(4097)
        .read_to_string(&mut contents)
        .map_err(|_| AdminError::File)?;
    if contents.len() > 4096 {
        return Err(AdminError::File);
    }
    Ok(contents)
}
/// Bounded non-secret configuration/CA input; FIFO/devices and final symlinks are rejected.
pub fn read_public_file(path: &Path, limit: usize) -> Result<Vec<u8>, AdminError> {
    if limit > 1024 * 1024 {
        return Err(AdminError::Configuration);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| AdminError::File)?;
    let metadata = file.metadata().map_err(|_| AdminError::File)?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(AdminError::File);
    }
    let mut data = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| AdminError::File)?;
    if data.len() > limit {
        return Err(AdminError::File);
    }
    Ok(data)
}

/// No file is opened until the authority returns a confirmed authorization.
/// On delivery failure, explicitly reissue; never reconstruct/replay an uncertain issuance.
pub fn deliver_authorization(
    path: &Path,
    result: Result<IssuedAuthorization, AuthorityError>,
) -> Result<(), AdminError> {
    let issued = result?;
    write_secret(path, issued.into_secret())
}
fn write_secret(
    path: &Path,
    secret: access_postgres::AuthorizationSecret,
) -> Result<(), AdminError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| AdminError::File)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let result = (|| {
        file.write_all(secret.expose().as_bytes())?;
        file.sync_all()?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(path);
        return Err(AdminError::File);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn files_are_private_exclusive_and_do_not_follow_symlinks() {
        let dir = std::env::temp_dir().join(format!("access-files-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("secret");
        let secret = || access_postgres::AuthorizationSecret::parse("1".repeat(64)).unwrap();
        write_secret(&file, secret()).unwrap();
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write_secret(&file, secret()).is_err());
        assert_eq!(read_secret(&file).unwrap().as_str(), "1".repeat(64));
        let link = dir.join("link");
        symlink(&file, &link).unwrap();
        assert!(read_secret(&link).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_secret(&file).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
