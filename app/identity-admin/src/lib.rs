//! Local secret-file boundary; there is no HTTP server or alternative session protocol.
use rss_identity_postgres::AuthorityError;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{fs::OpenOptions, io::Read, path::Path};
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
