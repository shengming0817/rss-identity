use crate::{Error, Session};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

fn validate(file: &File, mode: u32, limit: u64) -> Result<(), Error> {
    let m = file.metadata().map_err(|_| Error::Input)?;
    if !m.is_file()
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.permissions().mode() & 0o777 != mode
        || m.len() > limit
    {
        return Err(Error::Input);
    }
    Ok(())
}
pub fn secret(path: &Path) -> Result<Zeroizing<String>, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::Input)?;
    validate(&file, 0o600, 4096)?;
    let mut value = Zeroizing::new(String::new());
    file.take(4097)
        .read_to_string(&mut value)
        .map_err(|_| Error::Input)?;
    if value.is_empty() || value.len() > 4096 {
        return Err(Error::Input);
    }
    Ok(value)
}
pub fn public(path: &Path, limit: u64) -> Result<Vec<u8>, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::Input)?;
    let m = file.metadata().map_err(|_| Error::Input)?;
    if !m.is_file()
        || m.len() > limit
        || (m.uid() != rustix::process::geteuid().as_raw() && m.uid() != 0)
        || m.permissions().mode() & 0o022 != 0
    {
        return Err(Error::Input);
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Input)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Input);
    }
    Ok(bytes)
}
/// The lock is held through refresh, persistence, and the requested operation.
pub struct Store {
    dir: PathBuf,
    _lock: File,
}
impl Store {
    pub fn lock(dir: &Path) -> Result<Self, Error> {
        if !dir.is_absolute() {
            return Err(Error::Input);
        }
        if !dir.exists() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .map_err(|_| Error::Input)?;
        }
        let m = std::fs::symlink_metadata(dir).map_err(|_| Error::Input)?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || m.uid() != rustix::process::geteuid().as_raw()
            || m.permissions().mode() & 0o777 != 0o700
        {
            return Err(Error::Input);
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(dir.join("session.lock"))
            .map_err(|_| Error::Input)?;
        validate(&lock, 0o600, 0)?;
        lock.try_lock().map_err(|_| Error::Busy)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            _lock: lock,
        })
    }
    pub fn load(&self) -> Result<Option<Session>, Error> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.dir.join("session.json"))
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Input),
        };
        validate(&file, 0o600, 16384)?;
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(16385)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Input)?;
        let session: Session = serde_json::from_slice(&bytes).map_err(|_| Error::Input)?;
        // Network responses may add fields; the on-disk version remains a closed format.
        let mut input: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| Error::Input)?;
        let mut canonical = serde_json::to_value(&session).map_err(|_| Error::Input)?;
        let exact = input == canonical;
        crate::wipe(&mut input);
        crate::wipe(&mut canonical);
        if !exact {
            return Err(Error::Input);
        }
        Ok(Some(session))
    }
    pub fn save(&self, value: &Session) -> Result<(), Error> {
        let path = self
            .dir
            .join(format!("session-{}.tmp", uuid::Uuid::new_v4().simple()));
        let result = (|| {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)
                .map_err(|_| Error::Input)?;
            let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::Input)?);
            f.write_all(&bytes).map_err(|_| Error::Input)?;
            f.sync_all().map_err(|_| Error::Input)?;
            std::fs::rename(&path, self.dir.join("session.json")).map_err(|_| Error::Input)?;
            self.sync()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(path);
        }
        result
    }
    fn sync(&self) -> Result<(), Error> {
        File::open(&self.dir)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Input)
    }
    pub fn clear(&self) -> Result<(), Error> {
        match std::fs::remove_file(self.dir.join("session.json")) {
            Ok(()) => self.sync(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Error::Input),
        }
    }
}
use std::os::unix::fs::DirBuilderExt;
