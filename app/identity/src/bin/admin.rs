use rss_identity_app::{AppError, read_public_file, read_secret};
use rss_identity_core::account::AccountKey;
use rss_identity_core::{
    PrincipalId,
    account::{LoginKey, Password},
};
use rss_identity_postgres::*;
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    policy::{DeliveryBudget, OperationDeadline},
};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa, PgRuntime};
use serde::Deserialize;
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    identity_origin: DeploymentIdentity,
    host: String,
    port: u16,
    database: String,
    user: String,
    password_file: String,
    ca_file: String,
    tenant_id: String,
    storage_target: [u8; 16],
    storage_lineage: [u8; 16],
    storage_tenant_epoch: i64,
}
struct Timer;
impl Clock for Timer {
    fn now(&self) -> Instant {
        Instant::now()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, deadline: Deadline) {
        tokio::time::sleep(deadline.remaining(self.now()).unwrap_or_default()).await;
    }
}
fn password(path: &str) -> Result<Password, AppError> {
    Password::new(read_secret(Path::new(path))?.to_string()).map_err(|_| AppError::Password)
}
fn login(s: &str) -> Result<LoginKey, AppError> {
    LoginKey::parse(s).map_err(|_| AppError::Login)
}
fn key(tenant: TenantId, p: &str) -> Result<AccountKey, AppError> {
    Ok(AccountKey {
        tenant,
        principal: PrincipalId::parse(p).map_err(|_| AppError::Principal)?,
    })
}
fn budget() -> OperationDeadline {
    OperationDeadline::from_remaining(Duration::from_secs(30))
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), AppError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] || args == ["-h"] {
        println!("{}", usage());
        return Ok(());
    }
    if args.len() < 2 {
        return Err(AppError::Arguments);
    }
    let command = parse_command(&args[1..])?;
    let raw = read_public_file(Path::new(&args[0]), 16384).map_err(|_| AppError::Configuration)?;
    let config: Config = serde_json::from_slice(&raw).map_err(|_| AppError::Json)?;
    let tenant = TenantId::parse(&config.tenant_id).map_err(|_| AppError::Tenant)?;
    let ca = PgPrivateCa::from_pem(
        read_public_file(Path::new(&config.ca_file), 1024 * 1024).map_err(|_| AppError::Ca)?,
    )
    .map_err(|_| AppError::Ca)?;
    let pg = PgConfig::new(
        config.host,
        config.port,
        config.database,
        config.user,
        PgPassword::new(read_secret(Path::new(&config.password_file))?.to_string()),
        ca,
    );
    let binding = ExecutionBinding::new(
        StorageIdentity::new(config.storage_target, config.storage_lineage)
            .map_err(|_| AppError::StorageIdentity)?,
        vec![(
            tenant,
            Epoch::new(config.storage_tenant_epoch).map_err(|_| AppError::StorageEpoch)?,
        )],
    )
    .map_err(|_| AppError::StorageIdentity)?;
    let runtime = Arc::new(
        PgRuntime::connect_producer(pg, Timer, binding)
            .await
            .map_err(|_| AppError::Connection)?,
    );
    let kdf = Arc::new(rss_identity_core::account::PasswordKdf::new());
    let authority = Authority::connect(
        runtime.clone(),
        kdf.clone(),
        config.identity_origin,
        DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .map_err(|_| AppError::Budget)?,
        tenant,
        AuthorityProfile::Maintenance,
        budget(),
    )
    .await;
    let result = match authority {
        Ok(authority) => execute(&authority, tenant, command).await,
        Err(error) => Err(error.into()),
    };
    kdf.close();
    if tokio::time::timeout(Duration::from_secs(5), kdf.wait_closed())
        .await
        .is_err()
    {
        eprintln!("password task shutdown incomplete");
        std::process::exit(1);
    }
    if tokio::time::timeout(Duration::from_secs(5), runtime.close())
        .await
        .is_err()
    {
        eprintln!("database shutdown timed out; confirmed operation outcome unchanged");
    }
    result
}
async fn execute(a: &Authority, tenant: TenantId, command: Command<'_>) -> Result<(), AppError> {
    let result = match command {
        Command::Initialize(principal, name, pw) => {
            a.initialize(
                key(tenant, principal)?,
                login(name)?,
                password(pw)?,
                budget(),
            )
            .await
        }
        Command::Recover(principal, pw) => {
            a.recover_administrator(key(tenant, principal)?, password(pw)?, budget())
                .await
        }
    }?;
    println!(
        "principal={} epoch={}",
        result.key().principal.as_uuid(),
        result.epoch()
    );
    Ok(())
}

#[derive(Debug)]
enum Command<'a> {
    Initialize(&'a str, &'a str, &'a str),
    Recover(&'a str, &'a str),
}
fn usage() -> &'static str {
    "Usage: identity-admin CONFIG COMMAND\n  initialize <principal> <login> <password-file>\n  recover <principal> <password-file>"
}
fn parse_command(args: &[String]) -> Result<Command<'_>, AppError> {
    match args {
        [name, principal, login, password] if name == "initialize" => {
            Ok(Command::Initialize(principal, login, password))
        }
        [name, principal, password] if name == "recover" => {
            Ok(Command::Recover(principal, password))
        }
        [name, ..] if name == "initialize" || name == "recover" => Err(AppError::Arguments),
        _ => Err(AppError::UnknownCommand),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maintenance_commands_are_single_step() {
        assert!(parse_command(&["initialize", "id", "login", "file"].map(String::from)).is_ok());
        assert!(parse_command(&["recover", "id", "file"].map(String::from)).is_ok());
        for command in [
            "create",
            "password",
            "enable",
            "disable",
            "grant-admin",
            "revoke-admin",
            "enable-membership",
            "disable-membership",
            "idp-list",
            "idp-create",
            "idp-update",
            "idp-enable",
            "idp-disable",
            "idp-test",
            "authorize-recovery",
        ] {
            assert!(matches!(
                parse_command(&[command, "id", "file"].map(String::from)),
                Err(AppError::UnknownCommand)
            ));
        }
        assert!(parse_command(&["recover", "id", "file", "extra"].map(String::from)).is_err());
    }
}
