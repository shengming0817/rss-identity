use rss_identity_app::{AppError, read_public_file, read_secret};
use rss_identity_app::{
    assembly,
    config::{DatabaseConfig, StorageConfig},
};
use rss_identity_core::account::AccountKey;
use rss_identity_core::{
    PrincipalId,
    account::{LoginKey, Password},
};
use rss_identity_postgres::*;
use rss_request_context::TenantId;
use serde::Deserialize;
use std::{path::Path, sync::Arc, time::Duration};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    instance_id: String,
    database: DatabaseConfig,
    storage: StorageConfig,
}
fn password(path: &str) -> Result<Password, AppError> {
    Password::new(read_secret(Path::new(path))?.to_string()).map_err(|_| AppError::Password)
}
fn login(value: &str) -> Result<LoginKey, AppError> {
    LoginKey::parse(value).map_err(|_| AppError::Login)
}
fn key(tenant: &str, principal: &str) -> Result<AccountKey, AppError> {
    Ok(AccountKey {
        tenant: TenantId::parse(tenant).map_err(|_| AppError::Tenant)?,
        principal: PrincipalId::parse(principal).map_err(|_| AppError::Principal)?,
    })
}
fn budget() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(30))
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
    let runtime = Arc::new(
        rss_transactional_messaging_postgres::PgRuntime::connect_producer(
            config.database.pg()?,
            assembly::Timer,
            config.storage.binding()?,
        )
        .await
        .map_err(|_| AppError::Connection)?,
    );
    let kdf = Arc::new(rss_identity_core::account::PasswordKdf::new());
    let authority = Authority::connect_maintenance(
        runtime.clone(),
        kdf.clone(),
        AuthorityConfig::new(
            rss_identity_core::InstanceId::parse(&config.instance_id)
                .map_err(|_| AppError::Configuration)?,
            config.storage.tenants()?,
            rss_identity_core::session::SessionPolicy::new(900, 14400)
                .map_err(|_| AppError::Budget)?,
            assembly::delivery_budget()?,
        )?,
        budget(),
    )
    .await;
    let result = match authority {
        Ok(authority) => execute(&authority, command).await,
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
async fn execute(a: &Authority, command: Command<'_>) -> Result<(), AppError> {
    let result = match command {
        Command::Initialize(tenant, principal, name, pw) => {
            a.initialize(
                key(tenant, principal)?,
                login(name)?,
                password(pw)?,
                budget(),
            )
            .await
        }
        Command::Recover(target, principal, pw) => {
            a.recover_local_password(key(target, principal)?, password(pw)?, budget())
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
    Initialize(&'a str, &'a str, &'a str, &'a str),
    Recover(&'a str, &'a str, &'a str),
}
fn usage() -> &'static str {
    "Usage: identity-admin CONFIG COMMAND\n  initialize <tenant> <principal> <login> <password-file>\n  recover <tenant> <principal> <password-file>"
}
fn parse_command(args: &[String]) -> Result<Command<'_>, AppError> {
    match args {
        [name, tenant, principal, login, password] if name == "initialize" => {
            Ok(Command::Initialize(tenant, principal, login, password))
        }
        [name, tenant, principal, password] if name == "recover" => {
            Ok(Command::Recover(tenant, principal, password))
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
        assert!(
            parse_command(&["initialize", "tenant", "id", "login", "file"].map(String::from))
                .is_ok()
        );
        assert!(parse_command(&["recover", "tenant", "id", "file"].map(String::from)).is_ok());
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
        assert!(
            parse_command(&["recover", "tenant", "id", "file", "extra"].map(String::from)).is_err()
        );
    }
}
