use rss_identity_app::{AppError, read_secret};
use rss_identity_app::{
    assembly,
    config::{MaintenanceConfig, load},
};
use rss_identity_core::account::AccountKey;
use rss_identity_core::{
    PrincipalId,
    account::{LoginKey, Password},
};
use rss_identity_postgres::*;
use rss_request_context::TenantId;
use std::{path::Path, sync::Arc};
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
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), AppError> {
    if std::env::args().skip(1).collect::<Vec<_>>() == ["--version"] {
        println!("identity-admin {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] || args == ["-h"] {
        println!("{}", usage());
        return Ok(());
    }
    if args.len() == 2 && args[0] == "--check-config" {
        let config: MaintenanceConfig = load(Path::new(&args[1]))?;
        config.validate()?;
        config.database.pg()?;
        return Ok(());
    }
    if args.len() < 2 {
        return Err(AppError::Arguments);
    }
    let command = parse_command(&args[1..])?;
    let config: MaintenanceConfig = load(Path::new(&args[0]))?;
    config.validate()?;
    let cutoff = rss_identity_app::config::cutoff(config.budgets.maintenance_seconds)?;
    let authority_config = config.authority_config()?;
    let database = config.database.pg()?;
    let binding = config.storage.identity()?;
    let runtime = Arc::new(
        tokio::time::timeout_at(
            cutoff.instant().into(),
            rss_transactional_messaging_postgres::PgRuntime::connect_producer(
                database,
                assembly::Timer,
                binding,
            ),
        )
        .await
        .map_err(|_| AppError::Connection)?
        .map_err(|_| AppError::Connection)?,
    );
    let kdf = Arc::new(config.password_work.build()?);
    let authority = Authority::connect_maintenance(
        runtime.clone(),
        kdf.clone(),
        authority_config,
        config.storage.binding(command.tenant()?)?,
        cutoff,
    )
    .await;
    let result = match authority {
        Ok(authority) => execute(&authority, &config, command, cutoff).await,
        Err(error) => Err(error.into()),
    };
    kdf.close();
    if tokio::time::timeout(config.budgets.resource(), kdf.wait_closed())
        .await
        .is_err()
    {
        eprintln!("password task shutdown incomplete");
        std::process::exit(1);
    }
    if tokio::time::timeout(config.budgets.resource(), runtime.close())
        .await
        .is_err()
    {
        eprintln!("database shutdown timed out; confirmed operation outcome unchanged");
    }
    result
}
async fn execute(
    a: &Authority,
    config: &MaintenanceConfig,
    command: Command<'_>,
    cutoff: rss_request_context::Deadline,
) -> Result<(), AppError> {
    let result = match command {
        Command::Initialize(tenant, name, pw) => {
            a.initialize(
                config
                    .storage
                    .binding(TenantId::parse(tenant).map_err(|_| AppError::Tenant)?)?,
                config.bootstrap_key(TenantId::parse(tenant).map_err(|_| AppError::Tenant)?)?,
                login(name)?,
                password(pw)?,
                cutoff,
            )
            .await
        }
        Command::Recover(target, principal, pw) => {
            a.recover_local_password(
                config
                    .storage
                    .binding(TenantId::parse(target).map_err(|_| AppError::Tenant)?)?,
                key(target, principal)?,
                password(pw)?,
                cutoff,
            )
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
    Recover(&'a str, &'a str, &'a str),
}
impl Command<'_> {
    fn tenant(&self) -> Result<TenantId, AppError> {
        let (Self::Initialize(tenant, ..) | Self::Recover(tenant, ..)) = self;
        TenantId::parse(tenant).map_err(|_| AppError::Tenant)
    }
}
fn usage() -> &'static str {
    "Usage: identity-admin --check-config FILE\nidentity-admin CONFIG COMMAND\n  initialize <tenant> <login> <password-file>\n  recover <tenant> <principal> <password-file>"
}
fn parse_command(args: &[String]) -> Result<Command<'_>, AppError> {
    match args {
        [name, tenant, login, password] if name == "initialize" => {
            Ok(Command::Initialize(tenant, login, password))
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
            parse_command(&["initialize", "tenant", "login", "file"].map(String::from)).is_ok()
        );
        assert!(
            parse_command(&["initialize", "tenant", "id", "login", "file"].map(String::from))
                .is_err()
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
