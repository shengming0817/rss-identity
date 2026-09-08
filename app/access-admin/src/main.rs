use access_admin::{AdminError, deliver_authorization, read_public_file, read_secret};
use access_core::account::{AccountChange, AccountKey};
use access_core::{
    PrincipalId,
    account::{LoginKey, Password},
};
use access_postgres::*;
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
fn password(path: &str) -> Result<Password, AdminError> {
    Password::new(read_secret(Path::new(path))?.to_string()).map_err(|_| AdminError::Password)
}
fn login(s: &str) -> Result<LoginKey, AdminError> {
    LoginKey::parse(s).map_err(|_| AdminError::Login)
}
fn key(tenant: TenantId, p: &str) -> Result<AccountKey, AdminError> {
    Ok(AccountKey {
        tenant,
        principal: PrincipalId::parse(p).map_err(|_| AdminError::Principal)?,
    })
}
fn source() -> AttemptSource {
    AttemptSource::parse("local-operator").expect("constant source")
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
async fn run() -> Result<(), AdminError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] || args == ["-h"] {
        println!("{USAGE}");
        return Ok(());
    }
    if args.len() < 2 {
        return Err(AdminError::Arguments);
    }
    validate_command(&args[1..])?;
    let raw =
        read_public_file(Path::new(&args[0]), 16384).map_err(|_| AdminError::Configuration)?;
    let config: Config = serde_json::from_slice(&raw).map_err(|_| AdminError::Json)?;
    let tenant = TenantId::parse(&config.tenant_id).map_err(|_| AdminError::Tenant)?;
    let ca = PgPrivateCa::from_pem(
        read_public_file(Path::new(&config.ca_file), 1024 * 1024).map_err(|_| AdminError::Ca)?,
    )
    .map_err(|_| AdminError::Ca)?;
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
            .map_err(|_| AdminError::StorageIdentity)?,
        vec![(
            tenant,
            Epoch::new(config.storage_tenant_epoch).map_err(|_| AdminError::StorageEpoch)?,
        )],
    )
    .map_err(|_| AdminError::StorageIdentity)?;
    let runtime = Arc::new(
        PgRuntime::connect(pg, Timer, binding)
            .await
            .map_err(|_| AdminError::Connection)?,
    );
    let authority = Authority::connect(
        runtime.clone(),
        DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .map_err(|_| AdminError::Budget)?,
        tenant,
        if matches!(
            args[1].as_str(),
            "authorize-initialize" | "authorize-recovery"
        ) {
            AuthorityProfile::Issuer
        } else {
            AuthorityProfile::Runtime
        },
        budget(),
    )
    .await;
    let result = match authority {
        Ok(authority) => execute(&authority, tenant, &args[1..]).await,
        Err(error) => Err(error.into()),
    };
    if tokio::time::timeout(Duration::from_secs(5), runtime.close())
        .await
        .is_err()
    {
        eprintln!("database shutdown timed out; confirmed operation outcome unchanged");
    }
    result
}
async fn execute(a: &Authority, tenant: TenantId, args: &[String]) -> Result<(), AdminError> {
    let strings: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match strings.as_slice() {
        ["authorize-initialize", principal, output] | ["authorize-recovery", principal, output] => {
            let purpose = if strings[0] == "authorize-initialize" {
                AuthorizationPurpose::Initialize
            } else {
                AuthorizationPurpose::Recover
            };
            deliver_authorization(
                Path::new(output),
                a.issue_authorization(key(tenant, principal)?, purpose, budget())
                    .await,
            )?;
            println!("authorization delivered");
            return Ok(());
        }
        ["initialize", principal, name, pw, secret] => {
            a.initialize(
                key(tenant, principal)?,
                login(name)?,
                password(pw)?,
                AuthorizationSecret::parse(read_secret(Path::new(secret))?.to_string())?,
                source(),
                budget(),
            )
            .await
        }
        ["recover", principal, pw, secret] => {
            a.recover_administrator(
                key(tenant, principal)?,
                password(pw)?,
                AuthorizationSecret::parse(read_secret(Path::new(secret))?.to_string())?,
                source(),
                budget(),
            )
            .await
        }
        ["create", actor, actor_pw, name, pw, role] => {
            let (admin, emergency) = match *role {
                "member" => (false, false),
                "admin" => (true, false),
                "emergency" => (true, true),
                _ => return Err(AdminError::Role),
            };
            let actor = a
                .verify_password(
                    tenant,
                    login(actor)?,
                    password(actor_pw)?,
                    source(),
                    budget(),
                )
                .await?;
            a.create_account(
                actor,
                login(name)?,
                password(pw)?,
                admin,
                emergency,
                budget(),
            )
            .await
        }
        ["password", actor, actor_pw, target, pw] => {
            let actor = a
                .verify_password(
                    tenant,
                    login(actor)?,
                    password(actor_pw)?,
                    source(),
                    budget(),
                )
                .await?;
            a.change_account(
                actor,
                key(tenant, target)?,
                AccountChange::Password(password(pw)?),
                budget(),
            )
            .await
        }
        [command, actor, actor_pw, target] => {
            let change = match *command {
                "enable" => AccountChange::Enabled(true),
                "disable" => AccountChange::Enabled(false),
                "grant-admin" => AccountChange::Administrator(true),
                "revoke-admin" => AccountChange::Administrator(false),
                "enable-membership" => AccountChange::Membership(true),
                "disable-membership" => AccountChange::Membership(false),
                _ => return Err(AdminError::UnknownCommand),
            };
            let actor = a
                .verify_password(
                    tenant,
                    login(actor)?,
                    password(actor_pw)?,
                    source(),
                    budget(),
                )
                .await?;
            a.change_account(actor, key(tenant, target)?, change, budget())
                .await
        }
        _ => return Err(AdminError::UnknownCommand),
    }?;
    println!(
        "principal={} epoch={}",
        result.key().principal.as_uuid(),
        result.epoch()
    );
    Ok(())
}

const USAGE: &str = "Usage: access-admin <config.json> <command> <arguments>
  authorize-initialize|authorize-recovery <principal> <output-secret-file>
  initialize <principal> <login> <password-file> <authorization-file>
  recover <principal> <password-file> <authorization-file>
  create <actor-login> <actor-password-file> <login> <password-file> <member|admin|emergency>
  password <actor-login> <actor-password-file> <target-principal> <new-password-file>
  enable|disable|grant-admin|revoke-admin|enable-membership|disable-membership <actor-login> <actor-password-file> <target-principal>
  --help | -h
Secrets are read from private files. Authorization commands require the issuer database role.";

fn validate_command(args: &[String]) -> Result<(), AdminError> {
    let command = args.first().ok_or(AdminError::Arguments)?.as_str();
    let length = match command {
        "authorize-initialize" | "authorize-recovery" => 3,
        "initialize" | "password" => 5,
        "recover" | "enable" | "disable" | "grant-admin" | "revoke-admin" | "enable-membership"
        | "disable-membership" => 4,
        "create" => 6,
        _ => return Err(AdminError::UnknownCommand),
    };
    if args.len() != length {
        return Err(AdminError::Arguments);
    }
    if command == "create" && !matches!(args[5].as_str(), "member" | "admin" | "emergency") {
        return Err(AdminError::Role);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commands_fail_before_opening_configuration_or_provider() {
        for (command, count) in [
            ("authorize-initialize", 3),
            ("authorize-recovery", 3),
            ("initialize", 5),
            ("recover", 4),
            ("create", 6),
            ("password", 5),
            ("enable", 4),
            ("disable", 4),
            ("grant-admin", 4),
            ("revoke-admin", 4),
            ("enable-membership", 4),
            ("disable-membership", 4),
        ] {
            let mut args = vec!["private-value".into(); count];
            args[0] = command.into();
            if command == "create" {
                args[5] = "member".into();
            }
            validate_command(&args).unwrap();
            args.pop();
            assert!(matches!(
                validate_command(&args),
                Err(AdminError::Arguments)
            ));
            assert!(USAGE.contains(command));
        }
        assert!(matches!(
            validate_command(&["private-value".into()]),
            Err(AdminError::UnknownCommand)
        ));
        let error =
            validate_command(&["create", "a", "b", "c", "d", "private-value"].map(String::from))
                .unwrap_err();
        assert!(matches!(error, AdminError::Role));
        assert!(!error.to_string().contains("private-value"));
        assert!(matches!(
            key(
                TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
                "private-value"
            ),
            Err(AdminError::Principal)
        ));
        assert!(matches!(login(""), Err(AdminError::Login)));
    }
}
