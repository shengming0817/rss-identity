mod idp;
use rss_identity_admin::{AdminError, read_public_file, read_secret};
use rss_identity_core::account::{AccountChange, AccountKey};
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
        println!("{}", usage());
        return Ok(());
    }
    if args.len() < 2 {
        return Err(AdminError::Arguments);
    }
    let command = parse_command(&args[1..])?;
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
        command.profile(),
        budget(),
    )
    .await;
    let result = match authority {
        Ok(authority) => execute(&authority, tenant, command).await,
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
async fn execute(a: &Authority, tenant: TenantId, command: Command<'_>) -> Result<(), AdminError> {
    let result = match command {
        Command::Idp(command) => return idp::execute(a, tenant, command).await,
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
        Command::Create {
            actor,
            actor_pw,
            name,
            pw,
            admin,
            emergency,
        } => {
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
        Command::Password(actor, actor_pw, target, pw) => {
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
        Command::Change {
            actor,
            actor_pw,
            target,
            change,
        } => {
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
    Idp(idp::Command<'a>),
    Initialize(&'a str, &'a str, &'a str),
    Recover(&'a str, &'a str),
    Create {
        actor: &'a str,
        actor_pw: &'a str,
        name: &'a str,
        pw: &'a str,
        admin: bool,
        emergency: bool,
    },
    Password(&'a str, &'a str, &'a str, &'a str),
    Change {
        actor: &'a str,
        actor_pw: &'a str,
        target: &'a str,
        change: AccountChange,
    },
}
impl Command<'_> {
    fn profile(&self) -> AuthorityProfile {
        match self {
            Self::Initialize(..) | Self::Recover(..) => AuthorityProfile::Maintenance,
            Self::Create { .. } | Self::Password(..) | Self::Change { .. } | Self::Idp(..) => {
                AuthorityProfile::Runtime
            }
        }
    }
}
// Help renders structural value names; it never defines parser arity.
// ref: clap v4.5.20 clap_builder/src/builder/arg.rs (val_names / num_args).
struct CommandSpec {
    name: &'static str,
    arguments: &'static [&'static str],
    parse: for<'a> fn(&'a [String]) -> Result<Command<'a>, AdminError>,
}
const CHANGE_ARGUMENTS: &[&str] = &[
    "<actor-login>",
    "<actor-password-file>",
    "<target-principal>",
];
const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "idp-list",
        arguments: &["<actor>", "<actor_pw>"],
        parse: |a| match a {
            [actor, actor_pw] => Ok(Command::Idp(idp::Command {
                actor,
                password: actor_pw,
                operation: idp::Operation::List,
            })),
            _ => Err(AdminError::Arguments),
        },
    },
    CommandSpec {
        name: "idp-create",
        arguments: &["<policy>", "<actor>", "<actor_pw>", "<settings>"],
        parse: |a| match a {
            [policy, actor, actor_pw, settings] => Ok(Command::Idp(idp::Command {
                actor,
                password: actor_pw,
                operation: idp::Operation::Create(policy, settings),
            })),
            _ => Err(AdminError::Arguments),
        },
    },
    CommandSpec {
        name: "idp-update",
        arguments: &[
            "<policy>",
            "<actor>",
            "<actor_pw>",
            "<provider>",
            "<version>",
            "<settings>",
        ],
        parse: |a| match a {
            [policy, actor, actor_pw, provider, version, settings] => {
                Ok(Command::Idp(idp::Command {
                    actor,
                    password: actor_pw,
                    operation: idp::Operation::Update(policy, provider, version, settings),
                }))
            }
            _ => Err(AdminError::Arguments),
        },
    },
    CommandSpec {
        name: "idp-enable",
        arguments: &["<actor>", "<actor_pw>", "<provider>", "<version>"],
        parse: |a| match a {
            [actor, actor_pw, provider, version] => Ok(Command::Idp(idp::Command {
                actor,
                password: actor_pw,
                operation: idp::Operation::Enable(provider, version, true),
            })),
            _ => Err(AdminError::Arguments),
        },
    },
    CommandSpec {
        name: "idp-disable",
        arguments: &["<actor>", "<actor_pw>", "<provider>", "<version>"],
        parse: |a| match a {
            [actor, actor_pw, provider, version] => Ok(Command::Idp(idp::Command {
                actor,
                password: actor_pw,
                operation: idp::Operation::Enable(provider, version, false),
            })),
            _ => Err(AdminError::Arguments),
        },
    },
    CommandSpec {
        name: "idp-test",
        arguments: &["<policy>", "<actor>", "<actor_pw>", "<provider>"],
        parse: |a| match a {
            [policy, actor, actor_pw, provider] => Ok(Command::Idp(idp::Command {
                actor,
                password: actor_pw,
                operation: idp::Operation::Test(policy, provider),
            })),
            _ => Err(AdminError::Arguments),
        },
    },
    CommandSpec {
        name: "initialize",
        arguments: &["<principal>", "<login>", "<password-file>"],
        parse: |a| match a {
            [principal, login, password] => Ok(Command::Initialize(principal, login, password)),
            _ => Err(AdminError::Arguments),
        },
    },
    CommandSpec {
        name: "recover",
        arguments: &["<principal>", "<password-file>"],
        parse: |a| match a {
            [principal, password] => Ok(Command::Recover(principal, password)),
            _ => Err(AdminError::Arguments),
        },
    },
    CommandSpec {
        name: "create",
        arguments: &[
            "<actor-login>",
            "<actor-password-file>",
            "<login>",
            "<password-file>",
            "<member|admin|emergency>",
        ],
        parse: |a| {
            let [actor, actor_pw, name, pw, role] = a else {
                return Err(AdminError::Arguments);
            };
            let (admin, emergency) = match role.as_str() {
                "member" => (false, false),
                "admin" => (true, false),
                "emergency" => (true, true),
                _ => return Err(AdminError::Role),
            };
            Ok(Command::Create {
                actor,
                actor_pw,
                name,
                pw,
                admin,
                emergency,
            })
        },
    },
    CommandSpec {
        name: "password",
        arguments: &[
            "<actor-login>",
            "<actor-password-file>",
            "<target-principal>",
            "<new-password-file>",
        ],
        parse: |a| match a {
            [actor, actor_pw, target, password] => {
                Ok(Command::Password(actor, actor_pw, target, password))
            }
            _ => Err(AdminError::Arguments),
        },
    },
    CommandSpec {
        name: "enable",
        arguments: CHANGE_ARGUMENTS,
        parse: |a| change_command(a, AccountChange::Enabled(true)),
    },
    CommandSpec {
        name: "disable",
        arguments: CHANGE_ARGUMENTS,
        parse: |a| change_command(a, AccountChange::Enabled(false)),
    },
    CommandSpec {
        name: "grant-admin",
        arguments: CHANGE_ARGUMENTS,
        parse: |a| change_command(a, AccountChange::Administrator(true)),
    },
    CommandSpec {
        name: "revoke-admin",
        arguments: CHANGE_ARGUMENTS,
        parse: |a| change_command(a, AccountChange::Administrator(false)),
    },
    CommandSpec {
        name: "enable-membership",
        arguments: CHANGE_ARGUMENTS,
        parse: |a| change_command(a, AccountChange::Membership(true)),
    },
    CommandSpec {
        name: "disable-membership",
        arguments: CHANGE_ARGUMENTS,
        parse: |a| change_command(a, AccountChange::Membership(false)),
    },
];
fn change_command(args: &[String], change: AccountChange) -> Result<Command<'_>, AdminError> {
    match args {
        [actor, actor_pw, target] => Ok(Command::Change {
            actor,
            actor_pw,
            target,
            change,
        }),
        _ => Err(AdminError::Arguments),
    }
}
fn usage() -> String {
    let mut text = String::from("Usage: identity-admin <config.json> <command> <arguments>\n");
    for spec in COMMANDS {
        text.push_str(&format!("  {} {}\n", spec.name, spec.arguments.join(" ")));
    }
    text.push_str("  --help | -h\nSecrets are read from private files. Initialization and recovery require the maintenance database role.");
    text
}
fn parse_command(args: &[String]) -> Result<Command<'_>, AdminError> {
    let name = args.first().ok_or(AdminError::Arguments)?;
    let spec = COMMANDS
        .iter()
        .find(|s| s.name == name)
        .ok_or(AdminError::UnknownCommand)?;
    let arguments = &args[1..];
    if arguments.len() != spec.arguments.len() {
        return Err(AdminError::Arguments);
    }
    (spec.parse)(arguments)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_parsers_reject_any_wrong_shape_without_panicking() {
        for spec in COMMANDS {
            for count in 0..=spec.arguments.len() + 1 {
                let args = vec![String::from("member"); count];
                let result = (spec.parse)(&args);
                if count != spec.arguments.len() {
                    assert!(
                        matches!(result, Err(AdminError::Arguments)),
                        "{} accepted wrong shape",
                        spec.name
                    );
                } else {
                    assert!(result.is_ok(), "{} rejected its declared shape", spec.name);
                }
            }
        }
    }
    #[test]
    fn maintenance_commands_are_single_step() {
        for args in [
            vec!["initialize", "principal", "login", "password-file"],
            vec!["recover", "principal", "password-file"],
        ] {
            parse_command(&args.into_iter().map(String::from).collect::<Vec<_>>()).unwrap();
        }
        for command in ["authorize-initialize", "authorize-recovery"] {
            assert!(matches!(
                parse_command(&[command, "principal", "file"].map(String::from)),
                Err(AdminError::UnknownCommand)
            ));
        }
        assert!(
            parse_command(
                &[
                    "initialize",
                    "principal",
                    "login",
                    "password",
                    "authorization"
                ]
                .map(String::from)
            )
            .is_err()
        );
        assert!(
            parse_command(&["recover", "principal", "password", "authorization"].map(String::from))
                .is_err()
        );
    }
    #[test]
    fn commands_fail_before_opening_configuration_or_provider() {
        for (command, count) in [
            ("initialize", 4),
            ("recover", 3),
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
            let parsed = parse_command(&args).unwrap();
            assert_eq!(
                parsed.profile(),
                if matches!(command, "initialize" | "recover") {
                    AuthorityProfile::Maintenance
                } else {
                    AuthorityProfile::Runtime
                }
            );
            assert!(
                usage()
                    .lines()
                    .any(|line| line.starts_with(&format!("  {command} ")))
            );
            args.pop();
            assert!(matches!(parse_command(&args), Err(AdminError::Arguments)));
            assert!(usage().contains(command));
        }
        assert!(matches!(
            parse_command(&["private-value".into()]),
            Err(AdminError::UnknownCommand)
        ));
        let error =
            parse_command(&["create", "a", "b", "c", "d", "private-value"].map(String::from))
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
