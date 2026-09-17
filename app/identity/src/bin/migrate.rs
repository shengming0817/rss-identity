#[tokio::main]
async fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("identity migration panic")));
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--describe"] {
        use sha2::{Digest, Sha256};
        println!(
            "{}",
            serde_json::json!({"schema_version":rss_identity_postgres::SCHEMA_VERSION,"schema_contract":rss_identity_postgres::SCHEMA_SIGNATURE.trim(),"identity_sql_sha256":hex::encode(Sha256::digest(rss_identity_postgres::MIGRATION_SQL)),"rss_sql_sha256":hex::encode(Sha256::digest(rss_transactional_messaging_postgres::MIGRATION_SQL))})
        );
        return;
    }
    if args == ["--version"] {
        println!("identity-migrate {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args == ["--help"] {
        println!(
            "identity-migrate --config FILE [--verify]\nidentity-migrate --config FILE --rekey KEYRING_FILE\nidentity-migrate --config FILE --verify-keys KEYRING_FILE"
        );
        return;
    }
    let result = async {
        if args.len() < 2 || args[0] != "--config" {
            return Err(rss_identity_app::AppError::Arguments);
        }
        let config = rss_identity_app::config::load(std::path::Path::new(&args[1]))?;
        match &args[2..] {
            [] => rss_identity_app::migration::install(config).await,
            [command] if command == "--verify" => rss_identity_app::migration::verify(config).await,
            [command, keys] if command == "--rekey" || command == "--verify-keys" => {
                let keys: rss_identity_app::config::CredentialKeyringConfig =
                    rss_identity_app::config::load(std::path::Path::new(keys))?;
                rss_identity_app::rekey::run(config, keys, command == "--verify-keys").await
            }
            _ => Err(rss_identity_app::AppError::Arguments),
        }
    }
    .await;
    match result {
        Ok(()) => println!(
            "operation confirmed schema={}",
            rss_identity_postgres::SCHEMA_VERSION
        ),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
