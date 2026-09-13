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
        println!("identity-migrate --config FILE\nidentity-migrate --rekey --config FILE");
        return;
    }
    if args.len() == 3 && args[0] == "--rekey" && args[1] == "--config" {
        let result = async {
            let config = rss_identity_app::config::load(std::path::Path::new(&args[2]))?;
            rss_identity_app::rekey::run(config).await
        }
        .await;
        match result {
            Ok(n) => println!("rewritten={n}; repeat until rewritten=0 before retiring old keys"),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        return;
    }
    let result = async {
        if args.len() != 2 || args[0] != "--config" {
            return Err(rss_identity_app::AppError::Arguments);
        }
        let config = rss_identity_app::config::load(std::path::Path::new(&args[1]))?;
        rss_identity_app::migration::install(config).await
    }
    .await;
    match result {
        Ok(()) => println!(
            "installation verified schema={}",
            rss_identity_postgres::SCHEMA_VERSION
        ),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
