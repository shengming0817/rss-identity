use rss_identity_app::{AppError, config::RuntimeConfig, lifecycle};
fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("identity process panic")));
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() == 2 && args[0] == "--probe" {
        let healthy = args[1]
            .parse()
            .is_ok_and(rss_identity_app::transport::probe);
        std::process::exit(if healthy { 0 } else { 1 });
    }
    if args == ["--version"] {
        println!("identity-server {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args == ["--help"] {
        println!(
            "identity-server --config FILE\nidentity-server --check-config FILE\nidentity-server --version\nidentity-server --acceptance-profile\nidentity-server --probe LOOPBACK:PORT"
        );
        return;
    }
    let result = (|| {
        if args == ["--acceptance-profile"] {
            let policy = rss_identity_app::assembly::session_policy()?;
            println!(
                "{}",
                serde_json::json!({
                    "formatVersion": 1,
                    "schemaVersion": rss_identity_postgres::SCHEMA_VERSION,
                    "session": {"idleSeconds": policy.idle_seconds(), "absoluteSeconds": policy.absolute_seconds()},
                    "attempts": {
                        "sourceLimit": rss_identity_postgres::ATTEMPT_SOURCE_LIMIT,
                        "sourceSeconds": rss_identity_postgres::ATTEMPT_SOURCE_SECONDS,
                        "scopeLimit": rss_identity_postgres::ATTEMPT_SCOPE_LIMIT,
                        "scopeSeconds": rss_identity_postgres::ATTEMPT_SCOPE_SECONDS
                    },
                    "kdfConcurrency": rss_identity_core::account::PasswordKdf::MAX_CONCURRENCY,
                    "mfaMaxAgeSeconds": rss_identity_app::context::MFA_MAX_AGE_SECONDS
                })
            );
            return Ok(());
        }
        if args.len() != 2 || !["--config", "--check-config"].contains(&args[0].as_str()) {
            return Err(AppError::Arguments);
        }
        let config = RuntimeConfig::load(std::path::Path::new(&args[1]))?;
        rss_identity_app::assembly::preflight(&config)?;
        if args[0] == "--check-config" {
            return Ok(());
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|_| AppError::Shutdown)?;
        let result = runtime.block_on(lifecycle::serve(config, lifecycle::signal()));
        // A failed drain may retain a non-cooperative blocking closure. Do not enter runtime Drop.
        if let Err(error) = result {
            eprintln!("{error}");
            std::process::exit(1);
        }
        drop(runtime);
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
