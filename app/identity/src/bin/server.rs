use rss_identity_app::{AppError, config::RuntimeConfig, lifecycle};
fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("identity process panic")));
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() == 3 && args[0] == "--probe" {
        let healthy = args[1]
            .parse()
            .ok()
            .zip(
                args[2]
                    .parse()
                    .ok()
                    .and_then(|seconds| rss_identity_app::config::cutoff(seconds).ok()),
            )
            .is_some_and(|(address, cutoff)| rss_identity_app::transport::probe(address, cutoff));
        std::process::exit(if healthy { 0 } else { 1 });
    }
    if args == ["--version"] {
        println!("identity-server {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args == ["--help"] {
        println!(
            "identity-server --config FILE\nidentity-server --check-config FILE\nidentity-server --version\nidentity-server --acceptance-profile < runtime.json\nidentity-server --probe LOOPBACK:PORT TIMEOUT_SECONDS"
        );
        return;
    }
    let result = (|| {
        if args == ["--acceptance-profile"] {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(rss_identity_app::config::CONFIG_MAX_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| AppError::Configuration)?;
            if bytes.len() > rss_identity_app::config::CONFIG_MAX_BYTES {
                return Err(AppError::Configuration);
            }
            let config: RuntimeConfig =
                serde_json::from_slice(&bytes).map_err(|_| AppError::Json)?;
            config.validate()?;
            let policy = rss_identity_app::assembly::session_policy()?;
            println!(
                "{}",
                serde_json::json!({
                    "formatVersion": 1,
                    "schemaVersion": rss_identity_postgres::SCHEMA_VERSION,
                    "session": {"idleSeconds": policy.idle_seconds(), "absoluteSeconds": policy.absolute_seconds()},
                    "attempts": {
                        "sourceLimit": config.authority.source_limit,
                        "sourceSeconds": config.authority.source_seconds,
                        "scopeLimit": config.authority.scope_limit,
                        "scopeSeconds": config.authority.scope_seconds,
                        "passwordFailureLimit": config.authority.password_failure_limit,
                        "passwordFailureSeconds": config.authority.password_failure_seconds
                    },
                    "kdfConcurrency": config.password_work.concurrency.get(),
                    "operationProofSeconds": config.authority.operation_proof_seconds.get()
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
