use rss_identity_app::{AppError, config::RuntimeConfig, lifecycle};
fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("identity process panic")));
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--version"] {
        println!("identity-server {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args == ["--help"] {
        println!("identity-server --config FILE\nidentity-server --version");
        return;
    }
    let result = (|| {
        if args.len() != 2 || args[0] != "--config" {
            return Err(AppError::Arguments);
        }
        let config = RuntimeConfig::load(std::path::Path::new(&args[1]))?;
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
