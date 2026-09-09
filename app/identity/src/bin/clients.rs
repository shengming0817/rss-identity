#[tokio::main]
async fn main() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("identity client installation panic")
    }));
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("identity-clients --config FILE (run in Hydra network namespace)");
        return;
    }
    let result = async {
        if args.len() != 2 || args[0] != "--config" {
            return Err(rss_identity_app::AppError::Arguments);
        }
        let config = rss_identity_app::config::RuntimeConfig::load(std::path::Path::new(&args[1]))?;
        rss_identity_app::clients::LocalHydra::new(4445, 4444)?
            .install(&config)
            .await
    }
    .await;
    match result {
        Ok(count) => println!("Hydra client registration verified count={count}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
