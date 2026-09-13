#[tokio::main]
async fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("platform_client_failure")));
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] || args == ["-h"] {
        println!("{}", rss_identity_platform::usage());
        return;
    }
    if args == ["--version"] {
        println!("identity-platform {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    match rss_identity_platform::run(args).await {
        Ok((code, value)) => {
            println!("{value}");
            std::process::exit(code);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(e.exit_code());
        }
    }
}
