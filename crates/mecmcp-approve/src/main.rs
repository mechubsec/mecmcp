//! Entry point for the `mecmcp-approve` binary -- see `lib.rs` for the
//! actual login/preview/approve flow.

use clap::Parser;
use mecmcp_approve::cli::Args;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    if let Err(err) = mecmcp_approve::run(&args).await {
        eprintln!("mecmcp-approve: {err}");
        std::process::exit(1);
    }
}
