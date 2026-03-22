//! QUIC pipe - Simple QUIC-based data forwarding tool.

use clap::Parser;
use tracing_subscriber::EnvFilter;

mod client;
mod config;
mod endpoint;
mod error;
mod migration;
mod server;
mod stream;
#[cfg(test)]
mod tests;

use config::{Args, Commands};

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let filter = match args.verbose {
        0 => EnvFilter::from_default_env(),
        1 => EnvFilter::new("info"),
        2 => EnvFilter::new("debug"),
        _ => EnvFilter::new("trace"),
    };

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();

    let result = match args.command {
        Commands::Listen(args) => server::listen_stdio(args).await,
        Commands::Connect(args) => client::connect_stdio(args).await,
        Commands::ListenTcp(args) => server::listen_tcp(args).await,
        Commands::ConnectTcp(args) => client::connect_tcp(args).await,
    };

    // Exit immediately to avoid blocking on tokio's stdin background thread,
    // which can't be cancelled and would hang until the next key press.
    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
