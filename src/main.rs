//! QUIC pipe - Simple QUIC-based data forwarding tool.

use clap::Parser;

mod client;
mod config;
mod endpoint;
mod server;
mod stream;

use config::{Args, Commands};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    let res = match args.command {
        Commands::Listen(args) => server::listen_stdio(args).await,
        Commands::Connect(args) => client::connect_stdio(args).await,
        Commands::ListenTcp(args) => server::listen_tcp(args).await,
        Commands::ConnectTcp(args) => client::connect_tcp(args).await,
    };
    match res {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1)
        }
    }
}
