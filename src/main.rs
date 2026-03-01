mod cli;
mod core;
mod error;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    cli::dispatch(cli)
}
