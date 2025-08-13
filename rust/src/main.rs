mod query_runner;
mod ruleset;
mod runner;
mod scoring;

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Path to the file to check
    file: String,

    /// Path to the ruleset folder
    #[arg(long)]
    ruleset: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let res = runner::run_file(&cli.file, &cli.ruleset)?;
    println!("{}", serde_json::to_string_pretty(&res)?);
    Ok(())
}
