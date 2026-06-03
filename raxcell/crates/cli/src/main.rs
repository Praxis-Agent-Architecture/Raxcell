mod jsonrpc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use raxcell_core::{explain_backend, prepare_run, probe, resolve_profile, run};
use raxcell_protocol::{ExplainBackendRequest, ProbeRequest, ResolveProfileRequest, RunRequest};
use std::io::{self, Read};

#[derive(Debug, Parser)]
#[command(name = "raxcell")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Probe {
        #[arg(long)]
        json: Option<String>,
        #[arg(long)]
        stdin: bool,
    },
    ExplainBackend {
        #[arg(long)]
        json: Option<String>,
        #[arg(long)]
        stdin: bool,
    },
    Run {
        #[arg(long)]
        json: Option<String>,
        #[arg(long)]
        stdin: bool,
    },
    PrepareRun {
        #[arg(long)]
        json: Option<String>,
        #[arg(long)]
        stdin: bool,
    },
    ResolveProfile {
        #[arg(long)]
        json: Option<String>,
        #[arg(long)]
        stdin: bool,
    },
    Worker,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Probe { json, stdin } => {
            let request: ProbeRequest = serde_json::from_str(&read_json(json, stdin)?)?;
            println!("{}", serde_json::to_string(&probe(request))?);
        }
        Command::ExplainBackend { json, stdin } => {
            let request: ExplainBackendRequest = serde_json::from_str(&read_json(json, stdin)?)?;
            println!("{}", serde_json::to_string(&explain_backend(request))?);
        }
        Command::Run { json, stdin } => {
            let request: RunRequest = serde_json::from_str(&read_json(json, stdin)?)?;
            println!("{}", serde_json::to_string(&run(request))?);
        }
        Command::PrepareRun { json, stdin } => {
            let request: RunRequest = serde_json::from_str(&read_json(json, stdin)?)?;
            println!("{}", serde_json::to_string(&prepare_run(request))?);
        }
        Command::ResolveProfile { json, stdin } => {
            let request: ResolveProfileRequest = serde_json::from_str(&read_json(json, stdin)?)?;
            println!("{}", serde_json::to_string(&resolve_profile(request)?)?);
        }
        Command::Worker => jsonrpc::run_worker().await?,
    }
    Ok(())
}

fn read_json(json: Option<String>, stdin: bool) -> Result<String> {
    if let Some(json) = json {
        return Ok(json);
    }
    if stdin {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        return Ok(input);
    }
    anyhow::bail!("provide --json '<request>' or --stdin")
}

#[cfg(test)]
#[path = "jsonrpc_tests.rs"]
mod jsonrpc_tests;
