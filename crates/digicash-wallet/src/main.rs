//! The digicash wallet CLI binary: parse arguments and dispatch to the wallet library.

use std::io::Write;
use std::process::ExitCode;

use clap::Parser;
use digicash_wallet::{run, Cli};

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "error: {error}");
            ExitCode::FAILURE
        }
    }
}
