//! Mainnet and general reference-test runner entrypoint.

use std::process::ExitCode;

fn main() -> ExitCode {
    match tests::run_from_env() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
