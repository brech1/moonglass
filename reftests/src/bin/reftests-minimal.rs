//! Minimal preset reference-test runner entrypoint.

use std::process::ExitCode;

fn main() -> ExitCode {
    match reftests::run_from_env() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
