//! Command-line harness orchestration, reporting, and process isolation.

mod app;
mod color;
mod report;
mod trace;
mod worker;

pub(crate) use app::run_from_env;
