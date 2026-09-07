//! Independent supervisor entrypoint for the broker vertical slice.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use security_alignment_os::broker::run_supervisor_job;
use std::env;
use std::path::PathBuf;

fn main() {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(flag) = args.next() else {
        std::process::exit(2);
    };
    let Some(job) = args.next() else {
        std::process::exit(2);
    };
    if flag != "--job" || args.next().is_some() {
        std::process::exit(2);
    }
    let outcome = match run_supervisor_job(&PathBuf::from(job)) {
        Ok(value) => value,
        Err(_) => std::process::exit(1),
    };
    if serde_json::to_writer(std::io::stdout(), &outcome).is_err() {
        std::process::exit(1);
    }
}
