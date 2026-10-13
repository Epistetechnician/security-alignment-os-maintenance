//! One-shot broker for the fixed maintenance process.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//! Usage: `maintenance_broker <config.json> <request.json>`.

use security_alignment_os::maintenance_process::{run, Config, Request};
use std::fs;
use std::path::PathBuf;

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let (Some(config_path), Some(request_path)) = (args.next(), args.next()) else {
        eprintln!("usage: maintenance_broker CONFIG REQUEST");
        std::process::exit(2);
    };
    if args.next().is_some() {
        eprintln!("unexpected argument");
        std::process::exit(2);
    }
    let config_path = PathBuf::from(config_path);
    let request_path = PathBuf::from(request_path);
    let config: Config = match fs::read(&config_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(value) => value,
        None => {
            println!(r#"{{"error":"configuration JSON is invalid"}}"#);
            std::process::exit(2);
        }
    };
    let request: Request = match fs::read(&request_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(value) => value,
        None => {
            println!(r#"{{"error":"request JSON is invalid"}}"#);
            std::process::exit(2);
        }
    };
    match run(&config, &request) {
        Ok(outcome) => println!(
            "{}",
            serde_json::to_string(&outcome).expect("outcome serialization")
        ),
        Err(error) => {
            eprintln!("maintenance broker error: {error}");
            println!(
                r#"{{"error":{}}}"#,
                serde_json::to_string(&error.to_string()).expect("error serialization")
            );
            std::process::exit(1);
        }
    }
}
