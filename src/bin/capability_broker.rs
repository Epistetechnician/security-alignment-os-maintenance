//! Separate capability broker process.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use security_alignment_os::broker::{Broker, BrokerConfig};
use security_alignment_os::receipts::ReceiptSigner;
use security_alignment_os::EvidenceRegistry;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

fn main() {
    let mut args = env::args_os();
    let _program = args.next();
    let values: Vec<PathBuf> = args.map(PathBuf::from).collect();
    if values.len() != 5 {
        std::process::exit(2);
    }
    let evidence = match EvidenceRegistry::load(&values[3]) {
        Ok(value) => value,
        Err(_) => std::process::exit(2),
    };
    let mut seed = [0u8; 32];
    if File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut seed))
        .is_err()
    {
        std::process::exit(2);
    }
    let signer = match ReceiptSigner::from_seed("broker-ephemeral-v1", seed) {
        Ok(value) => value,
        Err(_) => std::process::exit(2),
    };
    let config = BrokerConfig {
        socket_path: values[0].clone(),
        workspace: values[1].clone(),
        journal_path: values[2].clone(),
        supervisor_path: values[4].clone(),
        kill_after_executing: env::var_os("BROKER_KILL_AFTER_EXECUTING").is_some_and(|v| v == "1"),
    };
    let broker = match Broker::new(config, evidence, signer) {
        Ok(value) => value,
        Err(_) => std::process::exit(2),
    };
    #[cfg(unix)]
    if broker.serve().is_err() {
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    std::process::exit(2);
}
