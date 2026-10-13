//! Digest-only verifier for an exchanged fixed-maintenance replication packet.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//! Usage: `maintenance_replication_verifier PACKET.json`.
//!
//! This entrypoint validates packet structure, signatures, bindings, and
//! canonical bytes. It does not execute maintenance, contact another host, or
//! authenticate the declared host and operator labels.

use security_alignment_os::maintenance_replication::ReplicationPacket;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

#[derive(Serialize)]
struct VerificationOutput<'a> {
    status: &'a str,
    verdict: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    packet_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn emit(output: VerificationOutput<'_>, code: i32) -> ! {
    println!(
        "{}",
        serde_json::to_string(&output).expect("verification output serialization")
    );
    std::process::exit(code);
}

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let Some(packet_path) = args.next() else {
        eprintln!("usage: maintenance_replication_verifier PACKET.json");
        std::process::exit(2);
    };
    if args.next().is_some() {
        eprintln!("unexpected argument");
        std::process::exit(2);
    }
    let packet_path = PathBuf::from(packet_path);
    let bytes = match fs::read(&packet_path) {
        Ok(bytes) => bytes,
        Err(error) => emit(
            VerificationOutput {
                status: "invalid_local_packet",
                verdict: "Invalid",
                packet_id: None,
                error: Some(format!("packet bytes unavailable: {error}")),
            },
            1,
        ),
    };
    match ReplicationPacket::from_canonical_bytes(&bytes) {
        Ok(packet) => emit(
            VerificationOutput {
                status: "valid_local_packet",
                verdict: "Inconclusive",
                packet_id: Some(&packet.packet_id),
                error: None,
            },
            0,
        ),
        Err(error) => emit(
            VerificationOutput {
                status: "invalid_local_packet",
                verdict: "Invalid",
                packet_id: None,
                error: Some(error.to_string()),
            },
            1,
        ),
    }
}
