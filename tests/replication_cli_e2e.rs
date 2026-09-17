//! Separate-process replication handoff verification.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//! This is local process evidence, not independent host or operator evidence.

use security_alignment_os::replication::{
    FrozenReplicationPacket, ReplicationResult, ReplicationSigner, ReplicationTerminal,
};
use std::collections::BTreeSet;
use std::process::Command;
use tempfile::TempDir;

fn digest(value: char) -> String {
    format!("{:064x}", value as u32)
}

fn packet() -> FrozenReplicationPacket {
    FrozenReplicationPacket::new(
        "packet-cli-1",
        digest('a'),
        digest('b'),
        digest('c'),
        digest('d'),
        digest('e'),
        ReplicationTerminal::Completed,
        Some(digest('f')),
        digest('g'),
        digest('h'),
        digest('i'),
        false,
        BTreeSet::from(["local-process".into()]),
        100,
    )
    .expect("packet")
}

fn invoke_verifier(
    directory: &TempDir,
    packet_path: &std::path::Path,
    result_path: &std::path::Path,
    signer: &ReplicationSigner,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_replication_verify"))
        .arg(packet_path)
        .arg(result_path)
        .arg(signer.key_id())
        .arg(hex(signer.verifying_key_bytes()))
        .current_dir(directory.path())
        .output()
        .expect("spawn replication verifier")
}

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn verifier_process_accepts_exact_signed_handoff_and_rejects_mismatch() {
    let directory = tempfile::tempdir().expect("directory");
    let packet = packet();
    let signer = ReplicationSigner::from_seed("replication-key-cli", [17; 32]).expect("signer");
    let result = ReplicationResult::new(
        &packet,
        "operator-b",
        "host-b",
        ReplicationTerminal::Completed,
        Some(digest('f')),
        digest('g'),
        digest('h'),
        digest('i'),
        false,
        10,
    )
    .expect("result");
    let signed = signer.sign(result).expect("signed result");
    let packet_path = directory.path().join("packet.json");
    let result_path = directory.path().join("result.json");
    packet.save(&packet_path).expect("packet save");
    signed.save(&result_path).expect("result save");

    let matched = invoke_verifier(&directory, &packet_path, &result_path, &signer);
    assert!(
        matched.status.success(),
        "verifier stderr: {:?}",
        matched.stderr
    );
    assert!(String::from_utf8_lossy(&matched.stdout).starts_with("MATCHED "));

    let changed = ReplicationResult::new(
        &packet,
        "operator-b",
        "host-b",
        ReplicationTerminal::Completed,
        Some(digest('f')),
        digest('g'),
        digest('z'),
        digest('i'),
        false,
        10,
    )
    .expect("changed result");
    signer
        .sign(changed)
        .expect("changed signed result")
        .save(&result_path)
        .expect("changed result save");
    let rejected = invoke_verifier(&directory, &packet_path, &result_path, &signer);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("replication verifier failed"));
}
