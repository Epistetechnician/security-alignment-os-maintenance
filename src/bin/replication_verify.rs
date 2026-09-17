//! Verify a signed replication result in a separate local process.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//! This verifies caller-supplied bytes; it does not authenticate a host,
//! operator, provider, model, or scientific validator.

use security_alignment_os::replication::{
    compare, FrozenReplicationPacket, ReplicationDisposition, SignedReplicationResult,
};
use std::env;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("replication verifier failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let packet_path = PathBuf::from(arguments.next().ok_or("missing packet path")?);
    let result_path = PathBuf::from(arguments.next().ok_or("missing signed result path")?);
    let signer_key_id = arguments.next().ok_or("missing signer key ID")?;
    let public_key_hex = arguments.next().ok_or("missing public key")?;
    if arguments.next().is_some() {
        return Err("unexpected command arguments".into());
    }

    let packet = FrozenReplicationPacket::load(&packet_path)?;
    let signed = SignedReplicationResult::load(&result_path)?;
    let public_key = decode_public_key(&public_key_hex)?;
    if compare(&packet, &signed, &signer_key_id, public_key)? != ReplicationDisposition::Matched {
        return Err("replication result was not matched".into());
    }
    println!("MATCHED {}", packet.packet_digest);
    Ok(())
}

fn decode_public_key(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if value.len() != 64 {
        return Err("public key must be 32 bytes encoded as 64 lowercase hex characters".into());
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk)?;
        if !text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("public key must use lowercase hexadecimal".into());
        }
        bytes[index] = u8::from_str_radix(text, 16)?;
    }
    Ok(bytes)
}
