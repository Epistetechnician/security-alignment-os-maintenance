//! Prints source identity inputs for an immutable Nitro image build.
//!
//! State slices: `security-alignment-os-foundation-v1` and
//! `maintenance-platform-runner-hermetic-e2e-v1`.

#[path = "../../build_support/source_identity.rs"]
mod source_identity;

use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct OutputIdentity {
    implementation_revision: String,
    source_tree_sha256: String,
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let identity = source_identity::derive_clean_checkout_identity(root).unwrap_or_else(|error| {
        eprintln!("Nitro image source identity rejected: {error}");
        std::process::exit(1);
    });
    let output = OutputIdentity {
        implementation_revision: identity.implementation_revision,
        source_tree_sha256: identity.source_tree_sha256,
    };
    println!(
        "{}",
        serde_json::to_string(&output).expect("identity serializes")
    );
}
