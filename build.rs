#[path = "build_support/source_identity.rs"]
mod source_identity;

use std::env;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=NITRO_IMAGE_BUILD");
    println!("cargo:rerun-if-env-changed=IMPLEMENTATION_REVISION");
    println!("cargo:rerun-if-env-changed=SOURCE_TREE_SHA256");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support");
    println!("cargo:rerun-if-changed=infra/nitro-enclave");
    println!("cargo:rerun-if-changed=src");

    if let Ok(files) = source_identity::source_files(Path::new(
        &env::var("CARGO_MANIFEST_DIR").expect("Cargo sets manifest directory"),
    )) {
        for file in files {
            println!("cargo:rerun-if-changed={}", file.display());
        }
    }

    if env::var("NITRO_IMAGE_BUILD").ok().as_deref() != Some("1") {
        return;
    }

    let revision = env::var("IMPLEMENTATION_REVISION")
        .expect("IMPLEMENTATION_REVISION is required for Nitro image builds");
    source_identity::validate_revision(&revision)
        .expect("IMPLEMENTATION_REVISION must be a 40-character lowercase commit ID");

    let expected_digest = env::var("SOURCE_TREE_SHA256")
        .expect("SOURCE_TREE_SHA256 is required for Nitro image builds");
    let actual_digest = source_identity::verify_source_digest(
        Path::new(&env::var("CARGO_MANIFEST_DIR").expect("Cargo sets manifest directory")),
        &expected_digest,
    )
    .expect("Nitro image source tree does not match SOURCE_TREE_SHA256");

    println!("cargo:rustc-env=NITRO_IMAGE_IMPLEMENTATION_REVISION={revision}");
    println!("cargo:rustc-env=NITRO_IMAGE_SOURCE_TREE_SHA256={actual_digest}");
}
