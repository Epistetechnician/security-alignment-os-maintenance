//! Local tests for Nitro image source identity and build wiring.
//!
//! State slices: `security-alignment-os-foundation-v1` and
//! `maintenance-platform-runner-hermetic-e2e-v1`.

#[path = "../build_support/source_identity.rs"]
mod source_identity;

const DOCKERFILE: &str = include_str!("../infra/nitro-enclave/Dockerfile");
const BUILD_SCRIPT: &str = include_str!("../build.rs");
const RUNNER_SOURCE: &str = include_str!("../src/bin/maintenance_nitro_enclave_runner.rs");

fn git(root: &std::path::Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("git is installed for hermetic source identity tests");
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn committed_source_fixture() -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("temporary source identity repository");
    let root = temp.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("build_support")).unwrap();
    std::fs::create_dir_all(root.join("infra/nitro-enclave")).unwrap();
    for (path, contents) in [
        ("Cargo.toml", "[package]\nname = \"fixture\"\n"),
        ("Cargo.lock", "# fixture lock\n"),
        ("build.rs", "fn main() {}\n"),
        (
            "build_support/source_identity.rs",
            "pub const FIXTURE: u8 = 1;\n",
        ),
        (
            "infra/nitro-enclave/Dockerfile",
            "FROM rust:1.87-bookworm\n",
        ),
        ("src/lib.rs", "pub const FIXTURE: u8 = 1;\n"),
    ] {
        std::fs::write(root.join(path), contents).unwrap();
    }
    git(root, &["init", "-q"]);
    git(root, &["config", "user.name", "Local Test"]);
    git(
        root,
        &["config", "user.email", "local-test@example.invalid"],
    );
    git(
        root,
        &[
            "add",
            "Cargo.toml",
            "Cargo.lock",
            "build.rs",
            "build_support",
            "infra/nitro-enclave",
            "src",
        ],
    );
    git(root, &["commit", "-qm", "fixture"]);
    temp
}

#[test]
fn source_digest_matches_only_the_exact_build_inputs() {
    let temp = committed_source_fixture();
    let identity = source_identity::derive_clean_checkout_identity(temp.path()).unwrap();
    assert_eq!(identity.implementation_revision.len(), 40);
    source_identity::validate_revision(&identity.implementation_revision).unwrap();
    source_identity::validate_sha256(&identity.source_tree_sha256).unwrap();
    assert_eq!(
        source_identity::verify_source_digest(temp.path(), &identity.source_tree_sha256).unwrap(),
        identity.source_tree_sha256
    );

    let mut wrong_digest = identity.source_tree_sha256.clone().into_bytes();
    wrong_digest[0] = if wrong_digest[0] == b'0' { b'1' } else { b'0' };
    let wrong_digest = String::from_utf8(wrong_digest).unwrap();
    assert!(source_identity::verify_source_digest(temp.path(), &wrong_digest).is_err());
}

#[test]
fn dirty_untracked_and_ignored_source_inputs_cannot_claim_a_commit_identity() {
    let temp = committed_source_fixture();
    let root = temp.path();
    std::fs::write(root.join("src/lib.rs"), "pub const FIXTURE: u8 = 2;\n").unwrap();
    assert!(source_identity::derive_clean_checkout_identity(root).is_err());
    git(root, &["checkout", "--", "src/lib.rs"]);

    std::fs::write(root.join("src/untracked.rs"), "pub const EXTRA: u8 = 1;\n").unwrap();
    assert!(source_identity::derive_clean_checkout_identity(root).is_err());
    std::fs::remove_file(root.join("src/untracked.rs")).unwrap();

    std::fs::write(root.join(".gitignore"), "src/ignored.rs\n").unwrap();
    git(root, &["add", ".gitignore"]);
    git(root, &["commit", "-qm", "ignore fixture file"]);
    std::fs::write(root.join("src/ignored.rs"), "pub const EXTRA: u8 = 2;\n").unwrap();
    assert!(source_identity::derive_clean_checkout_identity(root).is_err());
}

#[test]
fn image_build_checks_source_digest_before_embedding_identity() {
    assert!(BUILD_SCRIPT.contains("NITRO_IMAGE_BUILD"));
    assert!(BUILD_SCRIPT.contains("verify_source_digest"));
    assert!(BUILD_SCRIPT.contains("NITRO_IMAGE_IMPLEMENTATION_REVISION"));
    assert!(BUILD_SCRIPT.contains("NITRO_IMAGE_SOURCE_TREE_SHA256"));

    assert!(DOCKERFILE.contains("ARG IMPLEMENTATION_REVISION"));
    assert!(DOCKERFILE.contains("ARG SOURCE_TREE_SHA256"));
    assert!(DOCKERFILE.contains("COPY Cargo.toml Cargo.lock build.rs ./"));
    assert!(DOCKERFILE.contains("COPY build_support ./build_support"));
    assert!(DOCKERFILE.contains("COPY infra/nitro-enclave ./infra/nitro-enclave"));
    assert!(DOCKERFILE.contains("RUN NITRO_IMAGE_BUILD=1 cargo build --release --locked"));
    assert!(!DOCKERFILE.contains("ENV IMPLEMENTATION_REVISION"));
    assert!(!DOCKERFILE.contains("ENV SOURCE_TREE_SHA256"));

    assert!(RUNNER_SOURCE.contains("option_env!(\"NITRO_IMAGE_IMPLEMENTATION_REVISION\")"));
    assert!(RUNNER_SOURCE.contains("option_env!(\"NITRO_IMAGE_SOURCE_TREE_SHA256\")"));
    assert!(RUNNER_SOURCE.contains("reject_runtime_identity_overrides"));
}

#[test]
fn image_build_identity_requires_lowercase_full_digests() {
    assert!(source_identity::validate_revision(&"a".repeat(40)).is_ok());
    for invalid in ["", "abc", &"A".repeat(40), &"g".repeat(40)] {
        assert!(source_identity::validate_revision(invalid).is_err());
    }

    assert!(source_identity::validate_sha256(&"b".repeat(64)).is_ok());
    for invalid in ["", "abc", &"B".repeat(64), &"g".repeat(64)] {
        assert!(source_identity::validate_sha256(invalid).is_err());
    }
}

#[test]
fn image_installs_expected_binaries_under_the_unprivileged_entrypoint() {
    for binary in [
        "maintenance_broker",
        "maintenance_evaluator",
        "maintenance_replication_runner",
        "maintenance_nitro_enclave_runner",
    ] {
        assert!(DOCKERFILE.contains(&format!("--bin {binary}")));
        assert!(DOCKERFILE.contains(&format!(
            "/build/target/release/{binary} /opt/maintenance/bin/{binary}"
        )));
    }
    assert!(DOCKERFILE.contains("USER replication"));
    assert!(DOCKERFILE
        .contains("ENTRYPOINT [\"/opt/maintenance/bin/maintenance_nitro_enclave_runner\"]"));
    for binary in [
        "maintenance_broker",
        "maintenance_evaluator",
        "maintenance_replication_runner",
    ] {
        assert!(RUNNER_SOURCE.contains(&format!("Path::new(\"/opt/maintenance/bin/{binary}\")")));
    }
}
