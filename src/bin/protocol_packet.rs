//! Generate and validate a fresh, synthetic three-split protocol packet.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//! The packet is local test material only. It contains no private data,
//! credentials, model traces, external corpus, or scientific result.

use security_alignment_os::fresh_packet::{
    DocumentHeader, Manifest, ManifestEntry, AUTHOR, CREATED_ON, DOCUMENTS_PER_SPLIT,
    EXPECTED_DOCUMENTS, EXPECTED_FAMILIES_PER_SPLIT, FAMILIES_PER_DOCUMENT, GENERATOR_REVISION,
    PACKET_SCHEMA, PROTOCOL_ID, SOURCE,
};
use security_alignment_os::{canonical_bytes, digest, digest_bytes, STATE_SLICE};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MANIFEST_FILE: &str = "manifest.json";
const REVIEW_FILE: &str = "local-review.json";
const DRY_RUN_FILE: &str = "dry-run.json";
const FREEZE_FILE: &str = "protocol-freeze.json";

const DOMAINS: [&str; 12] = [
    "evidence lineage",
    "bounded resource accounting",
    "reversible state transitions",
    "reviewer separation",
    "custody retention",
    "replay resistance",
    "contract evolution",
    "observation quality",
    "failure quarantine",
    "claim ceilings",
    "operator handoff",
    "artifact provenance",
];

const CONTROLS: [&str; 12] = [
    "bind the exact predecessor digest",
    "require a distinct validator assertion",
    "reject stale state before mutation",
    "preserve the last known-good checkpoint",
    "record only digest-level evidence",
    "make the terminal disposition explicit",
    "recompute the manifest before admission",
    "keep the proposed action below the claim ceiling",
    "separate observation from authorization",
    "make replay idempotent without appending",
    "quarantine contradictory inputs",
    "retain a bounded review window",
];

const METHODS: [&str; 12] = [
    "a two-person review",
    "a canonical byte comparison",
    "a deterministic replay check",
    "an explicit state-machine transition",
    "a fixed input commitment",
    "a temporary-file recovery test",
    "a negative-path assertion",
    "a digest-bound handoff",
    "a bounded dry run",
    "a retention-window check",
    "a role-collision check",
    "a terminal-freeze check",
];

const OUTCOMES: [&str; 12] = [
    "the record remains reviewable without gaining authority",
    "the proposed transition is accepted only as local evidence",
    "the ambiguous case enters quarantine without a retry side effect",
    "the frozen predecessor remains recoverable",
    "the result can be compared by an independent checker",
    "the claim is narrowed to the exact observed fixture",
    "the output remains outside any production release path",
    "the packet can be reproduced from its declared inputs",
    "the decision cannot be upgraded by a model-generated label",
    "the local result does not imply external correctness",
    "the custody assertion remains caller-owned",
    "the protocol identity closes if a bound byte changes",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct LocalReview {
    schema: String,
    state_slice: String,
    protocol_id: String,
    status: String,
    manifest_sha256: String,
    document_count: usize,
    documents_by_split: BTreeMap<String, usize>,
    families_by_split: BTreeMap<String, usize>,
    family_duplicates: Vec<String>,
    custody_mode: String,
    notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct DryRunReport {
    schema: String,
    state_slice: String,
    protocol_id: String,
    status: String,
    manifest_sha256: String,
    reviewed_documents: usize,
    would_sign: bool,
    would_contact_network: bool,
    would_move_value: bool,
    would_authorize_payout: bool,
    side_effects: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ProtocolFreeze {
    schema: String,
    state_slice: String,
    protocol_id: String,
    status: String,
    local_review: String,
    manifest_sha256: String,
    local_review_sha256: String,
    dry_run_sha256: String,
    frozen_documents: usize,
    frozen_families_by_split: BTreeMap<String, usize>,
    claim_ceiling: String,
    notes: Vec<String>,
}

#[derive(Clone, Debug)]
struct ValidatedPacket {
    manifest: Manifest,
    manifest_sha256: String,
    review: LocalReview,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("protocol packet command failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or("missing command")?;
    let root = PathBuf::from(arguments.next().ok_or("missing custody root")?);
    if arguments.next().is_some() {
        return Err("unexpected command arguments".into());
    }
    match command.as_str() {
        "generate" => generate(&root),
        "validate" => {
            validate_and_write(&root)?;
            println!("LOCAL_PASS {}", root.display());
            Ok(())
        }
        "dry-run" => {
            dry_run(&root)?;
            println!("DRY_RUN_PASS {}", root.display());
            Ok(())
        }
        "freeze" => {
            freeze(&root)?;
            println!("FROZEN {}", root.display());
            Ok(())
        }
        _ => Err("command must be generate, validate, dry-run, or freeze".into()),
    }
}

fn generate(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if root.exists() {
        return Err(format!("custody root already exists: {}", root.display()).into());
    }
    let parent = root.parent().ok_or("custody root has no parent")?;
    fs::create_dir_all(parent)?;
    fs::create_dir(root)?;
    set_mode(root, 0o700)?;

    let mut entries = Vec::with_capacity(EXPECTED_DOCUMENTS);
    for (split_index, split) in ["fit", "tune", "assessment"].into_iter().enumerate() {
        let split_root = root.join(split);
        fs::create_dir(&split_root)?;
        set_mode(&split_root, 0o700)?;
        for document_index in 0..DOCUMENTS_PER_SPLIT {
            let first_family = document_index * FAMILIES_PER_DOCUMENT;
            let families = (0..FAMILIES_PER_DOCUMENT)
                .map(|offset| format!("{split}-family-{:04}", first_family + offset + 1))
                .collect::<Vec<_>>();
            let document_id = format!("{split}-{:03}", document_index + 1);
            let path = format!("{split}/{document_id}.md");
            let bytes =
                document_bytes(split, split_index, document_index, &document_id, &families)?;
            write_private(&root.join(&path), &bytes)?;
            entries.push(ManifestEntry {
                source: SOURCE.into(),
                revision: GENERATOR_REVISION.into(),
                split: split.into(),
                author: AUTHOR.into(),
                path,
                sha256: digest_bytes(&bytes),
                families,
            });
        }
    }
    let manifest = Manifest {
        schema: PACKET_SCHEMA.into(),
        state_slice: STATE_SLICE.into(),
        protocol_id: PROTOCOL_ID.into(),
        created_on: CREATED_ON.into(),
        document_count: entries.len(),
        families_per_document: FAMILIES_PER_DOCUMENT,
        documents: entries,
    };
    write_private(&root.join(MANIFEST_FILE), &canonical_bytes(&manifest)?)?;
    println!(
        "GENERATED {} documents and {} families per split at {}",
        EXPECTED_DOCUMENTS,
        EXPECTED_FAMILIES_PER_SPLIT,
        root.display()
    );
    Ok(())
}

fn document_bytes(
    split: &str,
    split_index: usize,
    document_index: usize,
    document_id: &str,
    families: &[String],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let fresh_nonce = digest(&(PROTOCOL_ID, split, document_index, families))?;
    let header = DocumentHeader {
        schema: PACKET_SCHEMA.into(),
        state_slice: STATE_SLICE.into(),
        protocol_id: PROTOCOL_ID.into(),
        document_id: document_id.into(),
        source: SOURCE.into(),
        revision: GENERATOR_REVISION.into(),
        split: split.into(),
        author: AUTHOR.into(),
        families: families.to_vec(),
        fresh_nonce: fresh_nonce.clone(),
    };
    let header_bytes = canonical_bytes(&header)?;
    let domain = DOMAINS[(document_index + split_index * 3) % DOMAINS.len()];
    let control = CONTROLS[(document_index * 5 + split_index) % CONTROLS.len()];
    let method = METHODS[(document_index * 7 + split_index * 2) % METHODS.len()];
    let outcome = OUTCOMES[(document_index * 11 + split_index) % OUTCOMES.len()];
    let mut body = format!(
        "# Fresh protocol fixture {document_id}\n\n\
This synthetic document is generated for the {split} split and is identified by\n\
fresh nonce `{fresh_nonce}`. It is new local fixture material, not an imported\n\
research trace or external corpus document.\n\n\
## Declared family coverage\n\n"
    );
    for family in families {
        body.push_str(&format!("- `{family}`\n"));
    }
    body.push_str(&format!(
        "\n## Bounded record\n\nThe fixture studies {domain}. It requires that the\noperator {control} using {method}; the expected local disposition is that\n{outcome}. This statement is a protocol fixture description only. It is not a\nmodel output, an assessment result, evidence of alignment, or authorization for\nexternal execution.\n\n## Freshness binding\n\nThe byte identity is bound by the manifest SHA-256 and by the header fields:\nsource `{SOURCE}`, revision `{GENERATOR_REVISION}`, split `{split}`, author\n`{AUTHOR}`, and the eight distinct family identifiers above.\n"
    ));
    let mut bytes = header_bytes;
    bytes.push(b'\n');
    bytes.append(&mut body.into_bytes());
    Ok(bytes)
}

fn validate_and_write(root: &Path) -> Result<ValidatedPacket, Box<dyn std::error::Error>> {
    let packet = validate_root(root)?;
    write_private_or_verify(&root.join(REVIEW_FILE), &canonical_bytes(&packet.review)?)?;
    Ok(packet)
}

fn validate_root(root: &Path) -> Result<ValidatedPacket, Box<dyn std::error::Error>> {
    let root_metadata = fs::metadata(root)?;
    if !root_metadata.is_dir() || root_metadata.permissions().mode() & 0o777 != 0o700 {
        return Err("custody root must be a directory with mode 0700".into());
    }
    let manifest_path = root.join(MANIFEST_FILE);
    let manifest_bytes = read_private_file(&manifest_path, 0o600)?;
    let manifest = Manifest::from_canonical_bytes(&manifest_bytes)?;

    let mut documents_by_split = BTreeMap::new();
    let mut families_by_split = BTreeMap::new();
    let mut split_families = BTreeMap::<String, BTreeSet<String>>::new();
    for entry in &manifest.documents {
        let document_path = root.join(Path::new(&entry.path));
        let bytes = read_private_file(&document_path, 0o600)?;
        if digest_bytes(&bytes) != entry.sha256 {
            return Err(format!("SHA-256 mismatch for {}", entry.path).into());
        }
        let mut reader = BufReader::new(bytes.as_slice());
        let mut header_line = String::new();
        reader.read_line(&mut header_line)?;
        let header = DocumentHeader::from_canonical_line(header_line.trim_end().as_bytes())?;
        header.validate_for_entry(entry)?;
        if reader.lines().next().is_none() {
            return Err(format!("document body is empty for {}", entry.path).into());
        }
        *documents_by_split.entry(entry.split.clone()).or_insert(0) += 1;
        let family_set = split_families.entry(entry.split.clone()).or_default();
        for family in &entry.families {
            if !family_set.insert(family.clone()) {
                return Err(format!("duplicate family {} in {}", family, entry.split).into());
            }
        }
    }
    for split in ["fit", "tune", "assessment"] {
        let document_count = documents_by_split.get(split).copied().unwrap_or_default();
        let family_count = split_families.get(split).map_or(0, BTreeSet::len);
        if document_count != DOCUMENTS_PER_SPLIT || family_count != EXPECTED_FAMILIES_PER_SPLIT {
            return Err(format!("split {split} has invalid document/family counts").into());
        }
        families_by_split.insert(split.into(), family_count);
    }
    let review = LocalReview {
        schema: PACKET_SCHEMA.into(),
        state_slice: STATE_SLICE.into(),
        protocol_id: PROTOCOL_ID.into(),
        status: "LOCAL_PASS".into(),
        manifest_sha256: digest_bytes(&manifest_bytes),
        document_count: manifest.documents.len(),
        documents_by_split,
        families_by_split,
        family_duplicates: Vec::new(),
        custody_mode: "0700-root-0600-files".into(),
        notes: vec![
            "synthetic local fixtures only".into(),
            "no external corpus, private data, model trace, credential, or provider call".into(),
            "LOCAL_PASS is local validation evidence, not independent scientific acceptance".into(),
        ],
    };
    Ok(ValidatedPacket {
        manifest,
        manifest_sha256: review.manifest_sha256.clone(),
        review,
    })
}

fn dry_run(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let packet = validate_root(root)?;
    let report = DryRunReport {
        schema: PACKET_SCHEMA.into(),
        state_slice: STATE_SLICE.into(),
        protocol_id: PROTOCOL_ID.into(),
        status: "DRY_RUN_PASS".into(),
        manifest_sha256: packet.manifest_sha256,
        reviewed_documents: packet.manifest.documents.len(),
        would_sign: false,
        would_contact_network: false,
        would_move_value: false,
        would_authorize_payout: false,
        side_effects: Vec::new(),
    };
    write_private_or_verify(&root.join(DRY_RUN_FILE), &canonical_bytes(&report)?)?;
    Ok(())
}

fn freeze(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let packet = validate_root(root)?;
    let review_bytes = read_private_file(&root.join(REVIEW_FILE), 0o600)?;
    let review: LocalReview = serde_json::from_slice(&review_bytes)?;
    if canonical_bytes(&review)? != review_bytes
        || review.status != "LOCAL_PASS"
        || review.manifest_sha256 != packet.manifest_sha256
    {
        return Err("protocol freeze requires a matching LOCAL_PASS review".into());
    }
    let dry_run_bytes = read_private_file(&root.join(DRY_RUN_FILE), 0o600)?;
    let dry_run: DryRunReport = serde_json::from_slice(&dry_run_bytes)?;
    if canonical_bytes(&dry_run)? != dry_run_bytes
        || dry_run.status != "DRY_RUN_PASS"
        || dry_run.manifest_sha256 != packet.manifest_sha256
        || dry_run.would_sign
        || dry_run.would_contact_network
        || dry_run.would_move_value
        || dry_run.would_authorize_payout
        || !dry_run.side_effects.is_empty()
    {
        return Err("protocol freeze requires a matching dry-run report".into());
    }
    let freeze = ProtocolFreeze {
        schema: PACKET_SCHEMA.into(),
        state_slice: STATE_SLICE.into(),
        protocol_id: PROTOCOL_ID.into(),
        status: "FROZEN".into(),
        local_review: "LOCAL_PASS".into(),
        manifest_sha256: packet.manifest_sha256,
        local_review_sha256: digest_bytes(&review_bytes),
        dry_run_sha256: digest_bytes(&dry_run_bytes),
        frozen_documents: packet.manifest.documents.len(),
        frozen_families_by_split: packet.review.families_by_split,
        claim_ceiling: "local synthetic protocol fixture and caller-owned custody evidence only"
            .into(),
        notes: vec![
            "freeze is local metadata and does not authorize model execution or assessment effects"
                .into(),
            "do not retune, replace, or reopen this packet under the same protocol identity".into(),
        ],
    };
    write_private_or_verify(&root.join(FREEZE_FILE), &canonical_bytes(&freeze)?)?;
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    set_mode(path, 0o600)?;
    Ok(())
}

fn write_private_or_verify(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
                return Err(format!("{} is not a regular private file", path.display()).into());
            }
            let existing = read_private_file(path, 0o600)?;
            if existing != bytes {
                return Err(format!("existing record differs: {}", path.display()).into());
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => write_private(path, bytes),
        Err(error) => Err(error.into()),
    }
}

fn read_private_file(
    path: &Path,
    expected_mode: u32,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o777 != expected_mode {
        return Err(format!("{} is not a regular private file", path.display()).into());
    }
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn set_mode(path: &Path, mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use security_alignment_os::fresh_packet::document_index;

    #[test]
    fn generated_documents_are_unique_and_partitioned() {
        let mut document_digests = BTreeSet::new();
        let mut family_ids = BTreeSet::new();

        for (split_index, split) in ["fit", "tune", "assessment"].into_iter().enumerate() {
            let mut split_families = BTreeSet::new();
            for document_index in 0..DOCUMENTS_PER_SPLIT {
                let first_family = document_index * FAMILIES_PER_DOCUMENT;
                let families = (0..FAMILIES_PER_DOCUMENT)
                    .map(|offset| format!("{split}-family-{:04}", first_family + offset + 1))
                    .collect::<Vec<_>>();
                let document_id = format!("{split}-{:03}", document_index + 1);
                let bytes =
                    document_bytes(split, split_index, document_index, &document_id, &families)
                        .expect("document bytes");
                assert!(document_digests.insert(digest_bytes(&bytes)));
                for family in &families {
                    assert!(split_families.insert(family.clone()));
                    assert!(family_ids.insert(family.clone()));
                }
                let header_line = String::from_utf8(bytes)
                    .expect("UTF-8 fixture")
                    .lines()
                    .next()
                    .expect("header line")
                    .to_owned();
                let header: DocumentHeader =
                    serde_json::from_str(&header_line).expect("canonical header");
                assert_eq!(header.document_id, document_id);
                assert_eq!(header.families.len(), FAMILIES_PER_DOCUMENT);
                assert_eq!(header.fresh_nonce.len(), 64);
            }
            assert_eq!(split_families.len(), EXPECTED_FAMILIES_PER_SPLIT);
        }

        assert_eq!(document_digests.len(), EXPECTED_DOCUMENTS);
        assert_eq!(family_ids.len(), EXPECTED_DOCUMENTS * FAMILIES_PER_DOCUMENT);
    }

    #[test]
    fn malformed_document_index_fails_closed() {
        assert!(document_index("fit/fit-000.md").is_err());
        assert_eq!(document_index("fit/fit-001.md").expect("first index"), 0);
    }

    #[test]
    fn evidence_write_is_idempotent_but_rejects_drift() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("review.json");
        let bytes = b"canonical-review";
        write_private(&path, bytes).expect("first write");
        write_private_or_verify(&path, bytes).expect("identical replay");
        assert!(write_private_or_verify(&path, b"drifted-review").is_err());
    }
}
