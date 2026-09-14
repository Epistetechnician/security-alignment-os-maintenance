# Fresh protocol packet V1

State slice: `security-alignment-os-foundation-v1`.

This packet is a local synthetic fixture boundary for the declared protocol
identity `fresh-207-552-v1`. It is not an imported corpus, model output,
research trace, scientific assessment, or alignment result.

## Packet shape

The Rust-only `protocol_packet` binary generates exactly 207 fresh documents:

| Split | Documents | Distinct families |
| --- | ---: | ---: |
| `fit` | 69 | 552 |
| `tune` | 69 | 552 |
| `assessment` | 69 | 552 |
| Total | 207 | 1,656 across split namespaces |

Each document contains eight distinct family identifiers. Family identifiers
are unique within each split, so each split has exactly 69 x 8 = 552 families.
Document bytes include a canonical header, a split/document-specific freshness
nonce, and an explicit statement that the material is synthetic local fixture
content. The generator does not read from HyperIntel, hyperAI, hypersacredai,
or any external corpus.

## Custody and manifest

The output root must be outside this repository. Generation creates the root
and split directories with Unix mode `0700`, and documents plus JSON records
with mode `0600`. This is an owner-declared local filesystem assertion, not
authenticated custody or secure deletion.

`manifest.json` is canonical JSON. Every document entry contains the required
`source`, `revision`, `split`, `author`, `path`, and `sha256` fields, plus its
eight family identifiers. Validation rejects noncanonical JSON, unsafe paths,
unexpected identity fields, wrong modes, SHA-256 mismatches, malformed headers,
freshness mismatches, duplicate paths, duplicate families, and incorrect split
cardinality.

## End-to-end commands

Use a new absolute path outside the repository for each protocol identity:

```sh
cargo run --bin protocol_packet -- generate /absolute/path/fresh-207-552-v1-20260914
cargo run --bin protocol_packet -- validate /absolute/path/fresh-207-552-v1-20260914
cargo run --bin protocol_packet -- dry-run /absolute/path/fresh-207-552-v1-20260914
cargo run --bin protocol_packet -- freeze /absolute/path/fresh-207-552-v1-20260914
```

The commands produce, in order, `manifest.json`, `local-review.json` with
`LOCAL_PASS`, `dry-run.json` with `DRY_RUN_PASS`, and
`protocol-freeze.json` with `FROZEN`. Freeze requires canonical, matching
review and dry-run records and verifies that all dry-run side-effect flags are
false. The freeze is local metadata only; it does not authorize model
execution, assessment effects, provider calls, signing, network activity,
value movement, or payout.

The frozen claim ceiling is limited to synthetic protocol-fixture validity and
caller-owned local custody evidence. A future scientific or independent review
must use a new authorized wedge and must not relabel this `LOCAL_PASS` as
independent acceptance.
