# Signed capability receipts V1

State slice: `security-alignment-os-foundation-v1`.

`src/receipts.rs` adds a local Ed25519 receipt layer around an already accepted
kernel decision. A `CapabilityReceipt` binds the complete proposal digest, the
decision candidate digest, the exact policy digest, the complete capability
digest, subject, agent, action, scope, issuer key ID, and a bounded validity
window. The receipt ID is derived from those fields and is included in the
signed canonical payload. The signature field is excluded from that payload.

`ReceiptSigner` accepts a caller-owned 32-byte Ed25519 seed and never exposes or
serializes the private key. `issue` uses the capability's existing validity
window. `issue_at` can shorten that window but cannot extend it. Only accepted
decisions whose proposal, policy, agent, action, and scope bindings recompute
exactly can be signed. The signer, verifier, and independent checker also
require the transport decision candidate identity to match the proposal, and
recompute the capability intent digest, token digest, and resource budget
binding before accepting a receipt.

`ReceiptVerifier` requires an explicit local key registry. Verification checks
canonical shape, receipt identity, subject equality, signature, freshness,
accepted-decision status, all four digests, and exact agent/action/scope
bindings. It records a receipt ID only after every check passes; a second
verification in the same verifier is rejected as replay. Key registration is
local and duplicate key IDs are rejected. `validate`, `save`, `load`, and
`recover` cover the trusted-key and replay sets with canonical JSON and a
validated temporary-file promotion path.

`checker::validate_capability_receipt` independently recomputes the receipt
identity, decision bindings, validity window, and Ed25519 signature without
calling `ReceiptVerifier`. It accepts a caller-provided public key and does not
replace independent trust in the persisted verifier snapshot.

The module is pure Rust and has no provider, network, model, host-attestation,
OS sandbox, authenticated storage, or distributed replay protection. A valid
signature proves possession of the registered local signing key over the
receipt payload. It does not prove that the capability was honored, that an
execution occurred, that inputs were truthful, or that the signer is an
independent authority. The caller must protect the persisted trusted-key
registry and verified set; canonical persistence detects accidental tampering
but does not authenticate the storage owner.

The `receipts` module is exported from `src/lib.rs`. Validation is:

```text
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```
