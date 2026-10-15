# Research report and findings

## Question

Can the proposal-to-rollback control loop for an autonomous-agent system be
built so that an untrusted proposal can only act through exact-subject evidence,
deterministic admission, a single-use kernel-bound capability, a separate
capability broker, and a sandboxed operation, with every step replayable and
every failure closing to freeze or rollback?

## What was built and tested

A Rust reference implementation of the loop: evidence review records,
admission, single-use capabilities, consented specialist memory, a separate
broker process, one sandboxed file transformation (trailing-space trimming of
Markdown), and a transaction-bound multi-file maintenance path over private
immutable generations. The maintenance evaluator checks patch *structure* in a
separate sandboxed process and never runs candidate code or tests. No model is
run.

Local test suite: **279 tests pass, 0 fail** (`cargo test --all-targets`),
including an adversarial runner that attacks the broker directly (path escape,
replay, forged receipts, malformed child operations, telemetry containment).

## Findings

1. **The control loop is implementable as a small, replayable kernel.** Policy,
   budgets, single-use execution, lifecycle, journal persistence, an independent
   checker, and signed receipts compose without a shared trusted component beyond
   the caller-owned policy and clock.
2. **Fixed maintenance operation, 20-scenario matrix, machine-attested
   reproduction.** One completed execution on a Google Confidential Space Intel
   TDX instance passed all 20 required scenarios. The Google-signed attestation
   verified for nonce, issuer, audience, TDX model, Secure Boot, disabled debug,
   Intel TCB, immutable image digest, source revision, instance, project, zone,
   and service account. See `docs/maintenance-gcp-tdx-record-v1.md`. This is a
   `MachineAttestedReproduction`, **not** an `IndependentReplication`.
3. **Replication evidence is versioned and backward compatible.** V2 binds the
   broker executable digest and V3 binds the per-host runner digest into signed
   host reports; V1/V2 packets stay verifiable with their original identities.
   The runner digest is a signed local observation, not proof of build
   provenance.
4. **Several platform gaps are recorded, not hidden.** The Confidential Space
   runner puts its attestation token on stdout and has no protected output sink,
   so it must not be launched outside a controlled test; the Linux sandbox
   backend was compile-checked on x86_64 only, without Linux runtime execution.

## What this does not establish

No scientific alignment result, authenticated independent review, production
readiness, complete multi-tenant isolation, or protection against a hostile
same-UID process. Persisted state is plaintext; digests detect accidental
tampering, not an attacker who can rewrite content and digest. Independent
replication on a second, separately administered host has not happened; until it
does that gate stays `Inconclusive`. The crypto-adapter seam is offline and
zero-value and authorizes no payout.

## Reproduce

```sh
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo run --bin local_demo
```

Rust 1.77+. No network access or provider calls are used by the tests.
