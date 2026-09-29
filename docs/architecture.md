# Architecture

State slice: `security-alignment-os-foundation-v1`.

## Control flow

```text
model/provider output
  -> ActionCandidate
  -> AdmissionKernel
  -> AdmissionDecision + CapabilityToken
  -> GuardedRuntime
  -> digest-chained AdmissionJournal
```

The model has no runtime authority. It supplies an intent, action, scope,
payload, resource cost, source digest, and claims. The kernel applies a fixed
policy. Only an accepted decision can issue a capability token. The runtime
checks the full candidate and decision against kernel-owned issuance records,
then consumes the decision once before mutating local state. `integration::run`
first requires fresh accepted evidence whose source digest binds the exact
candidate, then applies caller-supplied health and telemetry observations.

## Evidence flow

```text
Evidence(held)
  -> digest check
  -> reviewer distinct from operator and validator
  -> accepted evidence status
```

Revocation, contradiction and expiry invalidate acceptance. `artifacts::ArtifactManifest`
adds source, license, provenance, custody-root and retention fields around an
exact subject digest. Acceptance is not semantic proof. It is a local governance
transition that records who reviewed which exact bytes.

When callers select the artifact-bound coordinator, it checks the accepted
manifest against an active custody record by root ID, subject digest, and raw
retention deadline before admission. The combined artifact-and-receipt entry
point then verifies the signed capability receipt before consuming authority or
mutating runtime state. Custody and reviewer identities remain local assertions.
The local-artifact variant also hashes the manifest-bound file under a
caller-supplied `0700` custody directory before admission. On Unix it walks
path components relative to open directory handles without following
symlinks, checks ownership against the process effective UID and private
permissions, bounds and hashes the file, and detects metadata changes during
the read. It does not map that UID to the declared owner or control same-UID
filesystem mutations.

## Risk flow

Admission receives only explicit exact-integer resource requests. Missing
independent evidence quarantines the request. A passing local decision can be
handed to the local release and fixed-receipt contracts. This foundation
performs no transfer, settlement, or external side effect.

## Alignment boundary

`src/alignment.rs` defines the interface for a future fit/tune/held-out causal
measurement lane. It intentionally contains no model loader, provider client,
activation capture, or assessment effect. A future experiment must bind fresh
data, custody, model/runtime identity, prediction lock, independent review, and
claim ceiling before execution.

See [integration-v1.md](integration-v1.md) for specialist persistence,
observations, rollback and downstream local release/compute contracts.
See [plan-conformance-v1.md](plan-conformance-v1.md) for the phase gates and
remaining external enforcement work.
