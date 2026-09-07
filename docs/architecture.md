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

Revocation, contradiction and expiry invalidate acceptance. Acceptance is not semantic proof. It is a local governance transition that
records who reviewed which exact bytes.

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
