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
checks the token against the exact candidate intent before mutating local state.

## Evidence flow

```text
EvidenceProposal(held)
  -> digest check
  -> reviewer distinct from operator
  -> accepted evidence status
```

Acceptance is not semantic proof. It is a local governance transition that
records who reviewed which exact bytes.

## Risk flow

Statebook receives only explicit exact-integer resource requests. Missing
independent evidence freezes the request. A challenge quarantines it. A passing
local decision queues a separately authorized release. This foundation performs
no transfer, settlement, or external side effect.

## Alignment boundary

`alignment.py` defines the interface for a future fit/tune/held-out causal
measurement lane. It intentionally contains no model loader, provider client,
activation capture, or assessment effect. A future experiment must bind fresh
data, custody, model/runtime identity, prediction lock, independent review, and
claim ceiling before execution.
