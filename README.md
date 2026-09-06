# Security Alignment OS

State slice: `security-alignment-os-foundation-v1`.

A local reference implementation for the security/alignment control loop:

```text
untrusted proposal
  -> typed semantic case
  -> deterministic admission
  -> capability token
  -> bounded execution
  -> digest-chained audit
  -> independent evidence review
  -> held-out alignment measurement contract
```

The central security claim is narrow: rejected proposals do not mutate governed
state, accepted proposals receive only the authority explicitly granted by the
policy, and every admission decision is recorded in a replayable digest chain.
This is local regression evidence, not proof of model safety, alignment,
corrigibility, production readiness, or full security.

All implementation is clean-room. No code, artifacts, datasets, traces, or
generated outputs are ported from another local or remote repository. Public
SOTA specifications may inform independent reimplementation only when license
and provenance are recorded. See [clean-room policy](docs/clean-room-policy.md).

## Components

- `alignment_os.models`: canonical typed contracts and claim composition.
- `alignment_os.admission`: deterministic accept/reject/quarantine kernel.
- `alignment_os.capabilities`: short-lived, intent-bound authority tokens.
- `alignment_os.journal`: append-only admission history and replay checks.
- `alignment_os.evidence`: digest-bound evidence proposals and independent review.
- `alignment_os.benchmark`: deterministic semantic cases and adversarial mutations.
- `alignment_os.statebook`: exact-integer risk and release decisions; no value moves.
- `alignment_os.alignment`: prediction-lock and causal-measurement contracts only.
- `alignment_os.runtime`: bounded local state mutation and independent kill switch.

## Run

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q alignment_os tests
python3 -m alignment_os.demo
```

## Next authorized research boundaries

The current project deliberately stops before model execution. A future slice
may add a separately reviewed Astral causal-feature measurement runner, external
custody, independent validation, and a positive execution budget. It must not
import closed negative scientific artifacts or treat this reference system as
evidence that an agent is aligned.
