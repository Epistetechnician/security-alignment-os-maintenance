# Fixed maintenance process boundary V1

State slice: `security-alignment-os-foundation-v1`.

## Contract and task list

This slice advances the in-memory maintenance contract to a real-process,
single-file operation. The fixed task removes trailing ASCII spaces from a
root-level Markdown file in an operator-provisioned private checkout. This
deliberately changes Markdown hard-break syntax when present; it is appropriate
only for a task whose frozen requirements explicitly request that change.
It does not interpret a generic diff or run commands supplied by a proposer.

Implementation and review cover these transitions:

1. Validate the operator configuration, private checkout, bounded request, and
   live lease. Rejected requests cannot change checkout contents.
2. Run the pinned evaluator executable in a separate process. It checks the
   exact baseline and candidate against the fixed transformation and returns a
   signed, request-bound evaluation receipt.
3. Verify the signature, executable identity, frozen requirements, and current
   lease before recording durable intent and consuming replay authority.
4. Replace the authorized file, verify the exact result, recheck authorization
   immediately before the durable completion transition, and persist
   completion. Cancellation or expiry before completion requires restoration.
5. Recover interrupted intent by restoring the baseline and freezing subsequent
   work. Failed or ambiguous restoration stays frozen.

## Authority and threat boundary

The operator controls configuration, evaluator key custody, checkout creation,
and the cancellation path. The proposer supplies data only. A pinned signing
key authenticates an evaluator process under this operator's configuration;
it is not evidence of a separate human operator or separate-host replication.
The signing seed is test/operator custody material, never part of a proposal.

Private directories and rejection of links reduce accidental scope escape.
They do not isolate a hostile process running under the same operating-system
user. The operator must keep the checkout, state, configuration, executable,
and key outside proposer write authority. Arbitrary agent execution needs its
own OS sandbox and identity boundary before this tool can be exposed to it.
The broker grants authority only to its fixed file operation; it does not hand
the proposer a shell or filesystem handle.

The fixed evaluator establishes compliance with a byte transformation. It does
not establish general patch correctness, test-suite completeness, alignment,
or safety of arbitrary source changes. Independent replication, adaptation,
causal research, and external settlement remain separately gated.

## Verification record

The process regression suite must cover useful completion with an untouched
neighbor file, replay across restarts, invalid candidate bytes, stale baseline,
expired authority, cancellation, executable/key substitution, path/link escape,
and recovery after interruption. Passing results apply to the tested local host
and fixed operation only. The original broker's sandbox tests do not confer
sandbox guarantees on this separate maintenance entrypoint.

The independent adversarial review was frozen to commit
`cd2fb760dc6a0959e549986fcfbe1541bb1275ee` and completed with one Luna high
reviewer. It confirmed four defects: finalization lacked a last
lease/cancellation gate; the lock was scoped to `state_dir`; post-intent I/O
errors could escape without rollback; and recovery checked only the target,
not the checkout-wide baseline. The repaired operation uses one private sibling
lock per canonical checkout, binds the checkout digest into durable intent,
rolls back post-intent errors, and rechecks authorization before durable
completion. The durable state format is now process version 2.

Reproducible local validation passed with `pnpm run lint`: 103 library tests,
three broker process tests, 16 maintenance process tests, formatting, and
warnings-denied Clippy. The added maintenance tests cover lease expiry during
evaluation and finalization, finalization cancellation, completion-state
persistence failure, target and neighbor mutation during recovery, distinct
state directories sharing a checkout writer fence, and replacement-lock
ownership, in addition to the existing exact completion, replay, proposal,
cancellation, path/link, crash, and configuration-substitution cases.

The separate-host replication contract is implemented in
`maintenance_replication.rs`. Its eight contract tests bind two signed reports
to the same fixed request, process revision, full-checkout baseline, and exact
containment/recovery matrix. They are local wire-contract tests; they do not
count as separate-host execution or authenticated operator evidence.

The results establish containment and recovery for the tested local host and
fixed operation only. They do not establish arbitrary syscall containment,
same-UID hostile-process isolation, separate-host replication, deployment
acceptance, provider execution, or scientific alignment evidence. Recovery
verifies the complete checkout digest and freezes with `rolled_back: false` on
an ambiguous or concurrent modification. This version replaces the file with
private permissions and does not promise preservation of timestamps or
extended attributes. Infrastructure failures that also prevent durable
rollback state persistence remain operator-recovery work and are never
interpreted as successful completion.

## Local invocation and recovery

Build with `cargo build --bins`. The operator provisions a private checkout,
an external private state directory, a private copy of the evaluator executable,
and a 32-byte Ed25519 seed file with owner-only permissions. `Config` pins the
executable digest, public key, fixed input/test/policy digests, checkout and
state paths, cancellation path, and evaluator timeout. `Request` contains the
root Markdown path, exact before/after bytes and digests, checkout baseline
digest, nonce, and lease expiry. The Rust integration fixture demonstrates
provisioning with a synthetic test key; it is not a deployment key recipe.

Invoke `maintenance_broker CONFIG.json REQUEST.json`. It emits a JSON terminal
outcome, or exits unsuccessfully on infrastructure or recovery errors. Treat
every error as closed authority. Creating the configured cancellation file
closes execution at the next check. Cancellation is operator-controlled and
sticky until that operator removes the marker.

An existing `.maintenance-checkout-<sha256-of-canonical-path>.lock` blocks
every broker configuration for that checkout, including configurations with
different state directories. After a crash, first confirm externally that the
previous broker and evaluator have terminated. Only then may the operator
remove that stale lock and invoke recovery with the same configuration.
Recovery does not resume the patch; it restores an unambiguous recorded
baseline and freezes. If the checkout-wide baseline is no longer consistent,
recovery preserves the observed change and freezes without reporting a
successful rollback. Never delete the durable state to clear replay or freeze
controls. A fresh operational release needs review.

`MAINTENANCE_TEST_FAILPOINT` is an operator-only crash-injection control used by
the process tests. It must be absent from operational launches. No failpoint
grants additional authority.
