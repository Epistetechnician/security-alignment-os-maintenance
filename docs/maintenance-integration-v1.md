# Repository maintenance integration V1

State slice: `security-alignment-os-foundation-v1`.

## Current local implementation status

Audit date: 2026-09-23. State slice: `security-alignment-os-foundation-v1`.

The original maintenance workflow contract was developed from `fe4195b`. The
current checkout adds a fixed-operation process boundary and a local
20-scenario replication runner. `tests/maintenance_process_e2e.rs` exercises
real broker/evaluator subprocesses, mutation, replay rejection, cancellation,
rollback, and crash recovery. `tests/maintenance_replication_runner.rs`
executes and signs the fixed scenario matrix using local fixtures. These checks
establish local process and packet behavior only.

The separate-host packet remains `valid_local_packet` / `Inconclusive` until an
independent host, operator, and evidence custodian reproduce and authenticate
the exact frozen run. The hosted Confidential Space and Nitro wrappers are
environment-specific; hermetic local tests execute their workload functions
against actual local runner, broker, and evaluator binaries with synthetic
protocol and attestation adapters, not platform attestation. The local Nitro
image-policy tests reject dirty or mismatched source identity, verify build-time
digest checking and compile-time embedding, and reject runtime overrides,
without building an image. The GCP wrapper places its OIDC
attestation token in stdout. Its image now sets the Confidential Space
`log_redirect=never` launch policy, but the repository still has no protected
output sink or token-custody workflow. Do not launch it. Protected output
custody and any hosted execution remain outside this state slice.

The capability broker and maintenance tools remain separate transaction
boundaries. The enforcement lane owns `broker.rs`, supervisor binaries,
durable execution records, cancellation, and recovery. Its Linux `unshare`
path remains separate from the generic transaction sandbox. The fixed
maintenance process owns one Markdown whitespace transformation. The generic
local transaction has its own lifecycle and signed receipt, and its pinned
structural evaluator now has a shared macOS Seatbelt and Linux namespace,
Landlock, and seccomp launcher. Its Linux code contains x86_64 and aarch64
paths; only x86_64 cross-compilation has been checked here, and Linux runtime
probes have not run. Candidate code is not executed.

## Existing interface and remaining general-operation gap

The capability broker still accepts `FileTransformRequest` through
`BrokerRequest::Execute` and returns `BrokerResponse`. It binds source and
executable digests, relative paths, byte and runtime limits, nonce, and expiry.
Its only operation is `UppercaseAscii`, writing a previously absent
destination. `BrokerResponse::Completed` carries a capability receipt and
output digest; quarantine and frozen responses represent failure.

The new transaction path binds the managed workspace baseline, complete
replacement patch, exact operator allowlist, evaluator identity and policy,
patch byte ceilings, evaluator timeout, nonce, and lease. The complete lifecycle
is detailed in the linked transaction contract. This closes the local
generic-replacement wiring gap for existing regular files and selects a
platform-specific sandbox for the structural evaluator. Linux enforcement
still needs runtime execution on a host with the required namespace and
Landlock support. Additions, deletions, renames, arbitrary candidate execution,
and production sandbox authority remain outside its scope.

The [fixed maintenance process boundary](maintenance-process-v1.md) preserves
the existing broker protocol and exercises signed evaluation and durable
mutation for a single Markdown whitespace task. Its private-checkout trust
boundary is explicit. The generic transaction uses separate binaries and a
managed-generation pointer, with its own claim ceiling.

## Local integration coverage and remaining gate

The fixed process and the generic transaction remain distinct local
implementations. `tests/maintenance_transaction_e2e.rs` exercises init,
prepare, broker-launched sandboxed evaluation, commit, and recovery end to end. Its
cases cover a signed two-file update, stale baseline, disallowed path,
evaluator replacement, extra candidate edits, expired evaluator receipt,
cancellation, replay, crash after pointer swap, durable rollback receipt,
competing writers, and timeout recovery. `tests/maintenance_sandbox_e2e.rs`
probes filesystem-write denial, a local network connection denial, bounded
output capture, and process-group termination. These establish local macOS
protocol, persistence, and sandbox behavior for the tested scope.
`tests/maintenance_sandbox_linux_e2e.rs` adds strict Linux runtime probes for
filesystem, IP and Unix-socket network, signal, metadata, namespace-creation,
inherited-descriptor, address-space, output, and timeout controls. Ordinary
process and thread creation is still available, without a task-count limit.
The probes fail when prerequisites are unavailable and have not been executed
in this checkout. Linux cross-target compilation is not runtime evidence. Neither
platform's local tests establish candidate test correctness, hostile same-UID
isolation, authenticated identity, independent Linux reproduction, or
production readiness.

## Subsequent gates

1. Independent replication: use the [V2 report contract](maintenance-replication-v2.md)
   to bind the exact maintenance broker executable as well as the frozen
   containment/recovery packet. The legacy [V1 contract](maintenance-replication-v1.md)
   remains verifiable without broker executable binding. Actual separate-host
   reproduction remains open.
2. Shadow adaptation: candidate updates compete against an immutable baseline
   on locked evaluations; independent authority controls promotion and rollback.
3. Causal research: separately accepted preregistration, custody, identity, and
   spend gates precede interventions and held-out monitor evaluation.
4. External market: outsource the fixed job class only after independent receipt
   verification; escrow and settlement require their own authorization.

These produce distinct evidence for containment, bounded usefulness, replication,
controlled adaptation, causal effects, and outsourced computation. No individual
gate establishes general alignment. Model execution remains separately gated.
