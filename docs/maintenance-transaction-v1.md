# Transaction-bound multi-file maintenance V1

State slice: `security-alignment-os-foundation-v1`.

## Scope and claim ceiling

This local reference applies a bounded list of exact replacements to existing
regular files in a private managed workspace. The operator configuration
contains a sorted, unique exact-path allowlist; directory globs and implicit
prefix permissions are not accepted. Requests bind their full before/after
bytes and digests, the complete baseline-generation digest, transaction ID,
nonce, issue time, and lease expiry.

The lifecycle uses immutable generations. Preparation copies the current
generation, applies replacements to an inactive candidate, syncs candidate
files and directories, and records a durable intent. Evaluation binds the
candidate manifest and all transaction inputs. Commit validates the signature
and current baseline, records commit intent, then publishes with one atomic
replacement of the `current` symlink. That pointer replacement is the commit
point. A terminal receipt is persisted after publication. Recovery restores
the recorded baseline after interrupted work, retains the candidate for
inspection, records a rollback receipt, and freezes the workspace.

The reference evaluator checks request bindings, the full generation
manifest, exact requested output bytes, and that the candidate differs from
the baseline only at requested allowlisted files. It does not build or execute
candidate code, run the repository's tests, or establish semantic patch
correctness. The broker launches the pinned evaluator as a separate process
with a fresh launch token, bounded wall-clock budget, bounded output capture,
and a platform-specific sandbox. On macOS, Seatbelt denies network access and
filesystem writes except to exact granted roots. File reads follow the host's
default Seatbelt policy; macOS does not enforce the configured evaluator
address-space limit.

On Linux x86_64 and aarch64, evaluation requires unprivileged user and network
namespaces plus Landlock ABI 9 or newer; unavailable prerequisites fail closed.
Landlock denies filesystem writes outside exact granted roots and scopes
pathname and abstract Unix sockets and signal delivery. A seccomp filter denies
filesystem metadata changes, namespace and mount changes, capability changes,
namespace-creating `clone` flags, `clone3`, and process-group escape operations.
Ordinary thread and process creation remains available. The launcher applies
`RLIMIT_AS`, marks inherited file descriptors close-on-exec, and starts a
process group for timeout termination. The configured Linux limit bounds
virtual address space per process, not resident memory. There is no PID
namespace or cgroup task limit, so task creation is not rate- or count-limited;
the timeout can terminate descendants that remain in the sandbox process
group. Reads follow host filesystem permissions, so this is not isolation from
hostile same-UID processes or files readable by the evaluator's host identity.
The transaction assumes a private workspace controlled by cooperating local
processes. Candidate code and tests are never executed by this reference
evaluator.

The resource bounds also include patch and generation byte/file ceilings and
bounded evaluator output capture. Linux configuration requires
`evaluator_max_address_space_bytes` between 64 MiB and 16 GiB; macOS
configuration must set that field to `null` because Seatbelt has no corresponding
address-space control.

This is local process and persistence evidence only. It does not establish
independent Linux reproduction, an independent evaluator or operator, real
reviewer authority, scientific alignment, platform enforcement, or production
readiness.

## Local process flow

Build the Rust binaries with `cargo build --bins`. Initialize the managed
workspace from a private, source-only directory. Initialization rejects Git
metadata, links, hard links, special files, oversized trees, and a source that
changes during copying. It builds a sibling staging directory and renames that
directory into place only after the initial generation is complete.

```sh
maintenance_patch_broker init SOURCE_DIRECTORY MANAGED_WORKSPACE
maintenance_patch_broker CONFIG.json prepare REQUEST.json > prepared.json
maintenance_patch_broker CONFIG.json evaluate REQUEST.json prepared.json EVALUATOR_SEED > evaluation.json
maintenance_patch_broker CONFIG.json commit REQUEST.json evaluation.json > result.json
```

The operator creates `CONFIG.json` with the canonical workspace path, pinned
evaluator executable path and digest, evaluator public key, evaluator input,
tests and policy digests, cancellation path, exact allowed paths, patch resource
ceilings, and an evaluator timeout from 1 to 60,000 ms. The config and signing
seed are owner-only files. The broker creates a single-use launch token, sends
the job through stdin, and supplies only the token to the evaluator environment;
the token digest and timeout are part of the signed job/receipt bindings. The
evaluator seed is supplied only to the evaluator process and is never included
in the job.
The reference evaluator accepts only its compiled-in input, test, and policy
identities. The transaction supports at most 128 patch files, 4 MiB per
replacement file, 32 MiB across before/after bytes, and a 24-hour request
lease. Evaluator receipts expire within ten minutes. The configured evaluator
address-space limit is included in the signed job and receipt bindings.

The Rust API exposes `FileChange::new`, `PatchRequest`, and `Config` for
constructing canonical request and policy values. The broker's `evaluate`
command validates the prepared candidate, constructs the bounded job, and
launches only the configured evaluator. The evaluator reads the job from
standard input and emits a signed receipt on standard output. The broker accepts
no arbitrary command or candidate executable.

For a prepared but uncommitted transaction, an operator cancellation marker or
expired evaluator receipt closes commit. Run
`maintenance_patch_broker CONFIG.json recover` to restore the baseline and
record the terminal rollback. Recovery leaves the workspace frozen; this
reference slice has no automatic thaw or transaction-resume command. A
successful commit's durable record is available through
`maintenance_transaction::load_receipt` by request digest.

## Persistence and failure handling

Writer exclusion uses an owner-only lock file with an OS advisory exclusive
lock. The kernel releases the lock if the process exits, allowing a later
recovery process to proceed. Atomic state snapshots use a synced temporary
file and rename; after acquiring the writer lock, the next save discards a
leftover regular temporary snapshot and syncs its parent directory. Malformed,
oversized, noncanonical, or unsafe state is rejected. A malformed state is not
repaired automatically.

Transactions are single-flight per managed workspace. Used nonces and terminal
receipts are persisted. A replay, competing in-flight request, stale baseline,
disallowed path, evaluator substitution, changed candidate, expired receipt,
or cancellation cannot publish a generation. If an interruption occurs after
the pointer switch but before terminal receipt persistence, recovery points
`current` back at the recorded baseline, verifies it, records `RolledBack`, and
freezes further work. If that baseline cannot be verified, recovery records
`Frozen` and does not claim rollback success.

The lock is advisory and does not protect against another program that ignores
it or a hostile process with the same UID. Filesystem timestamp behavior,
power-loss durability, aggregate Linux memory or task limits, and hostile
same-UID isolation have not been established. macOS and Linux sandbox
conformance suites are platform-specific; Linux execution requires unprivileged
user and network namespaces and Landlock ABI 9 or newer.

## Verification

`tests/maintenance_transaction_e2e.rs` launches the actual initializer, broker,
and sandboxed evaluator processes. It covers successful two-file
publication, unchanged neighbors and old generation, stale baseline,
out-of-allowlist path, evaluator binary substitution, extra candidate edits,
post-evaluation candidate mutation, baseline mutation preservation, request
and evaluator-receipt expiry, cancellation, replay, crash after pointer swap,
durable rollback receipt, frozen recovery, concurrent preparation, and timeout
termination followed by recovery. `tests/maintenance_sandbox_e2e.rs` verifies
Seatbelt denial of writes outside an allowed workspace, denial of a connection
to a synthetic local listener, bounded output capture, and process-group
termination at timeout.
`tests/maintenance_sandbox_linux_e2e.rs` exercises explicit-root write grants,
write and metadata denial, loopback TCP, pathname and abstract Unix-socket
denial, signal scoping, namespace-creation denial, inherited-descriptor
closure, address-space and output bounds, and timeout cleanup. The Linux probes
fail if the required namespace or Landlock features are unavailable; they do not
silently skip. Run them on Linux with unprivileged user namespaces and Landlock
ABI 9 or newer to establish runtime evidence. `pnpm run test:e2e` includes both
platform suites on their supported operating systems; `pnpm run lint` runs all
targets, formatting, contract digest verification, and warnings-denied Clippy.
The transaction test config binds a 1 GiB evaluator address-space limit on
Linux and no such limit on macOS, where Seatbelt cannot enforce it.

Passing these checks supports `INTERNAL_PASS` for the tested exact local state
slice. A clean second-environment run with recorded toolchain, dependency,
fixture, and output digests may support `REPRODUCED_LOCAL`; same-owner
reproduction is not independent review. Neither result supports
`INDEPENDENT_ACCEPT` or `PRODUCTION_AUTHORIZED`.
