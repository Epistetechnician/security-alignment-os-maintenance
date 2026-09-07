# Phase 0 contract V1

State slice: `security-alignment-os-foundation-v1`.

This document freezes the local contract vocabulary used before runtime
implementation. It is a local, pure-data specification. It does not
authenticate identities, isolate a process, enforce operating-system policy,
prove input truth, or establish alignment evidence.

## Authority lattice

The authority universe is the eight-atom set:

`Read`, `Write`, `Network`, `Secrets`, `Spend`, `Replicate`, `Execute`, and
`SelfModify`.

`CapabilitySet` is the powerset lattice over those atoms:

- bottom is the empty set;
- top is the set of all eight atoms;
- `join` is set union;
- `meet` is set intersection;
- `a <= b` means `a` is a subset of `b`;
- a grant covers a request only when the requested set is a subset of the
  granted set.

There are no implicit edges between authority atoms. A write grant does not
grant read, network, secret, spend, replication, execution, or self-modifying
authority. A caller must name every required capability.

The Rust API is in `src/contract.rs`:

- `Authority::all()` returns the fixed universe;
- `CapabilitySet::empty()`, `all()`, and `from_slice()` construct lattice
  elements;
- `CapabilitySet::leq()`, `covers()`, `join()`, and `meet()` implement the
  order and lattice operations.

## Lifecycle state machine

The state machine starts at `Proposal`. The only transitions are:

| Current | Event | Next |
| --- | --- | --- |
| Proposal | Quarantine | Quarantined |
| Proposal | Reject | Rejected |
| Proposal | Admit | Admitted |
| Quarantined | Reject | Rejected |
| Quarantined | Admit | Admitted |
| Admitted | Quarantine | Quarantined |
| Admitted | BeginExecution | Executing |
| Executing | Complete | Completed |
| Executing | Rollback | RolledBack |
| Completed | Rollback | RolledBack |
| RolledBack | Admit | Admitted |
| Any live state | Freeze | Frozen |
| Any live state, including Frozen | Kill | Killed |

`Rejected`, `Frozen`, and `Killed` cannot return to ordinary execution.
`Frozen` can be moved to `Killed` as part of terminal shutdown. Every accepted
transition increments the `Lifecycle::revision`; failed transitions leave the
state and revision unchanged.

`transition(state, event)` is the pure transition function. `Lifecycle::apply`
wraps it in a caller-owned state record. Invalid transitions return
`ContractError::InvalidTransition` and do not mutate the record.

## Failure budget

`FailureBudget` contains inclusive ceilings for rejection, quarantine,
rollback, consecutive failures, and failures observed in a sliding window. Its
`window_size` must be positive and `max_window_failures` cannot exceed it.
Zero is allowed as an explicit immediate-freeze ceiling.

`FailureBudget::tracker()` validates the limits before creating a
`FailureTracker`. `FailureTracker::validate()` checks the budget, bounded
window, and counter consistency. `FailureTracker::record_failure()` increments exactly one
category, maintains the bounded recent window, and returns
`BudgetDecision::FreezeRequired` when any inclusive ceiling is reached. A
subsequent observation after exhaustion returns `BudgetExhausted`.
`record_success()` resets the consecutive-failure count; it does not erase
historical category counts or the recent window.

Failure trackers can be saved and loaded as canonical JSON. `recover()`
promotes a validated temporary snapshot only when the primary is absent;
malformed primary bytes remain an error. Persistence is caller-owned and does
not provide an independent monitor or process kill.

These counters are caller-owned local observations. They do not provide a
distributed failure detector, trusted clock, independent monitor, or automatic
process kill. An integration layer must wire `FreezeRequired` to its own
fail-closed lifecycle transition.

## Validation

The module has unit tests for lattice laws and non-implication, invalid
transitions, one-way freeze/kill behavior, and failure-budget validation. Run:

```text
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

`property::run_all()` independently enumerates the 72 lifecycle pairs, all
256 lattice elements and 65,536 ordered lattice pairs, plus the local kernel
invariants. It returns a digest-only report and is a regression check rather
than a formal proof.

Cross-module wiring is exported through `src/lib.rs`; integration remains
coordinator-owned work.
