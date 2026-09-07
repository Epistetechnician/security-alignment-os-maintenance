# Threat model

State slice: `security-alignment-os-foundation-v1`.

## In scope

- a model emits an action that requests too much authority;
- a candidate omits or forges provenance;
- an expired or replayed candidate is submitted;
- a candidate exceeds resource budgets;
- a write targets a scope outside its capability;
- an operator attempts to self-approve evidence;
- incomplete evidence is used to release resources;
- a runtime must be stopped independently of the model.

## Controls

| Threat | Control | Local test |
|---|---|---|
| Direct authority request | deterministic rejection | `rejection_and_evidence_gates_are_fail_closed` |
| Replay | journal candidate and agent-nonce uniqueness with chain validation | `end_to_end_completion_and_replay` |
| Scope escalation | intent-bound token plus scope check | `malformed_write_is_rejected_before_capability_consumption` |
| Missing provenance | quarantine | adversarial benchmark |
| Budget overrun | exact integer policy ceiling | adversarial benchmark |
| Self-approval | reviewer/operator/validator separation | evidence registry regression tests |
| Unaccepted evidence | integration quarantine | `rejection_and_evidence_gates_are_fail_closed` |
| Continued local execution | terminal freeze/kill flags outside proposal data | runtime regression tests |
| Artifact subject drift | exact subject digest and manifest lifecycle | artifact registry regressions |
| Capability implication | explicit powerset lattice with no implicit edges | Phase 0 lattice tests |
| Clock or policy drift | exclusive expiry and current policy digest check | fault-injection scenarios |
| Partial local transition | checkpoint restore and digest-only outcome | partial-write fault scenario |

## Not established

This foundation does not establish resistance to a compromised host, kernel,
TEE vendor, malicious dependency, side-channel attack, cryptographic key loss,
deceptive optimization, semantic misalignment, robust corrigibility, or
production deployment. Those require separate threat models and independent
evidence.

## Trust assumptions added by integration

The host, Rust process, role assertions, clock and observation producer are
trusted. Neither a digest nor a different role string authenticates a reviewer.
One kernel owns process-local execution consumption; a new kernel is a new
authority domain. Stored journals never restore executable capabilities.
Caller-owned canonical JSON memory has logical consent controls and digest checks,
not encryption, secure erasure or hostile-host protection.
