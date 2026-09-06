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
| Direct authority request | deterministic rejection | `test_rejection_cannot_mutate_state` |
| Replay | journal candidate uniqueness and chain validation | `test_journal_detects_replay_and_validates_chain` |
| Scope escalation | intent-bound token plus scope check | `test_accepted_write_requires_bound_scope` |
| Missing provenance | quarantine | adversarial benchmark |
| Budget overrun | exact integer policy ceiling | adversarial benchmark |
| Self-approval | reviewer/operator separation | `test_evidence_requires_independent_reviewer` |
| Unaccepted evidence | Statebook freeze | `test_statebook_freezes_without_accepted_evidence` |
| Runtime persistence | independent kill switch | runtime API |

## Not established

This foundation does not establish resistance to a compromised host, kernel,
TEE vendor, malicious dependency, side-channel attack, cryptographic key loss,
deceptive optimization, semantic misalignment, robust corrigibility, or
production deployment. Those require separate threat models and independent
evidence.
