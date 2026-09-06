import unittest

from alignment_os.admission import AdmissionKernel
from alignment_os.alignment import PredictionLock, current_foundation_spec
from alignment_os.benchmark import cases, run
from alignment_os.crypto import digest_object
from alignment_os.evidence import EvidenceProposal, EvidenceRegistry
from alignment_os.journal import AdmissionJournal, JournalError
from alignment_os.models import ActionCandidate, ActionKind, ClaimEnvelope, ClaimMaturity, DecisionKind
from alignment_os.runtime import GuardedRuntime
from alignment_os.statebook import ReleaseKind, StatebookKernel


def claim() -> ClaimEnvelope:
    return ClaimEnvelope(
        guarantees=("PolicyCompliance",),
        assumptions=(),
        excludes=("semantic_correctness",),
        maturity=ClaimMaturity.LOCAL,
        trust_roots=("test_validator",),
        valid_until=100,
        provenance_digest="a" * 64,
    )


def candidate(identifier="c1", action=ActionKind.WRITE, **overrides) -> ActionCandidate:
    data = dict(
        candidate_id=identifier,
        agent_id="agent",
        intent="set value",
        action=action,
        scope="sandbox",
        payload={"key": "sandbox:k", "value": 1},
        resource_cost={"cpu_ms": 1, "bytes": 1, "spend": 0},
        source_digest="b" * 64,
        claims=(claim(),),
        expires_at=50,
    )
    data.update(overrides)
    return ActionCandidate(**data)


class FoundationTests(unittest.TestCase):
    def test_claim_composition_meets_assurance(self):
        left = claim()
        right = ClaimEnvelope(("Provenance",), (), ("competence",), ClaimMaturity.ATTESTED, ("tee",), 80, "c" * 64)
        combined = left.compose(right)
        self.assertEqual(combined.maturity, ClaimMaturity.LOCAL)
        self.assertIn("semantic_correctness", combined.excludes)
        self.assertIn("competence", combined.excludes)

    def test_rejection_cannot_mutate_state(self):
        kernel = AdmissionKernel()
        runtime = GuardedRuntime(kernel)
        bad = candidate(requests_direct_authority=True)
        decision = kernel.admit(bad, 10)
        self.assertEqual(decision.decision, DecisionKind.REJECTED)
        self.assertFalse(runtime.execute(bad, decision, 10))
        self.assertEqual(runtime.state, {})

    def test_accepted_write_requires_bound_scope(self):
        kernel = AdmissionKernel()
        runtime = GuardedRuntime(kernel)
        good = candidate()
        decision = kernel.admit(good, 10)
        self.assertTrue(runtime.execute(good, decision, 10))
        self.assertEqual(runtime.state["sandbox:k"], 1)

    def test_journal_detects_replay_and_validates_chain(self):
        journal = AdmissionJournal()
        kernel = AdmissionKernel(journal=journal)
        first = candidate()
        decision = kernel.admit(first, 10)
        self.assertEqual(decision.decision, DecisionKind.ACCEPTED)
        journal.validate()
        replay = kernel.admit(first, 10)
        self.assertEqual(replay.decision, DecisionKind.REJECTED)
        self.assertEqual(replay.reason, "replayed candidate")
        with self.assertRaises(JournalError):
            journal.append(digest_object(first), decision)

    def test_capability_cannot_be_retargeted(self):
        kernel = AdmissionKernel()
        runtime = GuardedRuntime(kernel)
        original = candidate()
        decision = kernel.admit(original, 10)
        retargeted = candidate(identifier="retargeted", payload={"key": "public:k", "value": 1})
        with self.assertRaises(RuntimeError):
            runtime.execute(retargeted, decision, 10)
        self.assertEqual(runtime.state, {})

    def test_capability_budget_is_consumed_once(self):
        kernel = AdmissionKernel()
        runtime = GuardedRuntime(kernel)
        first = candidate()
        decision = kernel.admit(first, 10)
        self.assertTrue(runtime.execute(first, decision, 10))
        with self.assertRaises(RuntimeError):
            runtime.execute(first, decision, 10)

    def test_adversarial_benchmark(self):
        results = run()
        self.assertEqual(len(results), len(cases()))
        self.assertTrue(all(result.passed for result in results))

    def test_statebook_freezes_without_accepted_evidence(self):
        decision = StatebookKernel().decide(evidence_accepted=False, requested={"compute": 1})
        self.assertEqual(decision.release, ReleaseKind.FROZEN)

    def test_evidence_requires_independent_reviewer(self):
        proposal = EvidenceProposal("p1", "d" * 64, "validator", "operator", claim(), (("status", "pass"),))
        registry = EvidenceRegistry()
        registry.propose(proposal)
        with self.assertRaises(ValueError):
            registry.independently_accept("p1", "operator", proposal.digest)
        accepted = registry.independently_accept("p1", "reviewer", proposal.digest)
        self.assertEqual(accepted.status, "accepted")

    def test_alignment_contract_stays_closed(self):
        spec = current_foundation_spec()
        self.assertFalse(spec.model_execution_authorized)
        self.assertFalse(PredictionLock(spec.protocol_id, (1,), True, False).assessment_eligible())


if __name__ == "__main__":
    unittest.main()
