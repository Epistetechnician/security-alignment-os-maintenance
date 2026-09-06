"""Digest-chained admission journal with replay and stale-tip rejection."""

from __future__ import annotations

from dataclasses import dataclass

from .crypto import digest_object
from .models import AdmissionDecision


@dataclass(frozen=True)
class JournalEntry:
    sequence: int
    previous_digest: str
    candidate_digest: str
    decision_digest: str
    entry_digest: str


class JournalError(ValueError):
    pass


class AdmissionJournal:
    def __init__(self) -> None:
        self._entries: list[JournalEntry] = []
        self._candidate_digests: set[str] = set()

    @property
    def tip_digest(self) -> str:
        return self._entries[-1].entry_digest if self._entries else "0" * 64

    @property
    def entries(self) -> tuple[JournalEntry, ...]:
        return tuple(self._entries)

    def contains_candidate(self, candidate_digest: str) -> bool:
        return candidate_digest in self._candidate_digests

    def append(self, candidate_digest: str, decision: AdmissionDecision) -> JournalEntry:
        if candidate_digest in self._candidate_digests:
            raise JournalError("replayed candidate")
        previous = self.tip_digest
        sequence = len(self._entries)
        preimage = {
            "sequence": sequence,
            "previous_digest": previous,
            "candidate_digest": candidate_digest,
            "decision_digest": decision.decision_digest,
        }
        entry = JournalEntry(
            sequence=sequence,
            previous_digest=previous,
            candidate_digest=candidate_digest,
            decision_digest=decision.decision_digest,
            entry_digest=digest_object(preimage),
        )
        self._entries.append(entry)
        self._candidate_digests.add(candidate_digest)
        return entry

    def validate(self) -> None:
        previous = "0" * 64
        seen: set[str] = set()
        for expected_sequence, entry in enumerate(self._entries):
            if entry.sequence != expected_sequence:
                raise JournalError("non-contiguous sequence")
            if entry.previous_digest != previous:
                raise JournalError("broken previous digest")
            if entry.candidate_digest in seen:
                raise JournalError("duplicate candidate digest")
            expected = digest_object(
                {
                    "sequence": entry.sequence,
                    "previous_digest": entry.previous_digest,
                    "candidate_digest": entry.candidate_digest,
                    "decision_digest": entry.decision_digest,
                }
            )
            if entry.entry_digest != expected:
                raise JournalError("entry digest mismatch")
            previous = entry.entry_digest
            seen.add(entry.candidate_digest)
