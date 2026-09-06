"""Small end-to-end local demonstration."""

from __future__ import annotations

from .alignment import current_foundation_spec
from .benchmark import run
from .statebook import StatebookKernel


def main() -> None:
    results = run()
    print("security-alignment-os foundation")
    for result in results:
        print(f"{result.name}: {'PASS' if result.passed else 'FAIL'} ({result.actual.value})")
    risk = StatebookKernel().decide(evidence_accepted=False, requested={"compute": 1})
    print(f"risk: {risk.release.value} ({risk.reason})")
    print(f"alignment execution authorized: {current_foundation_spec().model_execution_authorized}")


if __name__ == "__main__":
    main()
