"""
runner.py — execute scenarios and print a metrics table.

Run as:  python -m scripts.eval.runner
Or:      python scripts/eval/runner.py

Computes:
  Notification Reduction Ratio (NRR)  = 1 - alerts / changes
  True Positive Rate                  = malicious caught / malicious total
  False Negative Rate                 = 1 - TPR
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make `scripts.eval...` importable when run as a script.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from scripts.eval.harness import EvalHarness, HarnessResult
from scripts.eval.scenarios import SCENARIOS


def run_one(name: str, fn) -> tuple[HarnessResult, int]:
    with EvalHarness(name) as h:
        truly_malicious = fn(h)
        # Drain the queue: baseline + change + pending-analysis processing.
        h.scan()
        h.process_pending(batch_size=500)
        # Some events stem from baseline ('new'); drain again for the modify pass.
        h.process_pending(batch_size=500)
        return h.snapshot(), truly_malicious


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    names = argv or list(SCENARIOS.keys())

    print(f"{'scenario':<22} {'changes':>8} {'alerts':>7} {'NRR':>7} "
          f"{'TPR':>7} {'FNR':>7}  caught/total")
    print("-" * 78)

    for name in names:
        fn = SCENARIOS.get(name)
        if fn is None:
            print(f"  ! unknown scenario: {name}")
            continue

        result, truly_malicious = run_one(name, fn)
        critical_dispatches = sum(
            1 for d in result.dispatches
            if d.dispatch_type == 'immediate' and d.priority in ('critical', 'high')
        )
        # TPR assumes the scenario's malicious additions are the only ones that
        # should produce immediate alerts. Useful for adversarial / mixed
        # scenarios; for pure-benign scenarios truly_malicious is 0 so TPR is
        # reported as "n/a".
        tpr = (critical_dispatches / truly_malicious) if truly_malicious else None
        fnr = (1.0 - tpr) if tpr is not None else None

        tpr_s = f"{tpr:.2f}" if tpr is not None else "n/a"
        fnr_s = f"{fnr:.2f}" if fnr is not None else "n/a"

        print(
            f"{name:<22} "
            f"{result.changes_detected:>8} "
            f"{result.total_notifications:>7} "
            f"{result.notification_reduction_ratio:>7.2f} "
            f"{tpr_s:>7} "
            f"{fnr_s:>7}  "
            f"{critical_dispatches}/{truly_malicious}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
