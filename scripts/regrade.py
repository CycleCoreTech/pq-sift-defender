"""Re-grade an existing eval log against the current grader.

Useful when the grader changes but the model output didn't. Avoids burning
another full eval cycle.

Usage:
    python scripts/regrade.py agent_logs/eval-YYYYMMDD-HHMMSS.jsonl
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
from run_eval import _grade, write_accuracy_report  # noqa: E402


def main() -> None:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <eval-log.jsonl>")
        sys.exit(1)
    log = Path(sys.argv[1])
    results: list[dict] = []
    with log.open() as f:
        for line in f:
            r = json.loads(line)
            r["grade"] = _grade(r["verdict_text"], r["expected"])
            results.append(r)
    out = write_accuracy_report(results)
    print(f"Re-graded {len(results)} cases → {out}")
    for r in results:
        print(f"  {r['alert']:30s} expected={r['expected']:6s} grade={r['grade']}")


if __name__ == "__main__":
    main()
