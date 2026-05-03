"""Export and verify a signed audit chain produced by an investigation.

Reads the most recent eval log, picks one chain_id with the IRChain backend,
and calls /v1/attest/export + /v1/attest/verify against it. Saves the export
to samples/audit_chain_export.json as a static proof artifact.

Usage:
    python scripts/export_audit_chain.py             # most recent eval log
    python scripts/export_audit_chain.py <chain_id>  # specific chain
"""

from __future__ import annotations

import contextlib
import json
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path

from dotenv import load_dotenv

REPO = Path(__file__).resolve().parent.parent
LOGS_DIR = REPO / "agent_logs"
SAMPLES_DIR = REPO / "samples"


def _serialize(obj):  # type: ignore[no-untyped-def]
    if obj is None or isinstance(obj, str | int | float | bool | bytes):
        return obj
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [_serialize(v) for v in obj]
    # Pull public attributes (props or instance dict) for SDK result objects.
    public_attrs = {
        a: getattr(obj, a)
        for a in dir(obj)
        if not a.startswith("_") and not callable(getattr(obj, a, None))
    }
    if public_attrs:
        return {k: _serialize(v) for k, v in public_attrs.items()}
    return str(obj)


def _pick_chain_id_from_logs() -> tuple[str, str]:
    logs = sorted(LOGS_DIR.glob("eval-*.jsonl"))
    if not logs:
        raise SystemExit("no eval logs found in agent_logs/")
    latest = logs[-1]
    with latest.open() as f:
        for line in f:
            r = json.loads(line)
            if r.get("chain_backend") == "IRChain" and r.get("chain_id"):
                return r["alert"], r["chain_id"]
    raise SystemExit(f"no IRChain-backed entries in {latest.name}")


def main() -> None:
    load_dotenv()
    from pq_sift_defender.clients.pq_client import PQClient

    if len(sys.argv) >= 2:
        chain_id = sys.argv[1]
        source = "argv"
    else:
        source, chain_id = _pick_chain_id_from_logs()
    print(f"Exporting chain {chain_id} (source: {source})")

    client = PQClient()
    export = client.attest_export(chain_id)
    verify = client.attest_verify(chain_id)

    export_dict = _serialize(export)
    if isinstance(export_dict, dict) and isinstance(export_dict.get("entries"), str):
        with contextlib.suppress(json.JSONDecodeError):
            export_dict["entries"] = json.loads(export_dict["entries"])
    payload = {
        "chain_id": chain_id,
        "source": source,
        "verify": _serialize(verify),
        "export": export_dict,
    }
    out = SAMPLES_DIR / "audit_chain_export.json"
    out.write_text(json.dumps(payload, indent=2, sort_keys=True))

    v = payload["verify"] if isinstance(payload["verify"], dict) else {}
    e = payload["export"] if isinstance(payload["export"], dict) else {}
    print(
        f"  verify.valid={v.get('valid')}"
        f" chain_length={v.get('chain_length')}"
        f" latency_us={v.get('latency_us')}"
    )
    print(
        f"  export.chain_length={e.get('chain_length')} entries={len(e.get('entries', []) or [])}"
    )
    print(f"  saved to: {out}")


if __name__ == "__main__":
    main()
