"""Run a harmless guest-side smoke check against ClamAV and one benign PE."""

import argparse
import json
from pathlib import Path

from aegisav.clamav_engine import ClamAVEngine
from aegisav.main import build_scanner


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--eicar", required=True, type=Path)
    parser.add_argument("--benign-pe", required=True, type=Path)
    args = parser.parse_args()

    clamav = ClamAVEngine()
    if not clamav.probe():
        raise RuntimeError("clamd is unavailable")
    test_report = clamav.scan(args.eicar.read_bytes())
    if test_report["status"] != "matched":
        raise RuntimeError(f"EICAR was not detected: {test_report['status']}")

    benign_report = build_scanner().scan(args.benign_pe.read_bytes())
    statuses = {name: item["status"] for name, item in benign_report["engines"].items()}
    if set(statuses.values()) != {"no_match"}:
        raise RuntimeError(f"Benign PE scan did not complete cleanly: {statuses}")
    print(json.dumps({
        "eicar_clamav": test_report,
        "benign_pe_sha256": benign_report["sha256"],
        "benign_engine_statuses": statuses,
        "benign_engine_versions": {name: item["engine_version"] for name, item in benign_report["engines"].items()},
        "benign_engine_elapsed_ms": {name: item["elapsed_ms"] for name, item in benign_report["engines"].items()},
    }, indent=2))


if __name__ == "__main__":
    main()
