"""Validate a YARA-X rule directory and its separate metadata file."""

import argparse
import json
from pathlib import Path

from .yara_engine import load_yara_engine


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if not args.rules.is_dir():
            raise ValueError("Rule directory does not exist")
        if not any(args.rules.glob("*.yar")) and json.loads(args.metadata.read_text(encoding="utf-8")) == []:
            print(json.dumps({"valid": True, "rule_count": 0, "artifact_version": None}))
            return 0
        engine = load_yara_engine(args.rules, args.metadata)
    except (OSError, ValueError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}))
        return 1
    print(json.dumps({"valid": True, "rule_count": len(engine.metadata),
                      "artifact_version": engine.artifact_version}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
