"""
Validate every Sigma rule in a directory tree.

Walks a directory, attempts to parse each .yml/.yaml file as a Sigma rule
using pySigma's SigmaCollection, and reports any errors. Exits non-zero if
any rule fails to parse, so it can be used as a CI gate.

Usage:
    python tools/validate_sigma.py detections/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError


def find_rule_files(root: Path) -> list[Path]:
    """Return every .yml and .yaml file under root."""
    return sorted([p for p in root.rglob("*.y*ml") if p.is_file()])


def validate_rule(path: Path) -> tuple[bool, str | None]:
    """Parse a single Sigma rule. Return (ok, error_message)."""
    try:
        SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        return True, None
    except SigmaError as exc:
        return False, f"SigmaError: {exc}"
    except Exception as exc:  # noqa: BLE001 — surface anything that breaks parsing
        return False, f"{type(exc).__name__}: {exc}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="Directory containing Sigma rules")
    args = parser.parse_args()

    if not args.path.exists():
        print(f"ERROR: {args.path} does not exist", file=sys.stderr)
        return 2

    rule_files = find_rule_files(args.path)
    if not rule_files:
        print(f"WARNING: no .yml/.yaml files found under {args.path}")
        return 0

    failures: list[tuple[Path, str]] = []
    for rule_path in rule_files:
        ok, err = validate_rule(rule_path)
        status = "PASS" if ok else "FAIL"
        base_path = args.path.parent if args.path.parent != Path(".") else args.path
        rel = rule_path.relative_to(base_path)
        print(f"  [{status}] {rel}")
        if not ok and err is not None:
            failures.append((rule_path, err))

    print()
    passed = len(rule_files) - len(failures)
    print(f"Validated {len(rule_files)} rule(s): {passed} pass, {len(failures)} fail")

    if failures:
        print("\nFailures:", file=sys.stderr)
        for path, err in failures:
            print(f"  - {path}: {err}", file=sys.stderr)
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
