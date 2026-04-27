"""
Retire a detection rule with a documented reason.

Retirement preserves the rule file in the repo so that future incident
investigations can `git log` the deprecation reason. The file is moved
to detections/retired/ so it's no longer deployed by the convert/deploy
pipeline (which excludes the retired/ subtree).

Updates the rule's YAML in place to set:
  status: deprecated
  retired_at: <ISO timestamp>
  retirement_reason: <reason text>

This is a CLI, not a CI step. Run it locally, review the diff, push a
branch, and open a PR. The retirement reason becomes part of the commit
message and the PR description.

Usage:
    python tools/retire_detection.py <rule_id_or_path> \\
        --reason "high FP rate, replaced by T1003.001 v2"

    # Or by file path
    python tools/retire_detection.py detections/windows/credential_access/T1003.001_lsass_dump_procdump.yml \\
        --reason "..."
"""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
import sys
from pathlib import Path

import yaml


def find_rule(repo_root: Path, identifier: str) -> Path | None:
    """Find a rule by UUID or by literal path."""
    candidate = Path(identifier)
    if candidate.exists() and candidate.is_file():
        return candidate.resolve()

    detections_dir = repo_root / "detections"
    if not detections_dir.exists():
        return None

    for path in detections_dir.rglob("*.y*ml"):
        if "retired" in path.parts:
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if isinstance(data, dict) and str(data.get("id", "")) == identifier:
            return path.resolve()
    return None


def update_metadata(rule_path: Path, reason: str) -> dict:
    """Mutate the rule's YAML to mark it deprecated. Returns the updated dict."""
    text = rule_path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{rule_path} did not parse as a Sigma rule mapping")

    data["status"] = "deprecated"
    data["retired_at"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["retirement_reason"] = reason
    data["modified"] = dt.datetime.now(dt.timezone.utc).strftime("%Y/%m/%d")

    # Preserve key order roughly: write back with stable sort_keys=False
    rule_path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100),
        encoding="utf-8",
    )
    return data


def move_to_retired(rule_path: Path, repo_root: Path) -> Path:
    """Move the rule file under detections/retired/, preserving subpath structure."""
    detections_dir = (repo_root / "detections").resolve()
    rel = rule_path.relative_to(detections_dir)
    if rel.parts and rel.parts[0] == "retired":
        return rule_path  # already retired

    dest = detections_dir / "retired" / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(rule_path), str(dest))
    return dest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rule", help="Rule UUID or path to the .yml file")
    parser.add_argument(
        "--reason", required=True,
        help="Reason for retirement (free text, becomes part of git history)",
    )
    parser.add_argument(
        "--repo-root", type=Path, default=Path("."),
        help="Repo root (default: current directory)",
    )
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    rule_path = find_rule(repo_root, args.rule)
    if rule_path is None:
        print(f"ERROR: could not find rule '{args.rule}'", file=sys.stderr)
        return 2

    print(f"Found rule: {rule_path.relative_to(repo_root)}")
    updated = update_metadata(rule_path, args.reason)
    new_path = move_to_retired(rule_path, repo_root)

    print()
    print(f"Retired: {updated.get('title', '?')} (id {updated.get('id', '?')})")
    print(f"  status: {updated['status']}")
    print(f"  retired_at: {updated['retired_at']}")
    print(f"  reason: {updated['retirement_reason']}")
    print(f"  moved to: {new_path.relative_to(repo_root)}")
    print()
    print("Next steps:")
    print(f"  git checkout -b retire/{updated.get('id', 'rule')[:8]}")
    print("  git add detections/")
    print(f'  git commit -m "chore(retire): {updated.get("title", "rule")} — {args.reason[:50]}"')
    print("  git push -u origin HEAD")
    print("  Open a PR; the convert/deploy pipeline will stop deploying this rule on merge.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
