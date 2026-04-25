"""
Identify which detection rules changed in a PR.

The orchestrator only re-tests detections that were modified, added, or
whose mapped atomic changed. This keeps PR feedback fast — testing all 4
rules every PR is fine; testing 200 rules every PR is not.

Used by the test-detections.yml workflow:
    git diff --name-only origin/main HEAD -- detections/ tests/atomics/

Returns a deduplicated list of detection_id (UUID) values to test.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import yaml


def changed_files(base_ref: str, head_ref: str) -> list[Path]:
    """Return paths changed between two refs, scoped to detections/ and tests/atomics/."""
    cmd = [
        "git",
        "diff",
        "--name-only",
        "--diff-filter=AMR",  # added, modified, renamed
        f"{base_ref}...{head_ref}",
        "--",
        "detections/",
        "tests/atomics/",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return [Path(line) for line in result.stdout.splitlines() if line.strip()]


def detection_id_from_yaml(path: Path) -> str | None:
    """Extract the Sigma rule UUID from a detection file."""
    if not path.exists() or path.suffix not in (".yml", ".yaml"):
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return str(data["id"]) if data and "id" in data else None
    except (yaml.YAMLError, OSError):
        return None


def detections_in_atomic_mapping(mapping_path: Path) -> set[str]:
    """Return all detection_ids referenced in tests/atomics/atomic_mapping.yml."""
    if not mapping_path.exists():
        return set()
    data = yaml.safe_load(mapping_path.read_text(encoding="utf-8")) or []
    return {str(entry["detection_id"]) for entry in data if "detection_id" in entry}


def resolve_changed_detections(
    base_ref: str,
    head_ref: str,
    repo_root: Path,
) -> list[str]:
    """
    Return the set of detection IDs that need re-testing for this PR.

    Includes:
    - detections/ files that changed (the rule itself was modified)
    - all detections referenced in tests/atomics/atomic_mapping.yml IF that
      file changed (atomic mapping changes can affect which test runs)
    """
    changed = changed_files(base_ref, head_ref)

    detection_ids: set[str] = set()
    mapping_changed = False

    for path in changed:
        full = repo_root / path
        if path.parts[0] == "detections":
            did = detection_id_from_yaml(full)
            if did:
                detection_ids.add(did)
        elif path == Path("tests/atomics/atomic_mapping.yml"):
            mapping_changed = True

    if mapping_changed:
        # Be conservative — re-test everything in the mapping
        detection_ids.update(detections_in_atomic_mapping(repo_root / "tests/atomics/atomic_mapping.yml"))

    return sorted(detection_ids)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/main", help="Base ref (default origin/main)")
    parser.add_argument("--head", default="HEAD", help="Head ref (default HEAD)")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument(
        "--all", action="store_true",
        help="Ignore git diff and return every detection in atomic_mapping.yml (for nightly runs)"
    )
    args = parser.parse_args()

    if args.all:
        ids = sorted(detections_in_atomic_mapping(args.repo_root / "tests/atomics/atomic_mapping.yml"))
    else:
        ids = resolve_changed_detections(args.base, args.head, args.repo_root)

    # Emit JSON array — easy for GitHub Actions to consume via fromJSON
    print(json.dumps(ids))
    return 0


if __name__ == "__main__":
    sys.exit(main())
