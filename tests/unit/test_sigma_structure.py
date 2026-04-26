"""
Structural unit tests for Sigma rules.

pySigma parses syntax. These tests enforce *organizational* standards that
make a detection library maintainable: consistent metadata, ATT&CK tagging,
required fields, and so on. Failing one of these tests means a rule will
parse but is missing context a SOC analyst needs at 3 a.m.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DETECTIONS_DIR = REPO_ROOT / "detections"

REQUIRED_TOP_LEVEL = {
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "tags",
    "logsource",
    "detection",
    "level",
}

VALID_STATUS = {"experimental", "test", "stable", "deprecated", "unsupported"}
VALID_LEVEL = {"informational", "low", "medium", "high", "critical"}


def all_rules() -> list[Path]:
    return sorted(p for p in DETECTIONS_DIR.rglob("*.y*ml") if p.is_file())


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("rule_path", all_rules(), ids=lambda p: str(p.relative_to(REPO_ROOT)))
class TestSigmaRuleStructure:
    def test_required_fields_present(self, rule_path: Path) -> None:
        rule = load(rule_path)
        missing = REQUIRED_TOP_LEVEL - set(rule.keys())
        assert not missing, f"Missing required field(s): {sorted(missing)}"

    def test_id_is_valid_uuid(self, rule_path: Path) -> None:
        rule = load(rule_path)
        try:
            uuid.UUID(str(rule["id"]))
        except (ValueError, TypeError):
            pytest.fail(f"id is not a valid UUID: {rule.get('id')!r}")

    def test_status_is_valid(self, rule_path: Path) -> None:
        rule = load(rule_path)
        assert rule["status"] in VALID_STATUS, (
            f"status={rule['status']!r} not in {sorted(VALID_STATUS)}"
        )

    def test_level_is_valid(self, rule_path: Path) -> None:
        rule = load(rule_path)
        assert rule["level"] in VALID_LEVEL, (
            f"level={rule['level']!r} not in {sorted(VALID_LEVEL)}"
        )

    def test_has_attack_tag(self, rule_path: Path) -> None:
        rule = load(rule_path)
        tags = rule.get("tags") or []
        attack_tags = [t for t in tags if isinstance(t, str) and t.startswith("attack.")]
        assert attack_tags, "rule has no attack.* tag — every detection must map to ATT&CK"

    def test_has_attack_technique_tag(self, rule_path: Path) -> None:
        rule = load(rule_path)
        tags = rule.get("tags") or []
        # T#### or T####.### format
        pattern = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
        technique_tags = [t for t in tags if isinstance(t, str) and pattern.match(t)]
        assert technique_tags, (
            "rule has no attack.t#### technique tag — coverage reporting requires technique IDs"
        )

    def test_has_falsepositives(self, rule_path: Path) -> None:
        rule = load(rule_path)
        fps = rule.get("falsepositives")
        assert fps, "falsepositives must be documented — analysts need to know what to triage"

    def test_has_references(self, rule_path: Path) -> None:
        rule = load(rule_path)
        refs = rule.get("references") or []
        assert refs, "references required — link to ATT&CK page and atomic test at minimum"
