"""
Unit tests for orchestrator components.

We can't unit-test the actual detonation flow (it requires a real lab), but
we CAN test:
  - changed-detection resolution (git diff parsing + YAML traversal)
  - PR comment formatting (golden output for known reports)
  - Atomic mapping loader (validates the mapping schema)
  - SPL extraction from .conf stanzas

Integration tests against the live lab live in tests/integration/ (not in this repo).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools" / "orchestrator"))

import format_pr_comment  # noqa: E402
import run_detonation  # noqa: E402


# --------------------------------------------------------------------------
# format_pr_comment
# --------------------------------------------------------------------------

def test_format_pr_comment_all_passing():
    report = {
        "started_at": "2026-04-25T18:00:00Z",
        "finished_at": "2026-04-25T18:02:30Z",
        "victim_host": "win10-victim",
        "splunk_host": "splunk",
        "proxmox_host": "pve",
        "victim_vmid": 9001,
        "runs": [
            {
                "detection_id": "abc",
                "detection_path": "detections/windows/credential_access/T1003.001_lsass.yml",
                "atomic": {"technique": "T1003.001", "test_number": 1},
                "started_at": "2026-04-25T18:00:00Z",
                "snapshot_created": True,
                "detonated": True,
                "cleaned": True,
                "reverted": True,
                "detection": {
                    "fired": True,
                    "event_count": 3,
                    "latency_sec": 12.4,
                    "timeout_reached": False,
                    "sample_event": {},
                },
            }
        ],
    }
    out = format_pr_comment.render(report)
    assert "1/1 detections fired" in out
    assert "✅" in out
    assert "12.4s" in out
    assert "T1003.001" in out


def test_format_pr_comment_failure_with_revert_failure():
    report = {
        "started_at": "2026-04-25T18:00:00Z",
        "finished_at": "2026-04-25T18:05:00Z",
        "victim_host": "v",
        "splunk_host": "s",
        "proxmox_host": "p",
        "victim_vmid": 1,
        "runs": [
            {
                "detection_id": "abc",
                "detection_path": "detections/windows/execution/foo.yml",
                "atomic": {"technique": "T1059.001", "test_number": 2},
                "started_at": "2026-04-25T18:00:00Z",
                "snapshot_created": True,
                "detonated": True,
                "reverted": False,
                "detection": None,
                "error": "REVERT FAILED for dac-xyz: ProxmoxError: 500",
            }
        ],
    }
    out = format_pr_comment.render(report)
    assert "0/1 detections fired" in out
    assert "❌" in out
    assert "revert failed" in out


def test_format_pr_comment_no_runs():
    report = {
        "started_at": "2026-04-25T18:00:00Z",
        "finished_at": "2026-04-25T18:00:01Z",
        "runs": [],
    }
    out = format_pr_comment.render(report)
    assert "No detections changed" in out


# --------------------------------------------------------------------------
# atomic_mapping loader
# --------------------------------------------------------------------------

def test_load_atomic_mapping_valid(tmp_path):
    mapping_yaml = """
- detection_id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
  detection_path: detections/foo.yml
  atomics:
    - technique: T1003.001
      test_number: 1
      test_name: "Dump LSASS"
      platform: windows
      elevation: admin
      expected_alert: "LSASS Dump"
"""
    p = tmp_path / "mapping.yml"
    p.write_text(mapping_yaml)
    mapping = run_detonation.load_atomic_mapping(p)
    assert "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in mapping
    atomics = mapping["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]
    assert len(atomics) == 1
    assert atomics[0].technique == "T1003.001"
    assert atomics[0].test_number == 1
    assert atomics[0].elevation == "admin"


def test_load_atomic_mapping_empty(tmp_path):
    p = tmp_path / "mapping.yml"
    p.write_text("[]")
    mapping = run_detonation.load_atomic_mapping(p)
    assert mapping == {}


# --------------------------------------------------------------------------
# SPL loader from .conf stanza
# --------------------------------------------------------------------------

def test_load_spl_for_detection(tmp_path):
    conf = tmp_path / "abc_def.conf"
    conf.write_text(
        "[DaC - Test Rule]\n"
        "description = a test\n"
        "search = index=windows EventCode=1\n"
        "is_scheduled = 1\n"
    )
    spl = run_detonation.load_spl_for_detection("abc-def", tmp_path)
    assert spl == "index=windows EventCode=1"


def test_load_spl_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        run_detonation.load_spl_for_detection("does-not-exist", tmp_path)


# --------------------------------------------------------------------------
# changed_detections (git diff)
# --------------------------------------------------------------------------

def test_changed_detections_module_imports():
    """Smoke test — module is syntactically valid and exposes its public API."""
    sys.path.insert(0, str(REPO_ROOT / "tools" / "orchestrator"))
    import changed_detections
    assert callable(changed_detections.resolve_changed_detections)
    assert callable(changed_detections.detection_id_from_yaml)
    assert callable(changed_detections.detections_in_atomic_mapping)


def test_detection_id_from_yaml(tmp_path):
    sys.path.insert(0, str(REPO_ROOT / "tools" / "orchestrator"))
    import changed_detections

    rule = tmp_path / "rule.yml"
    rule.write_text("title: Test\nid: 12345678-1234-1234-1234-123456789012\n")
    assert changed_detections.detection_id_from_yaml(rule) == "12345678-1234-1234-1234-123456789012"

    not_yaml = tmp_path / "rule.txt"
    not_yaml.write_text("not a sigma rule")
    assert changed_detections.detection_id_from_yaml(not_yaml) is None
