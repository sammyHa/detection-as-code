"""
Unit tests for Phase 5 — backtest helpers, fp_trend aggregation,
retire CLI, and coverage_report retired-rules handling.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "tools" / "orchestrator"))

import coverage_report  # noqa: E402
import fp_trend  # noqa: E402
import retire_detection  # noqa: E402
import backtest  # noqa: E402


# --------------------------------------------------------------------------
# retire_detection
# --------------------------------------------------------------------------

SAMPLE_RULE = """\
title: Test Rule for Retirement
id: 11111111-1111-1111-1111-111111111111
status: experimental
description: A rule that exists for tests
author: Test
date: 2026/01/01
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\foo.exe'
  condition: selection
falsepositives:
  - none
references:
  - https://attack.mitre.org/techniques/T1059/001/
level: medium
"""


def _make_repo(tmp_path: Path) -> Path:
    (tmp_path / "detections" / "windows" / "execution").mkdir(parents=True)
    rule_path = tmp_path / "detections" / "windows" / "execution" / "T1059.001_test.yml"
    rule_path.write_text(SAMPLE_RULE)
    return tmp_path


def test_retire_finds_rule_by_uuid(tmp_path):
    repo = _make_repo(tmp_path)
    found = retire_detection.find_rule(repo, "11111111-1111-1111-1111-111111111111")
    assert found is not None
    assert found.name == "T1059.001_test.yml"


def test_retire_finds_rule_by_path(tmp_path):
    repo = _make_repo(tmp_path)
    rule_path = repo / "detections" / "windows" / "execution" / "T1059.001_test.yml"
    found = retire_detection.find_rule(repo, str(rule_path))
    assert found == rule_path.resolve()


def test_retire_returns_none_for_missing(tmp_path):
    repo = _make_repo(tmp_path)
    assert retire_detection.find_rule(repo, "00000000-0000-0000-0000-000000000000") is None


def test_retire_updates_metadata_and_moves_file(tmp_path):
    repo = _make_repo(tmp_path)
    rule_path = repo / "detections" / "windows" / "execution" / "T1059.001_test.yml"
    retire_detection.update_metadata(rule_path, "test reason: noisy")
    new_path = retire_detection.move_to_retired(rule_path, repo)

    # Original location no longer has the file
    assert not rule_path.exists()
    # New location does
    expected = repo / "detections" / "retired" / "windows" / "execution" / "T1059.001_test.yml"
    assert new_path == expected
    assert new_path.exists()

    # Metadata is updated
    data = yaml.safe_load(new_path.read_text())
    assert data["status"] == "deprecated"
    assert data["retirement_reason"] == "test reason: noisy"
    assert "retired_at" in data


# --------------------------------------------------------------------------
# coverage_report — retired-rules behavior
# --------------------------------------------------------------------------

def test_find_rule_files_excludes_retired_by_default(tmp_path):
    detections = tmp_path / "detections"
    (detections / "windows" / "execution").mkdir(parents=True)
    (detections / "retired" / "windows" / "execution").mkdir(parents=True)
    (detections / "windows" / "execution" / "active.yml").write_text("title: active\nid: a\n")
    (detections / "retired" / "windows" / "execution" / "old.yml").write_text("title: old\nid: o\n")

    paths = coverage_report.find_rule_files(detections, include_retired=False)
    assert len(paths) == 1
    assert paths[0].name == "active.yml"


def test_find_rule_files_includes_retired_when_asked(tmp_path):
    detections = tmp_path / "detections"
    (detections / "windows" / "execution").mkdir(parents=True)
    (detections / "retired" / "windows" / "execution").mkdir(parents=True)
    (detections / "windows" / "execution" / "active.yml").write_text("title: active\nid: a\n")
    (detections / "retired" / "windows" / "execution" / "old.yml").write_text("title: old\nid: o\n")

    paths = coverage_report.find_rule_files(detections, include_retired=True)
    assert len(paths) == 2


def test_score_rules_excludes_retired():
    rules = [
        coverage_report.ParsedRule(
            path=Path("a"), rule_id="a", title="active", status="experimental",
            level="high", techniques=["T1003.001"], tactics=["credential_access"],
            retired=False,
        ),
        coverage_report.ParsedRule(
            path=Path("b"), rule_id="b", title="retired", status="deprecated",
            level="high", techniques=["T1003.001"], tactics=["credential_access"],
            retired=True, retired_at="2026-04-01T00:00:00Z",
            retirement_reason="superseded",
        ),
    ]
    cov = coverage_report.score_rules(rules)
    assert "T1003.001" in cov
    # Only the active rule contributes
    assert cov["T1003.001"].rule_count == 1
    assert cov["T1003.001"].rule_titles == ["active"]


def test_render_report_includes_retired_section_when_present():
    rules = [
        coverage_report.ParsedRule(
            path=Path("a"), rule_id="a", title="Active Rule", status="stable",
            level="high", techniques=["T1003.001"], tactics=["credential_access"],
        ),
        coverage_report.ParsedRule(
            path=Path("b"), rule_id="b", title="Old Rule", status="deprecated",
            level="medium", techniques=["T1059.001"], tactics=["execution"],
            retired=True, retired_at="2026-04-01T00:00:00Z",
            retirement_reason="superseded by T1059.001 v2",
        ),
    ]
    coverage = coverage_report.score_rules(rules)
    report = coverage_report.render_report(rules, coverage)
    assert "Retired rules (audit log)" in report
    assert "Old Rule" in report
    assert "superseded by T1059.001 v2" in report


def test_render_report_omits_retired_section_when_empty():
    rules = [
        coverage_report.ParsedRule(
            path=Path("a"), rule_id="a", title="Active", status="stable",
            level="high", techniques=["T1003.001"], tactics=["credential_access"],
        ),
    ]
    coverage = coverage_report.score_rules(rules)
    report = coverage_report.render_report(rules, coverage)
    assert "Retired rules (audit log)" not in report


# --------------------------------------------------------------------------
# fp_trend
# --------------------------------------------------------------------------

def test_fp_trend_aggregate_builds_per_rule_series(tmp_path):
    history = tmp_path / "fp.jsonl"
    history.write_text(
        json.dumps({"collected_at": "2026-04-20T09:00:00Z", "rules": [
            {"name": "DaC - A", "fires": 1},
            {"name": "DaC - B", "fires": 0},
        ]}) + "\n" +
        json.dumps({"collected_at": "2026-04-21T09:00:00Z", "rules": [
            {"name": "DaC - A", "fires": 3},
            {"name": "DaC - B", "fires": 0},
        ]}) + "\n"
    )
    records = fp_trend.load_history(history)
    series = fp_trend.aggregate(records)
    assert "DaC - A" in series
    assert series["DaC - A"].latest == 3
    assert series["DaC - A"].total == 4
    assert series["DaC - B"].latest == 0


def test_fp_trend_color_grading():
    assert fp_trend.color_for(0) == fp_trend.COLOR_CLEAN
    assert fp_trend.color_for(2) == fp_trend.COLOR_NOISY
    assert fp_trend.color_for(10) == fp_trend.COLOR_BAD


def test_fp_trend_empty_state():
    svg = fp_trend.render_svg({})
    assert "No FP history" in svg
    assert svg.startswith("<svg")


def test_fp_trend_renders_with_data():
    series = {
        "DaC - Test": fp_trend.RuleSeries(
            name="DaC - Test",
            points=[("2026-04-20T09:00:00Z", 0), ("2026-04-21T09:00:00Z", 3)],
        ),
    }
    svg = fp_trend.render_svg(series)
    assert "DaC - Test" in svg
    assert "<polyline" in svg


# --------------------------------------------------------------------------
# backtest
# --------------------------------------------------------------------------

def test_backtest_fp_budget_default():
    rule = {"title": "x", "id": "y"}
    assert backtest.fp_budget_for(rule) == 0


def test_backtest_fp_budget_custom():
    rule = {"title": "x", "id": "y", "custom": {"fp_budget_per_30d": 5}}
    assert backtest.fp_budget_for(rule) == 5


def test_backtest_load_spl(tmp_path):
    conf = tmp_path / "abc_def.conf"
    conf.write_text(
        "[Saved Search]\n"
        "search = index=windows EventCode=1\n"
    )
    spl = backtest.load_spl("abc-def", tmp_path)
    assert spl == "index=windows EventCode=1"


def test_backtest_load_spl_missing(tmp_path):
    with pytest.raises(FileNotFoundError):
        backtest.load_spl("missing-id", tmp_path)


def test_backtest_find_rules_excludes_retired(tmp_path):
    detections = tmp_path / "detections"
    (detections / "windows" / "execution").mkdir(parents=True)
    (detections / "retired" / "windows" / "execution").mkdir(parents=True)
    (detections / "windows" / "execution" / "active.yml").write_text("title: a\nid: a\n")
    (detections / "retired" / "windows" / "execution" / "old.yml").write_text("title: o\nid: o\n")

    rules = backtest.find_rules(detections)
    assert len(rules) == 1
    assert rules[0].name == "active.yml"
