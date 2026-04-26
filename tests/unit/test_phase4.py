"""
Unit tests for Phase 4 — coverage report and latency dashboard generators.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import coverage_report  # noqa: E402
import latency_dashboard  # noqa: E402


# --------------------------------------------------------------------------
# coverage_report
# --------------------------------------------------------------------------

SAMPLE_RULE = """
title: Test Rule
id: 11111111-1111-1111-1111-111111111111
status: experimental
description: |
  Sample rule for tests.
author: Test Author
date: 2026/04/25
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\foo.exe'
  condition: selection
falsepositives:
  - none expected
references:
  - https://attack.mitre.org/techniques/T1003/001/
level: high
"""


def test_extract_techniques_handles_subtechniques():
    tags = ["attack.credential_access", "attack.t1003.001", "attack.t1027"]
    techs = coverage_report.extract_techniques(tags)
    assert techs == ["T1003.001", "T1027"]


def test_extract_techniques_ignores_non_attack_tags():
    tags = ["custom.tag", "attack.t1059.001", "another"]
    techs = coverage_report.extract_techniques(tags)
    assert techs == ["T1059.001"]


def test_extract_tactics_excludes_techniques():
    tags = ["attack.credential_access", "attack.t1003.001", "attack.execution"]
    tactics = coverage_report.extract_tactics(tags)
    assert tactics == ["credential_access", "execution"]


def test_parse_rule(tmp_path):
    p = tmp_path / "rule.yml"
    p.write_text(SAMPLE_RULE)
    rule = coverage_report.parse_rule(p)
    assert rule is not None
    assert rule.title == "Test Rule"
    assert rule.status == "experimental"
    assert "T1003.001" in rule.techniques
    assert "credential_access" in rule.tactics


def test_score_rules_caps_at_100(tmp_path):
    rules = []
    # 4 'stable' rules @ 100 each on the same technique should still cap at 100
    for i in range(4):
        rules.append(
            coverage_report.ParsedRule(
                path=Path(f"r{i}"),
                rule_id=f"id{i}",
                title=f"rule{i}",
                status="stable",
                level="high",
                techniques=["T1003.001"],
                tactics=["credential_access"],
            )
        )
    cov = coverage_report.score_rules(rules)
    assert cov["T1003.001"].score == 100
    assert cov["T1003.001"].rule_count == 4


def test_score_rules_excludes_deprecated():
    rules = [
        coverage_report.ParsedRule(
            path=Path("r"), rule_id="x", title="t", status="deprecated",
            level="low", techniques=["T1003.001"], tactics=["credential_access"],
        )
    ]
    assert coverage_report.score_rules(rules) == {}


def test_render_navigator_layer_structure():
    cov = {
        "T1003.001": coverage_report.CoverageEntry(
            technique_id="T1003.001", score=60, rule_count=1, rule_titles=["LSASS dump"]
        )
    }
    layer = coverage_report.render_navigator_layer(cov)
    assert layer["domain"] == "enterprise-attack"
    assert len(layer["techniques"]) == 1
    t = layer["techniques"][0]
    assert t["techniqueID"] == "T1003.001"
    assert t["score"] == 60
    assert "LSASS dump" in t["comment"]


def test_render_badge_color_grades():
    empty = coverage_report.render_badge({})
    assert empty["color"] == "lightgrey"
    assert empty["message"] == "0"

    five = {
        f"T100{i}": coverage_report.CoverageEntry(f"T100{i}", 30, 1, [])
        for i in range(5)
    }
    assert coverage_report.render_badge(five)["color"] == "yellow"

    thirty = {
        f"T20{i:02d}": coverage_report.CoverageEntry(f"T20{i:02d}", 30, 1, [])
        for i in range(30)
    }
    assert coverage_report.render_badge(thirty)["color"] == "brightgreen"


# --------------------------------------------------------------------------
# latency_dashboard
# --------------------------------------------------------------------------

def test_aggregate_computes_percentiles():
    reports = [{
        "runs": [
            {"atomic": {"technique": "T1"}, "detection": {"fired": True, "latency_sec": 10, "timeout_reached": False}},
            {"atomic": {"technique": "T1"}, "detection": {"fired": True, "latency_sec": 20, "timeout_reached": False}},
            {"atomic": {"technique": "T1"}, "detection": {"fired": True, "latency_sec": 30, "timeout_reached": False}},
        ]
    }]
    stats = latency_dashboard.aggregate(reports)
    assert "T1" in stats
    assert stats["T1"].p50 == 20
    assert stats["T1"].pass_count == 3
    assert stats["T1"].pass_rate == 1.0


def test_aggregate_excludes_timeouts_from_latency():
    reports = [{
        "runs": [
            {"atomic": {"technique": "T1"}, "detection": {"fired": True, "latency_sec": 10, "timeout_reached": False}},
            {"atomic": {"technique": "T1"}, "detection": {"fired": False, "latency_sec": 300, "timeout_reached": True}},
        ]
    }]
    stats = latency_dashboard.aggregate(reports)
    # Only the successful 10s sample should drive p50
    assert stats["T1"].p50 == 10
    assert stats["T1"].pass_count == 1
    assert stats["T1"].total_count == 2
    assert stats["T1"].pass_rate == 0.5


def test_aggregate_handles_all_failures():
    reports = [{
        "runs": [
            {"atomic": {"technique": "T1"}, "detection": {"fired": False, "latency_sec": 300, "timeout_reached": True}},
        ]
    }]
    stats = latency_dashboard.aggregate(reports)
    assert stats["T1"].p50 == 0.0
    assert stats["T1"].pass_count == 0


def test_render_svg_with_data():
    stats = {
        "T1003.001": latency_dashboard.TechniqueStats(
            technique="T1003.001", samples=[10.0, 12.0, 15.0], pass_count=3, total_count=3,
        ),
    }
    svg = latency_dashboard.render_svg(stats)
    assert svg.startswith("<svg")
    assert "T1003.001" in svg
    assert "Detection latency by technique" in svg


def test_render_svg_empty_state():
    svg = latency_dashboard.render_svg({})
    assert svg.startswith("<svg")
    assert "No Phase 3 reports" in svg


def test_collect_reports_directory(tmp_path):
    # One valid report, one unrelated json
    (tmp_path / "valid.json").write_text(json.dumps({"runs": [{"atomic": {"technique": "T1"}}]}))
    (tmp_path / "noise.json").write_text(json.dumps({"unrelated": "data"}))
    reports = latency_dashboard.collect_reports(tmp_path)
    assert len(reports) == 1
    assert reports[0]["runs"][0]["atomic"]["technique"] == "T1"
