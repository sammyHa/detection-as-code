"""
Generate ATT&CK coverage artifacts from the detections/ tree.

Outputs three things on every run:

  1. docs/coverage/coverage_layer.json
     ATT&CK Navigator layer file. Open it at
     https://mitre-attack.github.io/attack-navigator/ to see a heatmap.

  2. docs/coverage/REPORT.md
     Human-readable summary: total rules, by tactic, by status, technique list.

  3. docs/coverage/badge.json
     Shields.io endpoint format. Lets the README badge stay in sync with
     reality without external services.

Scoring model:
  - 'stable'       → 100 (battle-tested, 30+ days FP review)
  - 'test'         →  60 (under FP review)
  - 'experimental' →  30 (newly written)
  - 'deprecated'   →   0 (excluded from coverage)

Multiple rules covering the same technique add additively but cap at 100.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import yaml

STATUS_SCORES = {
    "stable": 100,
    "test": 60,
    "experimental": 30,
    "deprecated": 0,
    "unsupported": 0,
}

# Color stops for the Navigator layer — green-yellow-red gradient
NAVIGATOR_GRADIENT = {
    "colors": ["#ffe5e5", "#ffd966", "#6aa84f"],
    "minValue": 0,
    "maxValue": 100,
}

TECHNIQUE_TAG_RE = re.compile(r"^attack\.t(\d{4})(\.\d{3})?$", re.IGNORECASE)


@dataclass
class ParsedRule:
    path: Path
    rule_id: str
    title: str
    status: str
    level: str
    techniques: list[str]  # ['T1003.001', 'T1059.001', ...]
    tactics: list[str]     # ['credential_access', 'execution', ...]


@dataclass
class CoverageEntry:
    technique_id: str
    score: int
    rule_count: int
    rule_titles: list[str] = field(default_factory=list)


def find_rule_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.y*ml") if p.is_file())


def extract_techniques(tags: Iterable[str]) -> list[str]:
    """Pull technique IDs (e.g. 'T1003.001') out of attack.* tags."""
    out = []
    for tag in tags or []:
        m = TECHNIQUE_TAG_RE.match(str(tag))
        if not m:
            continue
        sub = m.group(2) or ""
        out.append(f"T{m.group(1)}{sub}")
    return out


def extract_tactics(tags: Iterable[str]) -> list[str]:
    """Pull tactic names from attack.* tags (e.g. 'attack.credential_access')."""
    out = []
    for tag in tags or []:
        s = str(tag).lower()
        if not s.startswith("attack."):
            continue
        rest = s[len("attack."):]
        # Skip technique tags — those are the t#### form
        if rest.startswith("t") and rest[1:2].isdigit():
            continue
        out.append(rest)
    return out


def parse_rule(path: Path) -> ParsedRule | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    return ParsedRule(
        path=path,
        rule_id=str(data.get("id", "")),
        title=str(data.get("title", "")),
        status=str(data.get("status", "experimental")).lower(),
        level=str(data.get("level", "medium")).lower(),
        techniques=extract_techniques(data.get("tags") or []),
        tactics=extract_tactics(data.get("tags") or []),
    )


def score_rules(rules: list[ParsedRule]) -> dict[str, CoverageEntry]:
    """Aggregate per-technique coverage. Score caps at 100 per technique."""
    by_tech: dict[str, CoverageEntry] = {}
    for rule in rules:
        if rule.status in ("deprecated", "unsupported"):
            continue
        rule_score = STATUS_SCORES.get(rule.status, 30)
        for tech in rule.techniques:
            if tech not in by_tech:
                by_tech[tech] = CoverageEntry(technique_id=tech, score=0, rule_count=0)
            entry = by_tech[tech]
            entry.score = min(100, entry.score + rule_score)
            entry.rule_count += 1
            entry.rule_titles.append(rule.title)
    return by_tech


# --------------------------------------------------------------------------
# Navigator layer
# --------------------------------------------------------------------------

def render_navigator_layer(coverage: dict[str, CoverageEntry], *, name: str = "DaC Coverage") -> dict:
    techniques = []
    for tech_id, entry in sorted(coverage.items()):
        comment = (
            f"{entry.rule_count} rule(s):\n- "
            + "\n- ".join(entry.rule_titles[:5])
        )
        if entry.rule_count > 5:
            comment += f"\n... and {entry.rule_count - 5} more"
        techniques.append(
            {
                "techniqueID": tech_id,
                "score": entry.score,
                "color": "",  # let the gradient drive color
                "comment": comment,
                "enabled": True,
                "metadata": [
                    {"name": "rule_count", "value": str(entry.rule_count)},
                ],
                "showSubtechniques": True,
            }
        )

    return {
        "name": name,
        "versions": {
            "attack": "14",
            "navigator": "5.0.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            "Auto-generated detection coverage layer from "
            "github.com/sammyHa/detection-as-code. Score reflects rule "
            "maturity (stable=100, test=60, experimental=30); multiple "
            "rules covering the same technique add additively to a cap of 100."
        ),
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "showName": True,
            "showID": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": NAVIGATOR_GRADIENT,
        "legendItems": [
            {"label": "Stable", "color": "#6aa84f"},
            {"label": "Test", "color": "#ffd966"},
            {"label": "Experimental", "color": "#ffe5e5"},
        ],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
    }


# --------------------------------------------------------------------------
# Markdown report
# --------------------------------------------------------------------------

def render_report(rules: list[ParsedRule], coverage: dict[str, CoverageEntry]) -> str:
    """Generate the human-readable coverage summary."""
    by_status: dict[str, int] = defaultdict(int)
    by_tactic: dict[str, int] = defaultdict(int)
    for r in rules:
        by_status[r.status] += 1
        for t in r.tactics:
            by_tactic[t] += 1

    lines: list[str] = []
    lines.append("# Detection Coverage Report")
    lines.append("")
    lines.append(
        "_Auto-generated by `tools/coverage_report.py` on every merge to main. "
        "Do not edit by hand._"
    )
    lines.append("")
    lines.append("## At a glance")
    lines.append("")
    lines.append(f"- **Total rules:** {len(rules)}")
    lines.append(f"- **Techniques covered:** {len(coverage)}")
    avg = sum(e.score for e in coverage.values()) / len(coverage) if coverage else 0
    lines.append(f"- **Average maturity score:** {avg:.0f}/100")
    lines.append("")

    lines.append("## Rules by status")
    lines.append("")
    lines.append("| Status | Count |")
    lines.append("|---|---:|")
    for status in ("stable", "test", "experimental", "deprecated"):
        lines.append(f"| {status} | {by_status.get(status, 0)} |")
    lines.append("")

    lines.append("## Rules by ATT&CK tactic")
    lines.append("")
    lines.append("| Tactic | Rules |")
    lines.append("|---|---:|")
    for tactic, count in sorted(by_tactic.items()):
        pretty = tactic.replace("_", " ").title()
        lines.append(f"| {pretty} | {count} |")
    lines.append("")

    lines.append("## Technique coverage")
    lines.append("")
    lines.append("| Technique | Score | Rules |")
    lines.append("|---|---:|---:|")
    for tech_id in sorted(coverage):
        entry = coverage[tech_id]
        lines.append(
            f"| [{tech_id}](https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/) "
            f"| {entry.score} | {entry.rule_count} |"
        )
    lines.append("")
    lines.append("## How to view the coverage heatmap")
    lines.append("")
    lines.append(
        "Open [coverage_layer.json](coverage_layer.json) in the "
        "[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) "
        "(File → Open Existing Layer → Upload from local) to see the heatmap."
    )
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Shields.io endpoint badge
# --------------------------------------------------------------------------

def render_badge(coverage: dict[str, CoverageEntry]) -> dict:
    """Generate a shields.io endpoint-format badge JSON."""
    n = len(coverage)
    if n == 0:
        color = "lightgrey"
    elif n < 10:
        color = "yellow"
    elif n < 25:
        color = "yellowgreen"
    else:
        color = "brightgreen"
    return {
        "schemaVersion": 1,
        "label": "ATT&CK techniques covered",
        "message": str(n),
        "color": color,
    }


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("detections"))
    parser.add_argument("--output", type=Path, default=Path("docs/coverage"))
    parser.add_argument("--name", default="DaC Coverage", help="Layer name shown in Navigator")
    args = parser.parse_args()

    if not args.source.exists():
        print(f"ERROR: source dir {args.source} not found", file=sys.stderr)
        return 2

    args.output.mkdir(parents=True, exist_ok=True)

    rule_files = find_rule_files(args.source)
    rules = [r for r in (parse_rule(p) for p in rule_files) if r is not None]
    coverage = score_rules(rules)

    layer = render_navigator_layer(coverage, name=args.name)
    layer_path = args.output / "coverage_layer.json"
    layer_path.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")

    report = render_report(rules, coverage)
    report_path = args.output / "REPORT.md"
    report_path.write_text(report, encoding="utf-8")

    badge = render_badge(coverage)
    badge_path = args.output / "badge.json"
    badge_path.write_text(json.dumps(badge, indent=2) + "\n", encoding="utf-8")

    print(f"Parsed {len(rules)} rule(s)")
    print(f"Covering {len(coverage)} unique technique(s)")
    print(f"Wrote {layer_path}")
    print(f"Wrote {report_path}")
    print(f"Wrote {badge_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
