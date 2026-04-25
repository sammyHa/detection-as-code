"""
Convert all Sigma rules in detections/ to Splunk SPL and Elastic EQL.

Outputs build artifacts to build/splunk/ and build/elastic/ that downstream
deploy scripts consume. Designed to be deterministic — same inputs always
produce the same outputs, so generated files can be committed to the repo
and reviewed in PRs.

Usage:
    python tools/sigma_convert.py --source detections/ --output build/
    python tools/sigma_convert.py --source detections/ --output build/ --target splunk
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

# Mapping of Sigma 'level' to alert severity in target SIEMs.
SEVERITY_MAP = {
    "informational": ("informational", 1),
    "low": ("low", 25),
    "medium": ("medium", 47),
    "high": ("high", 73),
    "critical": ("critical", 99),
}


@dataclass
class ConvertedRule:
    rule_id: str
    title: str
    description: str
    level: str
    tags: list[str]
    spl: str | None
    lucene: str | None
    source_path: Path
    error: str | None = None


def find_rule_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.y*ml") if p.is_file())


def convert_one(
    path: Path,
    splunk_be: object | None,
    lucene_be: object | None,
) -> ConvertedRule:
    """Parse one Sigma file and convert to both target query languages."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    base = ConvertedRule(
        rule_id=str(raw.get("id", "")),
        title=str(raw.get("title", "")),
        description=str(raw.get("description", "")).strip(),
        level=str(raw.get("level", "medium")),
        tags=list(raw.get("tags") or []),
        spl=None,
        lucene=None,
        source_path=path,
    )
    try:
        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        if splunk_be is not None:
            spl_results = splunk_be.convert(collection)
            base.spl = spl_results[0] if spl_results else None
        if lucene_be is not None:
            lucene_results = lucene_be.convert(collection)
            base.lucene = lucene_results[0] if lucene_results else None
    except SigmaError as exc:
        base.error = f"SigmaError: {exc}"
    except Exception as exc:  # noqa: BLE001
        base.error = f"{type(exc).__name__}: {exc}"
    return base


def write_splunk_savedsearch(rule: ConvertedRule, out_dir: Path) -> Path:
    """
    Emit a Splunk savedsearches.conf-style stanza for one rule.

    Splunk's REST API accepts the same key/value pairs that go in
    savedsearches.conf, so this format doubles as both human-readable build
    output and the source of truth the deploy script reads.
    """
    severity_name, _ = SEVERITY_MAP.get(rule.level, ("medium", 47))
    safe_id = rule.rule_id.replace("-", "_")
    name = f"DaC - {rule.title}"

    # Description goes through Splunk; keep it on a single line, escape pipes.
    description = " ".join(rule.description.split())

    stanza_lines = [
        f"[{name}]",
        f"# rule_id: {rule.rule_id}",
        f"# source: {rule.source_path.as_posix()}",
        f"# tags: {','.join(rule.tags)}",
        f'description = {description}',
        f'search = {rule.spl}',
        "is_scheduled = 1",
        "cron_schedule = */5 * * * *",
        "dispatch.earliest_time = -5m",
        "dispatch.latest_time = now",
        "alert.track = 1",
        "alert.severity = " + str(SEVERITY_MAP.get(rule.level, ("medium", 47))[1]),
        f"alert.suppress = 0",
        f"action.notable = 1",
        f"action.notable.param.rule_title = {rule.title}",
        f"action.notable.param.security_domain = threat",
        f"action.notable.param.severity = {severity_name}",
        "",
    ]

    out_path = out_dir / f"{safe_id}.conf"
    out_path.write_text("\n".join(stanza_lines), encoding="utf-8")
    return out_path


def write_elastic_rule(rule: ConvertedRule, out_dir: Path) -> Path:
    """
    Emit an Elastic Detection Engine rule as NDJSON.

    The Elastic API accepts NDJSON for bulk import. Schema docs:
    https://www.elastic.co/guide/en/security/current/rule-api-overview.html
    """
    severity_name, risk_score = SEVERITY_MAP.get(rule.level, ("medium", 47))

    # Extract MITRE technique tags for the threat[] field.
    threats = []
    for tag in rule.tags:
        if isinstance(tag, str) and tag.startswith("attack.t"):
            tech_id = tag.replace("attack.", "").upper()
            threats.append(
                {
                    "framework": "MITRE ATT&CK",
                    "technique": [{"id": tech_id, "name": "", "reference": ""}],
                }
            )

    rule_doc = {
        "rule_id": rule.rule_id,
        "name": f"DaC - {rule.title}",
        "description": " ".join(rule.description.split()) or rule.title,
        "risk_score": risk_score,
        "severity": severity_name,
        "type": "query",
        "language": "lucene",
        "query": rule.lucene,
        "index": ["winlogbeat-*", "logs-windows.*", "logs-system.*"],
        "from": "now-5m",
        "to": "now",
        "interval": "5m",
        "enabled": True,
        "tags": ["detection-as-code"] + rule.tags,
        "threat": threats,
        "author": ["Samim Hakimi"],
        "license": "MIT",
        "version": 1,
    }

    safe_id = rule.rule_id.replace("-", "_")
    out_path = out_dir / f"{safe_id}.ndjson"
    out_path.write_text(json.dumps(rule_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("detections"), help="Sigma source dir")
    parser.add_argument("--output", type=Path, default=Path("build"), help="Build output dir")
    parser.add_argument(
        "--target",
        choices=["splunk", "elastic", "both"],
        default="both",
        help="Which backend(s) to convert for",
    )
    args = parser.parse_args()

    if not args.source.exists():
        print(f"ERROR: source {args.source} not found", file=sys.stderr)
        return 2

    splunk_dir = args.output / "splunk"
    elastic_dir = args.output / "elastic"
    splunk_dir.mkdir(parents=True, exist_ok=True)
    elastic_dir.mkdir(parents=True, exist_ok=True)

    splunk_be = None
    lucene_be = None
    if args.target in ("splunk", "both"):
        from sigma.backends.splunk import SplunkBackend
        splunk_be = SplunkBackend()
    if args.target in ("elastic", "both"):
        from sigma.backends.elasticsearch import LuceneBackend
        lucene_be = LuceneBackend()

    rule_files = find_rule_files(args.source)
    if not rule_files:
        print(f"WARNING: no Sigma rules found under {args.source}")
        return 0

    converted: list[ConvertedRule] = []
    for path in rule_files:
        rule = convert_one(path, splunk_be, lucene_be)
        converted.append(rule)

        if rule.error:
            print(f"  [FAIL] {path.relative_to(args.source.parent if args.source.parent != Path('.') else args.source)}: {rule.error}")
            continue

        wrote = []
        if args.target in ("splunk", "both") and rule.spl:
            wrote.append(str(write_splunk_savedsearch(rule, splunk_dir).name))
        if args.target in ("elastic", "both") and rule.lucene:
            wrote.append(str(write_elastic_rule(rule, elastic_dir).name))
        print(f"  [OK]   {path.name} → {', '.join(wrote)}")

    failed = [r for r in converted if r.error]
    print()
    print(f"Converted {len(converted) - len(failed)}/{len(converted)} rule(s)")
    if failed:
        print("\nFailures:", file=sys.stderr)
        for r in failed:
            print(f"  - {r.source_path}: {r.error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
