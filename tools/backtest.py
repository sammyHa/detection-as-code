"""
Backtest converted detection rules against a benign telemetry corpus.

For each detection in scope, runs its converted SPL against a configured
"known-benign" time window in Splunk and asserts the rule fires fewer
times than its configured FP budget. A rule that fires above the budget
on benign telemetry will produce false positives in production — block
the PR until it's tuned.

Two corpus sources are supported:

  1. Lab-captured baseline (preferred): a fixed time range in the lab
     Splunk during which no atomics or active red-team work occurred.
     Configured via env BACKTEST_EARLIEST and BACKTEST_LATEST.

  2. Public corpus index (fallback): a Splunk index ingested from a
     curated benign dataset (e.g., parts of the Mordor Project). Used
     when the lab hasn't yet captured a baseline.

FP budgets are per-rule. Default is 0 (rule must not fire at all on
benign data). Rules that legitimately fire on rare benign events can
declare their tolerance:

  custom:
    fp_budget_per_30d: 5

Usage:
    # Backtest a single rule
    python tools/backtest.py --rule detections/.../foo.yml

    # Backtest every rule that maps to a converted SPL
    python tools/backtest.py --all --build-dir build/splunk
"""

from __future__ import annotations

import argparse
import configparser
import json
import logging
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml

# Reuse Splunk plumbing from the orchestrator
sys.path.insert(0, str(Path(__file__).resolve().parent / "orchestrator"))
from splunk_query import SplunkQueryClient, SplunkQueryConfig, SplunkQueryError  # noqa: E402

log = logging.getLogger("backtest")

DEFAULT_FP_BUDGET = 0
DEFAULT_BACKTEST_EARLIEST = "-30d"
DEFAULT_BACKTEST_LATEST = "-1d"  # exclude the last 24h to avoid in-flight detonations


@dataclass
class BacktestResult:
    detection_id: str
    detection_path: str
    rule_title: str
    fp_budget: int
    benign_hits: int
    earliest: str
    latest: str
    passed: bool
    error: str | None = None


def load_rule_metadata(path: Path) -> dict:
    """Read just the metadata fields we need from a Sigma rule."""
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def fp_budget_for(rule: dict) -> int:
    """Read the per-rule FP budget; default to 0 (must not fire)."""
    custom = rule.get("custom") or {}
    return int(custom.get("fp_budget_per_30d", DEFAULT_FP_BUDGET))


def load_spl(detection_id: str, build_dir: Path) -> str:
    """Read the converted SPL from build/splunk/<id>.conf."""
    safe_id = detection_id.replace("-", "_")
    conf = build_dir / f"{safe_id}.conf"
    if not conf.exists():
        raise FileNotFoundError(f"converted SPL not found: {conf}")
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.read(conf, encoding="utf-8")
    for section in parser.sections():
        if parser.has_option(section, "search"):
            return parser.get(section, "search")
    raise ValueError(f"no 'search' field in {conf}")


def run_backtest(
    rule_path: Path,
    build_dir: Path,
    splunk: SplunkQueryClient,
    *,
    earliest: str,
    latest: str,
) -> BacktestResult:
    """Backtest one rule. Returns BacktestResult; never raises."""
    rule = load_rule_metadata(rule_path)
    rule_id = str(rule.get("id", ""))
    title = str(rule.get("title", rule_path.name))
    budget = fp_budget_for(rule)

    result = BacktestResult(
        detection_id=rule_id,
        detection_path=str(rule_path),
        rule_title=title,
        fp_budget=budget,
        benign_hits=0,
        earliest=earliest,
        latest=latest,
        passed=False,
    )

    try:
        spl = load_spl(rule_id, build_dir)
    except (FileNotFoundError, ValueError) as exc:
        result.error = f"could not load SPL: {exc}"
        return result

    # Wrap in `| stats count` so we don't pull events back, just the count
    counting_spl = f"{spl} | stats count"

    try:
        sid = splunk._create_job(counting_spl, earliest=earliest, latest=latest)
        # Wait for completion — give it up to 5 minutes for a 30d window
        import time
        deadline = time.time() + 300
        while time.time() < deadline:
            done, _ = splunk._job_done(sid)
            if done:
                break
            time.sleep(2)
        else:
            result.error = "backtest job timed out"
            return result

        results = splunk._job_results(sid, count=1)
        count = int(results[0].get("count", 0)) if results else 0
        result.benign_hits = count
        result.passed = count <= budget
    except SplunkQueryError as exc:
        result.error = f"splunk query failed: {exc}"

    return result


def find_rules(detections_dir: Path) -> list[Path]:
    """Return all Sigma rules under detections/, excluding retired/."""
    return sorted(
        p for p in detections_dir.rglob("*.y*ml")
        if p.is_file() and "retired" not in p.parts
    )


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s | %(message)s")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rule", type=Path, help="Backtest a single rule file")
    parser.add_argument("--all", action="store_true", help="Backtest every non-retired rule")
    parser.add_argument("--detections-dir", type=Path, default=Path("detections"))
    parser.add_argument("--build-dir", type=Path, default=Path("build/splunk"))
    parser.add_argument("--report", type=Path, default=Path("backtest-report.json"))
    parser.add_argument(
        "--earliest", default=os.environ.get("BACKTEST_EARLIEST", DEFAULT_BACKTEST_EARLIEST),
    )
    parser.add_argument(
        "--latest", default=os.environ.get("BACKTEST_LATEST", DEFAULT_BACKTEST_LATEST),
    )
    args = parser.parse_args()

    if not args.rule and not args.all:
        print("ERROR: pass --rule <path> or --all", file=sys.stderr)
        return 2

    rules = [args.rule] if args.rule else find_rules(args.detections_dir)
    if not rules:
        print("WARNING: no rules to backtest")
        args.report.write_text(json.dumps({"results": [], "passed": 0, "failed": 0}))
        return 0

    splunk = SplunkQueryClient()
    log.info(
        "backtesting %d rule(s) against %s → %s on %s",
        len(rules), args.earliest, args.latest, splunk.cfg.base_url,
    )

    results = [
        run_backtest(p, args.build_dir, splunk, earliest=args.earliest, latest=args.latest)
        for p in rules
    ]

    failures = [r for r in results if not r.passed]
    summary = {
        "earliest": args.earliest,
        "latest": args.latest,
        "splunk_host": splunk.cfg.host,
        "results": [asdict(r) for r in results],
        "passed": sum(1 for r in results if r.passed),
        "failed": len(failures),
    }
    args.report.write_text(json.dumps(summary, indent=2))

    print()
    print(f"Backtest summary: {summary['passed']}/{len(results)} passed")
    for r in failures:
        if r.error:
            print(f"  [ERROR] {r.rule_title}: {r.error}", file=sys.stderr)
        else:
            print(
                f"  [FAIL ] {r.rule_title}: {r.benign_hits} benign hits "
                f"(budget {r.fp_budget})",
                file=sys.stderr,
            )

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
