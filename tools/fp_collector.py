"""
Collect false-positive rate data from deployed Splunk saved searches.

Runs nightly. Queries Splunk's _audit index for `alert_fired` events from
DaC-deployed saved searches over the last 24 hours, aggregates per-rule
fire counts, and appends a single timestamped record to docs/fp_history.jsonl.

The JSONL file is append-only by design: git history IS the audit trail.
Never rewrite or compress this file — past readings are evidence.

Output schema (one record per night, one line):
{
  "collected_at": "2026-04-26T09:00:00Z",
  "window_earliest": "-24h",
  "window_latest": "now",
  "rules": [
    {"name": "DaC - LSASS Memory Dump via Procdump", "fires": 0},
    {"name": "DaC - PowerShell Encoded Command Execution", "fires": 3},
    ...
  ]
}
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import sys
import time
from pathlib import Path

# Reuse Splunk plumbing from the orchestrator
sys.path.insert(0, str(Path(__file__).resolve().parent / "orchestrator"))
from splunk_query import SplunkQueryClient, SplunkQueryError  # noqa: E402

log = logging.getLogger("fp_collector")

DEFAULT_WINDOW_EARLIEST = "-24h"
DEFAULT_WINDOW_LATEST = "now"
JOB_POLL_TIMEOUT_SEC = 120


def collect_fires(
    splunk: SplunkQueryClient,
    *,
    earliest: str,
    latest: str,
    rule_prefix: str = "DaC - ",
) -> dict[str, int]:
    """
    Query Splunk audit log for alert fires from saved searches matching prefix.

    Splunk records alert fires in _audit with action="alert_fired" and the
    triggering search name in `savedsearch_name`. We aggregate per-rule
    counts over the window.
    """
    spl = (
        f'index=_audit action=alert_fired savedsearch_name="{rule_prefix}*" '
        f'| stats count by savedsearch_name'
    )

    sid = splunk._create_job(spl, earliest=earliest, latest=latest)
    deadline = time.time() + JOB_POLL_TIMEOUT_SEC
    while time.time() < deadline:
        done, _ = splunk._job_done(sid)
        if done:
            break
        time.sleep(1)
    else:
        raise SplunkQueryError(f"audit query timed out after {JOB_POLL_TIMEOUT_SEC}s")

    rows = splunk._job_results(sid, count=1000)
    return {row["savedsearch_name"]: int(row.get("count", 0)) for row in rows}


def append_record(
    history_path: Path,
    fires: dict[str, int],
    *,
    earliest: str,
    latest: str,
) -> dict:
    """Append one nightly record to the JSONL file. Returns the record."""
    record = {
        "collected_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_earliest": earliest,
        "window_latest": latest,
        "rules": [
            {"name": name, "fires": count}
            for name, count in sorted(fires.items())
        ],
    }
    history_path.parent.mkdir(parents=True, exist_ok=True)
    with history_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return record


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s | %(message)s")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--history", type=Path, default=Path("docs/coverage/fp_history.jsonl"),
    )
    parser.add_argument(
        "--earliest", default=os.environ.get("FP_WINDOW_EARLIEST", DEFAULT_WINDOW_EARLIEST),
    )
    parser.add_argument(
        "--latest", default=os.environ.get("FP_WINDOW_LATEST", DEFAULT_WINDOW_LATEST),
    )
    parser.add_argument(
        "--rule-prefix", default="DaC - ",
        help="Prefix of saved search names to include",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print the record but don't append to history",
    )
    args = parser.parse_args()

    splunk = SplunkQueryClient()
    log.info(
        "collecting FP fires from %s in window %s → %s",
        splunk.cfg.host, args.earliest, args.latest,
    )

    try:
        fires = collect_fires(
            splunk,
            earliest=args.earliest,
            latest=args.latest,
            rule_prefix=args.rule_prefix,
        )
    except SplunkQueryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    log.info("collected fire counts for %d rule(s)", len(fires))

    if args.dry_run:
        record = {
            "collected_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "window_earliest": args.earliest,
            "window_latest": args.latest,
            "rules": [{"name": n, "fires": c} for n, c in sorted(fires.items())],
        }
        print(json.dumps(record, indent=2))
        return 0

    append_record(args.history, fires, earliest=args.earliest, latest=args.latest)
    log.info("appended to %s", args.history)
    return 0


if __name__ == "__main__":
    sys.exit(main())
