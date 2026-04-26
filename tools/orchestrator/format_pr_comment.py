"""
Format a Phase 3 detonation report as a Markdown summary for PR comment.

Reads phase3-report.json, emits Markdown to stdout. Used by the GitHub
Actions workflow to post results back to the PR.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def fmt_latency(detection: dict | None) -> str:
    if not detection:
        return "—"
    if detection.get("timeout_reached"):
        return f"⏱️ timeout ({detection.get('latency_sec', 0):.0f}s)"
    return f"{detection.get('latency_sec', 0):.1f}s"


def render(report: dict) -> str:
    runs = report.get("runs", [])
    total = len(runs)
    passed = sum(1 for r in runs if r.get("detection", {}) and r["detection"].get("fired") and not r.get("error"))
    failed = total - passed

    lines: list[str] = []
    icon = "✅" if failed == 0 and total > 0 else ("⚠️" if total == 0 else "❌")
    lines.append(f"## {icon} Phase 3 — Detection Validation")
    lines.append("")
    lines.append(f"**{passed}/{total} detections fired** within SLA.")
    lines.append("")

    if total == 0:
        lines.append("_No detections changed in this PR — no detonation runs were executed._")
        return "\n".join(lines)

    lines.append("| Detection | Atomic | Fired | Latency | Events | Notes |")
    lines.append("|---|---|:-:|:-:|:-:|---|")
    for r in runs:
        atomic = r.get("atomic", {})
        det = r.get("detection")
        fired = det and det.get("fired")
        icon = "✅" if fired else "❌"
        latency = fmt_latency(det)
        events = det.get("event_count", 0) if det else 0

        notes = []
        if r.get("error"):
            notes.append(f"⚠️ {r['error'][:80]}")
        if not r.get("snapshot_created"):
            notes.append("snapshot skipped")
        if r.get("snapshot_created") and not r.get("reverted"):
            notes.append("⚠️ revert failed")
        notes_str = "; ".join(notes) or "—"

        path = r.get("detection_path", "?").split("/")[-1]
        technique = atomic.get("technique", "?")
        # Technique IDs in the mapping already include the 'T' prefix
        lines.append(
            f"| `{path}` | {technique} #{atomic.get('test_number', '?')} "
            f"| {icon} | {latency} | {events} | {notes_str} |"
        )

    lines.append("")
    lines.append(
        f"<sub>Victim: `{report.get('victim_host', '?')}` (VMID {report.get('victim_vmid', '?')}) · "
        f"Splunk: `{report.get('splunk_host', '?')}` · "
        f"Proxmox: `{report.get('proxmox_host', '?')}`</sub>"
    )
    lines.append(
        f"<sub>Started {report.get('started_at', '')} · Finished {report.get('finished_at', '')}</sub>"
    )

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()

    if not args.report.exists():
        print(f"## ❌ Phase 3 — Detection Validation\n\nReport file `{args.report}` not found.")
        return 1

    report = json.loads(args.report.read_text(encoding="utf-8"))
    print(render(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
