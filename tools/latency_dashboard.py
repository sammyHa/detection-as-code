"""
Generate a detection-latency SVG dashboard from Phase 3 report artifacts.

Reads one or more phase3-report.json files (downloaded from GitHub Actions
artifacts) and renders an SVG bar chart showing p50/p95 detection latency
per technique. The SVG is committed to docs/coverage/latency.svg and
embedded in the README.

Why SVG and not D3/React: GitHub markdown renders SVG inline. React widgets
don't. The whole point of Phase 4 is to make the work visible without
running anything.

Usage:
    # Aggregate all reports under a directory
    python tools/latency_dashboard.py --reports artifacts/ --output docs/coverage/latency.svg

    # Single file
    python tools/latency_dashboard.py --reports phase3-report.json --output docs/coverage/latency.svg
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TechniqueStats:
    technique: str
    samples: list[float]
    pass_count: int
    total_count: int

    @property
    def p50(self) -> float:
        successful = [s for s in self.samples if s > 0]
        return statistics.median(successful) if successful else 0.0

    @property
    def p95(self) -> float:
        successful = sorted(s for s in self.samples if s > 0)
        if not successful:
            return 0.0
        # Closest-rank p95
        idx = max(0, math.ceil(0.95 * len(successful)) - 1)
        return successful[idx]

    @property
    def pass_rate(self) -> float:
        return self.pass_count / self.total_count if self.total_count else 0.0


def collect_reports(report_path: Path) -> list[dict]:
    """Load one report file or every JSON file under a directory."""
    if report_path.is_file():
        return [json.loads(report_path.read_text(encoding="utf-8"))]
    if report_path.is_dir():
        out = []
        for p in report_path.rglob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            # Heuristic — Phase 3 reports have a 'runs' array
            if isinstance(data, dict) and "runs" in data:
                out.append(data)
        return out
    return []


def aggregate(reports: list[dict]) -> dict[str, TechniqueStats]:
    """Aggregate per-technique latency and pass rate across all reports."""
    samples: dict[str, list[float]] = defaultdict(list)
    pass_count: dict[str, int] = defaultdict(int)
    total_count: dict[str, int] = defaultdict(int)

    for report in reports:
        for run in report.get("runs", []):
            atomic = run.get("atomic", {})
            tech = atomic.get("technique", "")
            if not tech:
                continue
            total_count[tech] += 1
            det = run.get("detection") or {}
            if det.get("fired") and not det.get("timeout_reached"):
                pass_count[tech] += 1
                samples[tech].append(float(det.get("latency_sec", 0.0)))

    return {
        tech: TechniqueStats(
            technique=tech,
            samples=samples[tech],
            pass_count=pass_count[tech],
            total_count=total_count[tech],
        )
        for tech in total_count
    }


# --------------------------------------------------------------------------
# SVG rendering
# --------------------------------------------------------------------------

CHART_WIDTH = 720
ROW_HEIGHT = 36
ROW_PAD = 8
LEFT_PAD = 140  # space for technique label
RIGHT_PAD = 60  # space for max value
TOP_PAD = 60
BOTTOM_PAD = 40
BAR_HEIGHT = 18
COLOR_P50 = "#6aa84f"
COLOR_P95 = "#f1c232"
COLOR_FAIL = "#cc0000"
COLOR_AXIS = "#cccccc"
COLOR_TEXT = "#333333"
FONT_FAMILY = "ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
SLA_SEC = 300  # 5 min — matches Phase 3 default


def render_svg(stats: dict[str, TechniqueStats], *, sla_sec: int = SLA_SEC) -> str:
    if not stats:
        return _empty_svg("No Phase 3 reports found yet — run a PR through detection validation.")

    # Sort by p50 descending so slowest detections appear at the top
    items = sorted(stats.values(), key=lambda s: -s.p50)
    rows = len(items)

    # Determine x-scale. Cap at SLA so a single timeout doesn't squish everything.
    max_val = max(
        max((s.p95 for s in items), default=0),
        sla_sec * 0.6,  # leave headroom even if all detections are fast
    )
    inner_width = CHART_WIDTH - LEFT_PAD - RIGHT_PAD

    def x(val: float) -> float:
        return LEFT_PAD + (val / max_val) * inner_width

    height = TOP_PAD + rows * (ROW_HEIGHT + ROW_PAD) + BOTTOM_PAD

    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {CHART_WIDTH} {int(height)}" '
        f'role="img" aria-label="Detection latency dashboard">'
    )
    parts.append(f'<style>text {{ font-family: {FONT_FAMILY}; fill: {COLOR_TEXT}; }}</style>')

    # Title
    parts.append(
        f'<text x="{LEFT_PAD}" y="24" font-size="16" font-weight="600">'
        f'Detection latency by technique</text>'
    )
    parts.append(
        f'<text x="{LEFT_PAD}" y="42" font-size="11" fill="#666">'
        f'Aggregated across {sum(s.total_count for s in items)} '
        f'detonation run(s) · SLA {sla_sec}s</text>'
    )

    # X-axis ticks
    tick_count = 5
    for i in range(tick_count + 1):
        val = (max_val * i) / tick_count
        tx = x(val)
        parts.append(
            f'<line x1="{tx:.1f}" y1="{TOP_PAD - 6}" x2="{tx:.1f}" '
            f'y2="{height - BOTTOM_PAD + 4}" stroke="{COLOR_AXIS}" stroke-width="0.5"/>'
        )
        parts.append(
            f'<text x="{tx:.1f}" y="{height - BOTTOM_PAD + 18}" font-size="10" '
            f'fill="#888" text-anchor="middle">{val:.0f}s</text>'
        )

    # SLA marker
    sla_x = x(min(sla_sec, max_val))
    parts.append(
        f'<line x1="{sla_x:.1f}" y1="{TOP_PAD - 6}" x2="{sla_x:.1f}" '
        f'y2="{height - BOTTOM_PAD + 4}" stroke="{COLOR_FAIL}" stroke-width="1" '
        f'stroke-dasharray="4 3"/>'
    )
    parts.append(
        f'<text x="{sla_x:.1f}" y="{TOP_PAD - 10}" font-size="10" fill="{COLOR_FAIL}" '
        f'text-anchor="middle">SLA {sla_sec}s</text>'
    )

    # Rows
    for i, s in enumerate(items):
        row_y = TOP_PAD + i * (ROW_HEIGHT + ROW_PAD)
        # Label
        parts.append(
            f'<text x="{LEFT_PAD - 8}" y="{row_y + ROW_HEIGHT/2 + 4:.0f}" '
            f'font-size="12" text-anchor="end" font-weight="500">{s.technique}</text>'
        )
        # Pass rate sublabel
        pr_pct = int(s.pass_rate * 100)
        pr_color = "#6aa84f" if pr_pct == 100 else ("#f1c232" if pr_pct >= 50 else COLOR_FAIL)
        parts.append(
            f'<text x="{LEFT_PAD - 8}" y="{row_y + ROW_HEIGHT/2 + 16:.0f}" '
            f'font-size="9" text-anchor="end" fill="{pr_color}">'
            f'{s.pass_count}/{s.total_count} fired</text>'
        )

        if s.p50 == 0:
            # All-failed row — render an "x"
            parts.append(
                f'<text x="{LEFT_PAD + 8}" y="{row_y + ROW_HEIGHT/2 + 4:.0f}" '
                f'font-size="11" fill="{COLOR_FAIL}">no successful detonations</text>'
            )
            continue

        # p95 bar (background)
        p95_w = max(2, x(s.p95) - LEFT_PAD)
        parts.append(
            f'<rect x="{LEFT_PAD}" y="{row_y + (ROW_HEIGHT - BAR_HEIGHT)/2:.0f}" '
            f'width="{p95_w:.1f}" height="{BAR_HEIGHT}" fill="{COLOR_P95}" rx="2"/>'
        )
        # p50 bar (foreground)
        p50_w = max(2, x(s.p50) - LEFT_PAD)
        parts.append(
            f'<rect x="{LEFT_PAD}" y="{row_y + (ROW_HEIGHT - BAR_HEIGHT)/2:.0f}" '
            f'width="{p50_w:.1f}" height="{BAR_HEIGHT}" fill="{COLOR_P50}" rx="2"/>'
        )
        # Value labels
        parts.append(
            f'<text x="{x(s.p95) + 6:.1f}" y="{row_y + ROW_HEIGHT/2 + 4:.0f}" '
            f'font-size="10" fill="#666">p50 {s.p50:.1f}s · p95 {s.p95:.1f}s</text>'
        )

    # Legend
    legend_y = height - 16
    parts.append(
        f'<rect x="{LEFT_PAD}" y="{legend_y - 8}" width="10" height="10" fill="{COLOR_P50}"/>'
        f'<text x="{LEFT_PAD + 14}" y="{legend_y}" font-size="10" fill="#666">p50 (median)</text>'
        f'<rect x="{LEFT_PAD + 100}" y="{legend_y - 8}" width="10" height="10" fill="{COLOR_P95}"/>'
        f'<text x="{LEFT_PAD + 114}" y="{legend_y}" font-size="10" fill="#666">p95 (worst)</text>'
    )
    parts.append("</svg>")
    return "\n".join(parts)


def _empty_svg(message: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {CHART_WIDTH} 120" '
        f'role="img" aria-label="Detection latency dashboard">'
        f'<style>text {{ font-family: {FONT_FAMILY}; fill: #888; }}</style>'
        f'<text x="{CHART_WIDTH/2}" y="40" font-size="14" font-weight="600" '
        f'text-anchor="middle">Detection latency by technique</text>'
        f'<text x="{CHART_WIDTH/2}" y="72" font-size="12" '
        f'text-anchor="middle">{message}</text>'
        f'</svg>'
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, required=True,
                        help="phase3-report.json file OR directory containing reports")
    parser.add_argument("--output", type=Path, default=Path("docs/coverage/latency.svg"))
    parser.add_argument("--sla-sec", type=int, default=SLA_SEC)
    args = parser.parse_args()

    reports = collect_reports(args.reports)
    stats = aggregate(reports)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    svg = render_svg(stats, sla_sec=args.sla_sec)
    args.output.write_text(svg, encoding="utf-8")
    print(f"Aggregated {len(reports)} report(s), {len(stats)} technique(s)")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
