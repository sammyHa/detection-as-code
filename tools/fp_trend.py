"""
Render an SVG trend chart of false-positive rates per rule from
docs/coverage/fp_history.jsonl.

For each rule that has at least one nightly reading, plot a small
sparkline showing fire count over time. Rules are sorted by total fires
descending so the noisiest are visible first.

Same SVG-not-React rationale as the latency dashboard — has to render
inline in GitHub markdown.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RuleSeries:
    name: str
    points: list[tuple[str, int]]  # (collected_at, fires)

    @property
    def total(self) -> int:
        return sum(p[1] for p in self.points)

    @property
    def latest(self) -> int:
        return self.points[-1][1] if self.points else 0


# Visual constants
CHART_WIDTH = 720
ROW_HEIGHT = 40
ROW_PAD = 6
LEFT_PAD = 320  # rule names get more space than technique IDs
RIGHT_PAD = 60
TOP_PAD = 60
BOTTOM_PAD = 30
SPARK_HEIGHT = 24
COLOR_CLEAN = "#6aa84f"   # 0 fires recent — green
COLOR_NOISY = "#f1c232"   # some fires — yellow
COLOR_BAD = "#cc0000"     # many fires — red
COLOR_AXIS = "#cccccc"
COLOR_TEXT = "#333333"
FONT_FAMILY = "ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"


def load_history(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def aggregate(records: list[dict]) -> dict[str, RuleSeries]:
    """Convert nightly records into per-rule time series."""
    series: dict[str, list[tuple[str, int]]] = defaultdict(list)
    # Sort records chronologically
    records_sorted = sorted(records, key=lambda r: r.get("collected_at", ""))
    for record in records_sorted:
        ts = record.get("collected_at", "")
        for entry in record.get("rules", []):
            series[entry["name"]].append((ts, int(entry.get("fires", 0))))
    return {name: RuleSeries(name=name, points=points) for name, points in series.items()}


def color_for(latest: int) -> str:
    if latest == 0:
        return COLOR_CLEAN
    if latest <= 3:
        return COLOR_NOISY
    return COLOR_BAD


def render_svg(series: dict[str, RuleSeries]) -> str:
    if not series:
        return _empty_svg(
            "No FP history yet — the nightly fp-tracking workflow will populate this."
        )

    items = sorted(series.values(), key=lambda s: -s.total)
    rows = len(items)
    height = TOP_PAD + rows * (ROW_HEIGHT + ROW_PAD) + BOTTOM_PAD

    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {CHART_WIDTH} {int(height)}" '
        f'role="img" aria-label="False positive rate trend">'
    )
    parts.append(f'<style>text {{ font-family: {FONT_FAMILY}; fill: {COLOR_TEXT}; }}</style>')

    # Title
    parts.append(
        f'<text x="20" y="24" font-size="16" font-weight="600">False positive trend</text>'
    )
    total_records = max((len(s.points) for s in items), default=0)
    parts.append(
        f'<text x="20" y="42" font-size="11" fill="#666">'
        f'Per-rule fire counts over the last {total_records} nightly readings</text>'
    )

    spark_x_start = LEFT_PAD
    spark_width = CHART_WIDTH - LEFT_PAD - RIGHT_PAD

    # Determine global y-scale across all series, with a floor of 5 so even
    # zero-fire rules render with visible baseline.
    global_max = max((max((p[1] for p in s.points), default=0) for s in items), default=0)
    y_max = max(global_max, 5)

    for i, s in enumerate(items):
        row_y = TOP_PAD + i * (ROW_HEIGHT + ROW_PAD)
        spark_y = row_y + (ROW_HEIGHT - SPARK_HEIGHT) / 2

        # Truncate long names; full name in title attribute for hover
        display_name = s.name if len(s.name) <= 42 else (s.name[:39] + "…")
        parts.append(
            f'<text x="{LEFT_PAD - 12}" y="{row_y + ROW_HEIGHT/2 + 4:.0f}" '
            f'font-size="11" text-anchor="end" font-weight="500">'
            f'<title>{s.name}</title>{display_name}</text>'
        )

        if not s.points:
            continue

        # Sparkline
        n = len(s.points)
        if n == 1:
            # single point — render a dot
            x = spark_x_start + spark_width / 2
            y = spark_y + SPARK_HEIGHT / 2
            parts.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{color_for(s.latest)}"/>'
            )
        else:
            # baseline
            parts.append(
                f'<line x1="{spark_x_start}" y1="{spark_y + SPARK_HEIGHT:.1f}" '
                f'x2="{spark_x_start + spark_width}" y2="{spark_y + SPARK_HEIGHT:.1f}" '
                f'stroke="{COLOR_AXIS}" stroke-width="0.5"/>'
            )
            # line
            points_str = " ".join(
                f"{spark_x_start + (j / (n - 1)) * spark_width:.1f},"
                f"{spark_y + SPARK_HEIGHT - (val / y_max) * SPARK_HEIGHT:.1f}"
                for j, (_ts, val) in enumerate(s.points)
            )
            parts.append(
                f'<polyline points="{points_str}" fill="none" '
                f'stroke="{color_for(s.latest)}" stroke-width="1.5"/>'
            )
            # last point emphasized
            last_x = spark_x_start + spark_width
            last_val = s.points[-1][1]
            last_y = spark_y + SPARK_HEIGHT - (last_val / y_max) * SPARK_HEIGHT
            parts.append(
                f'<circle cx="{last_x:.1f}" cy="{last_y:.1f}" r="2.5" '
                f'fill="{color_for(s.latest)}"/>'
            )

        # Latest value label, right of sparkline
        parts.append(
            f'<text x="{spark_x_start + spark_width + 8}" y="{row_y + ROW_HEIGHT/2 + 4:.0f}" '
            f'font-size="11" fill="{color_for(s.latest)}" font-weight="600">'
            f'{s.latest}</text>'
        )
        parts.append(
            f'<text x="{spark_x_start + spark_width + 8}" y="{row_y + ROW_HEIGHT/2 + 16:.0f}" '
            f'font-size="9" fill="#888">total {s.total}</text>'
        )

    parts.append("</svg>")
    return "\n".join(parts)


def _empty_svg(message: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {CHART_WIDTH} 120" '
        f'role="img" aria-label="False positive rate trend">'
        f'<style>text {{ font-family: {FONT_FAMILY}; fill: #888; }}</style>'
        f'<text x="{CHART_WIDTH/2}" y="40" font-size="14" font-weight="600" '
        f'text-anchor="middle">False positive trend</text>'
        f'<text x="{CHART_WIDTH/2}" y="72" font-size="12" '
        f'text-anchor="middle">{message}</text>'
        f'</svg>'
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--history", type=Path, default=Path("docs/coverage/fp_history.jsonl"),
    )
    parser.add_argument(
        "--output", type=Path, default=Path("docs/coverage/fp_trend.svg"),
    )
    args = parser.parse_args()

    records = load_history(args.history)
    series = aggregate(records)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    svg = render_svg(series)
    args.output.write_text(svg, encoding="utf-8")
    print(f"Loaded {len(records)} record(s), {len(series)} rule(s)")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
