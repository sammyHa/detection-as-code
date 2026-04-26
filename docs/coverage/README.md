# Coverage

This directory contains auto-generated artifacts that summarize what this detection library covers and how well it's performing. **Do not edit by hand** — they're regenerated on every merge to `main` and on a nightly schedule.

## Contents

| File | Purpose |
|---|---|
| [`REPORT.md`](REPORT.md) | Human-readable coverage summary — totals, breakdowns by tactic and status, full technique list |
| [`coverage_layer.json`](coverage_layer.json) | ATT&CK Navigator layer file — open in Navigator to see the heatmap |
| [`badge.json`](badge.json) | Shields.io endpoint format used by the README badge |
| [`latency.svg`](latency.svg) | Detection latency dashboard, p50/p95 per technique, aggregated from Phase 3 runs |

## How to view the coverage heatmap

1. Go to the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
2. Click "Open Existing Layer" → "Upload from local"
3. Select [`coverage_layer.json`](coverage_layer.json)

The heatmap shades each covered technique by maturity score:

- **Dark green (100):** stable, battle-tested, ≥30 days FP review
- **Yellow (60):** under FP review
- **Light pink (30):** experimental, newly written

Multiple rules covering the same technique add additively, capped at 100.

## How the latency dashboard works

`latency.svg` is built from the last ~30 days of Phase 3 detonation reports. Each row shows one technique with two bars:

- **p50 (green):** median detection latency from detonation to first matching event
- **p95 (yellow):** worst-case detection latency, 95th percentile

The dashed red line is the configured detection SLA (default 5 min). Anything past it is a problem.

Pass-rate fractions under each technique label show how many detonation runs fired the detection within SLA over the aggregation window.

## Generating locally

```bash
# Coverage artifacts
python tools/coverage_report.py --source detections/ --output docs/coverage/

# Latency dashboard (requires Phase 3 reports)
python tools/latency_dashboard.py --reports path/to/reports/ --output docs/coverage/latency.svg
```
