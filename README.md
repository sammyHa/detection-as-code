# Detection-as-Code Pipeline

[![Validate Detections](https://github.com/sammyHa/detection-as-code/actions/workflows/validate.yml/badge.svg)](https://github.com/sammyHa/detection-as-code/actions/workflows/validate.yml)
[![Deploy Detections](https://github.com/sammyHa/detection-as-code/actions/workflows/deploy.yml/badge.svg)](https://github.com/sammyHa/detection-as-code/actions/workflows/deploy.yml)
[![Test Detections](https://github.com/sammyHa/detection-as-code/actions/workflows/test-detections.yml/badge.svg)](https://github.com/sammyHa/detection-as-code/actions/workflows/test-detections.yml)
[![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FsammyHa%2Fdetection-as-code%2Fmain%2Fdocs%2Fcoverage%2Fbadge.json)](docs/coverage/REPORT.md)
[![Sigma](https://img.shields.io/badge/format-Sigma-orange)](https://sigmahq.io/)
[![ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

A production-style detection engineering pipeline. Sigma rules live in source control, every PR is validated AND **continuously tested by detonating the corresponding Atomic Red Team test on a real Windows victim VM**, and merges to `main` deploy to Splunk Enterprise and Elastic Security via REST APIs — executed by a self-hosted GitHub Actions runner inside a private SOC lab.

## What makes this different

> **A PR cannot ship a detection that doesn't actually catch the technique it claims to catch.**

When a PR adds or modifies a Sigma rule, CI:
1. Snapshots a dedicated Windows victim VM via the Proxmox API
2. Detonates the matching Atomic Red Team test on the victim via WinRM
3. Polls Splunk via ad-hoc search until the detection fires
4. Asserts the alert appeared within a 5-minute SLA
5. Reverts the VM to a clean snapshot
6. Posts a sticky comment on the PR with pass/fail, latency, event count

Built and maintained by [Samim Hakimi](https://www.linkedin.com/in/) on an enterprise-grade home SOC lab (40-core Dell R740xd, Arista 10GbE backbone, Splunk + ELK + Wazuh + Velociraptor).

## Coverage

[![Coverage report](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FsammyHa%2Fdetection-as-code%2Fmain%2Fdocs%2Fcoverage%2Fbadge.json)](docs/coverage/REPORT.md) · See [`docs/coverage/REPORT.md`](docs/coverage/REPORT.md) for the full breakdown · Open [`docs/coverage/coverage_layer.json`](docs/coverage/coverage_layer.json) in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to see the heatmap.

## Detection latency

Aggregated from the last ~30 days of Phase 3 detonation runs. Updated nightly.

![Detection latency dashboard](docs/coverage/latency.svg)

## Architecture

```mermaid
flowchart TB
    A[PR opened] --> B{Validate}
    B --> B1[Sigma lint]
    B --> B2[Unit tests]
    B --> B3[Conversion smoke test]
    B --> B4[SPL precedence linter]

    A --> C{Test Detections}
    C --> C1[Identify changed detections]
    C1 --> C2[Convert to SPL]
    C2 --> D[Self-hosted runner]
    D --> D1[Snapshot victim VM via Proxmox]
    D1 --> D2[Run Atomic Red Team via WinRM]
    D2 --> D3[Poll Splunk for alert]
    D3 --> D4[Cleanup + revert VM]
    D4 --> D5[Post results to PR]

    A --> M[Merge to main]
    M --> N{Deploy}
    N --> N1[Convert Sigma]
    N1 --> N2[Splunk REST API]
    N1 --> N3[Elastic Detection Engine]

    M --> CV{Coverage}
    CV --> CV1[Regenerate Navigator layer]
    CV --> CV2[Regenerate latency dashboard]
    CV1 --> CV3[Commit back to repo]
    CV2 --> CV3
```

## Repo structure

| Path | Purpose |
|------|---------|
| `detections/` | Sigma rules organized by platform and ATT&CK tactic |
| `tests/atomics/` | Detection ↔ Atomic Red Team test mapping |
| `tests/unit/` | Pytest suites for Sigma syntax and orchestrator logic |
| `tools/sigma_convert.py` | Sigma → SPL + EQL conversion |
| `tools/spl_lint.py` | Catches Splunk operator-precedence bugs in converted output |
| `tools/deploy_splunk.py` | Idempotent Splunk REST API deploy |
| `tools/deploy_elastic.py` | Idempotent Elastic Detection Engine deploy |
| `tools/coverage_report.py` | Generates ATT&CK Navigator layer + REPORT.md + badge JSON |
| `tools/latency_dashboard.py` | Generates SVG latency dashboard from Phase 3 reports |
| `tools/orchestrator/` | Phase 3 detonation orchestrator |
| `.github/workflows/validate.yml` | PR validation pipeline |
| `.github/workflows/deploy.yml` | Merge-to-main deployment pipeline |
| `.github/workflows/test-detections.yml` | PR-triggered detonation pipeline |
| `.github/workflows/coverage.yml` | Coverage artifact regeneration |
| `docs/coverage/` | Auto-generated coverage artifacts (heatmap, report, badge, latency) |
| `docs/self_hosted_runner.md` | Lab runner integration setup |
| `docs/victim_vm_setup.md` | Windows victim VM build runbook |
| `docs/phase_3_design.md` | Detonation pipeline design rationale |
| `docs/known_issues.md` | Conversion gotchas and how the pipeline handles them |

## Quick start (local validation)

```bash
git clone https://github.com/sammyHa/detection-as-code.git
cd detection-as-code
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Validate every Sigma rule locally
python tools/validate_sigma.py detections/

# Run the unit test suite
pytest tests/unit/ -v

# Convert all rules to Splunk SPL + Elastic EQL
python tools/sigma_convert.py --source detections/ --output build/

# Regenerate coverage artifacts
python tools/coverage_report.py --source detections/ --output docs/coverage/
```

## Adding a detection

See [`docs/adding_a_new_detection.md`](docs/adding_a_new_detection.md). Short version: write Sigma → add an atomic mapping → open PR → CI detonates the atomic on a real Windows victim and asserts your detection fires → merge → pipeline deploys to lab Splunk and Elastic.

## Roadmap

- [x] **Phase 1 — Foundation:** Repo structure, Sigma validation in CI, first detections
- [x] **Phase 2 — Conversion & deploy:** pySigma → Splunk + Elastic, auto-deploy on merge, SPL precedence linter
- [x] **Phase 3 — Live testing:** Self-hosted runner detonates Atomic Red Team via WinRM, queries SIEM, asserts alerts fire, reverts victim VM via Proxmox API
- [x] **Phase 4 — Coverage reporting:** ATT&CK Navigator coverage layer, latency dashboard, badge, machine-generated coverage report
- [ ] **Phase 5 — Hardening:** Backtesting against benign telemetry corpus, false-positive tracking over time, detection retirement workflow

## Engineering decisions worth calling out

- **Sigma is the source of truth.** SPL and EQL are build artifacts, never hand-edited.
- **Self-hosted runner over tunneled exposure.** Lab APIs are never exposed to the internet. The runner only makes outbound long-poll connections to GitHub.
- **Per-test snapshot/revert via Proxmox API.** Every detonation gets a clean victim. No state pollution between tests.
- **Ad-hoc Splunk search for assertion.** Bypasses the 5-minute scheduler so we measure true detection latency, not scheduler delay.
- **Coverage and latency artifacts committed to the repo.** They're build outputs, but having them committed means a recruiter sees the heatmap and dashboard the moment they land on the page — no clicking through CI runs required.
- **SVG, not React.** Rendered inline in GitHub markdown. Visible in any RSS reader, any markdown viewer, any LinkedIn preview.

## License

MIT
