# Detection engineering process

The methodology this repo follows. Influenced by Palantir's [Alerting and Detection Strategies (ADS)](https://github.com/palantir/alerting-detection-strategy-framework) framework and the [Detection Engineering Maturity Matrix](https://detectionengineering.io/).

## Lifecycle

```
                    ┌─────────────┐
                    │  1. Identify │  Threat intel, red team report,
                    │   threat     │  ATT&CK gap analysis, incident
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ 2. Research  │  Map to ATT&CK technique(s),
                    │   technique  │  understand adversary procedures,
                    └──────┬───────┘  identify detectable artifacts
                           │
                    ┌──────▼───────┐
                    │ 3. Author    │  Write Sigma rule covering the
                    │   detection  │  observable, document FPs, level
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ 4. Test in   │  Detonate atomic in lab, confirm
                    │   isolation  │  alert fires, measure latency
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ 5. Backtest  │  Run rule against 30+ days of
                    │ for false-pos│  baseline telemetry, tune
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ 6. Deploy    │  Merge to main → CI pushes to
                    │   via CI     │  Splunk + Elastic
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ 7. Monitor & │  Track FP rate, MTTD, alert
                    │   maintain   │  fatigue; retire stale rules
                    └──────────────┘
```

## Quality gates

A detection cannot graduate to `stable` status until it has:

1. **Test coverage** — at least one atomic test that triggers it, mapped in `tests/atomics/atomic_mapping.yml`
2. **FP review** — 30 consecutive days of baseline lab telemetry with the rule deployed in alerting mode and a documented FP rate
3. **Runbook** — analyst-facing triage steps in the Sigma `description` and `falsepositives` fields
4. **ATT&CK mapping** — at least one specific sub-technique tag

## What this repo deliberately does *not* do

- **Vendor-specific rule formats as the source of truth.** Sigma is the source. SPL and EQL are build artifacts.
- **Detection by IOC list.** IOC blocking belongs in EDR/firewall, not in a behavioral detection library. Rules here target TTPs.
- **Coverage theater.** A rule that fires on every `powershell.exe -nop -w hidden` is not "PowerShell coverage" — it's a future false positive incident. Rules must target a *specific* adversary procedure.

## References

- [Palantir Alerting and Detection Strategy Framework](https://github.com/palantir/alerting-detection-strategy-framework)
- [Detection Engineering Maturity Matrix](https://detectionengineering.io/)
- [Florian Roth — How to Write Sigma Rules](https://www.nextron-systems.com/2018/02/10/write-sigma-rules/)
- [Red Canary — Detection Engineering at Red Canary](https://redcanary.com/blog/detection-engineering/)
