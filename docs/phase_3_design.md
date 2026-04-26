# Phase 3 — Continuous detection validation

This document explains the design of the Phase 3 detection validation pipeline. It's written for two audiences: contributors to this repo, and hiring managers reviewing the project.

## What it does

For every PR that adds or modifies a detection, the pipeline:

1. Identifies which detection rules changed
2. Looks up the corresponding Atomic Red Team test in `tests/atomics/atomic_mapping.yml`
3. Snapshots a dedicated Windows victim VM via the Proxmox API
4. Detonates the atomic on the victim using Invoke-AtomicRedTeam over WinRM
5. Polls Splunk via ad-hoc search until the detection fires (or hits a 5-minute SLA)
6. Runs the atomic's cleanup commands
7. Reverts the victim VM to the snapshot
8. Posts a pass/fail summary as a sticky comment on the PR with detection latency, event count, and any errors

A merge to `main` requires this workflow to pass. **A PR cannot ship a detection that doesn't actually fire against a real adversary technique on a real Windows host.**

## Why this design

### Why snapshot per test, not just per PR?

State pollution. A T1003.001 LSASS dump test leaves the dump file on disk and credentials in the attacker's hands. The next test would run against a poisoned baseline. Per-test snapshot/revert means every detection sees an identical clean victim — same as a tier-1 SOC's detection lab.

Snapshot revert with `vmstate=1` (RAM included) takes 30-60 seconds on this hardware. Acceptable for a CI run that tests the small number of changed detections.

### Why ad-hoc Splunk search instead of waiting for the scheduled saved search?

Two reasons:

**Determinism.** Scheduled searches run every 5 minutes. The race between detonation timestamp and next scheduled run introduces noise that has nothing to do with detection correctness. Ad-hoc execution against a fixed time window removes that noise — you're testing whether the SPL itself matches, not whether the scheduler happened to wake up.

**Latency measurement.** With ad-hoc, we measure the actual end-to-end latency from `detonation_start` (monotonic time) to first matching event. That's a metric you can quote in interviews: "median detection latency is 18 seconds across our coverage matrix." Schedulers obscure that signal entirely.

The trade-off: an ad-hoc search proves the SPL is correct, but doesn't prove the saved search is *also* correct. For the corner case where converted SPL doesn't match deployed SPL, Phase 5 will add a deployed-rule firing assertion as a follow-up step.

### Why orchestrator-as-runner instead of agent-on-victim?

The CI runner sits in MGMT VLAN. The victim sits in CORP-DETONATION VLAN. The runner reaches into the victim via WinRM but is otherwise air-gapped from the attack surface. That separation is non-negotiable: you do not run attack tooling on a CI host that has GitHub credentials.

### Why fail the PR if a detection doesn't fire?

The whole point. Most "detection libraries" on GitHub are untested SPL files. A green check mark on this PR means: *this detection actually catches the technique it claims to catch on a real Windows endpoint with realistic logging.*

That claim, with a CI badge to back it up, is the differentiator.

## Failure modes and recovery

The orchestrator is built around one principle: **never leave the lab in a corrupted state, even if everything else goes wrong.**

| Failure | Behavior |
|---|---|
| Snapshot creation fails | Test marked failed; nothing to revert; report shows `snapshot skipped` |
| WinRM transport error | Test marked failed; revert still runs; PR comment shows the error |
| Atomic detonation throws | Test marked failed; revert still runs; cleanup may not run, that's fine — revert wipes everything |
| Splunk query timeout | Test marked failed (`timeout_reached: true`); cleanup + revert still run |
| Atomic cleanup fails | Logged as warning, NOT a failure (revert handles it) |
| Snapshot revert fails | Test marked failed AND a loud `REVERT FAILED` is posted in the PR — this requires human attention |
| Snapshot delete fails | Logged as warning, NOT a failure (snapshots will accumulate, monitor disk) |

## What this signals to a hiring manager

When you point a hiring manager at this pipeline you're showing four things at once:

1. **Detection engineering as a software engineering discipline.** Sigma source, CI tests, deploys via pipeline. Same workflow as Elastic, Palantir, SpecterOps, and Red Canary.
2. **Real adversary emulation.** Atomic Red Team executed against real Windows victims, not synthetic test data.
3. **Production-grade failure handling.** The orchestrator handles every error path explicitly. No "happy path only" code.
4. **Infrastructure ownership.** Proxmox automation, VLAN-segmented detonation, self-hosted runners — all the parts a real SOC needs to maintain.

Each of those is a topic you can spend 15 minutes on in an interview. The pipeline gives you four interview chapters per repo visit.

## What it doesn't do (yet)

- **Backtest against historical telemetry.** Phase 5 will add a corpus of known-benign log data; rules must produce zero hits against it.
- **Track FP rate over time.** Phase 5 — once the pipeline has run for a month, we'll have data.
- **Validate Linux and macOS detections.** The orchestrator currently assumes Windows victims. Adding Linux is a Phase 6 item — different IART path, different snapshot mechanics, different log shipping.
- **Test with EDR present.** Defender is intentionally disabled to validate the *detection* layer in isolation. A separate workflow with Defender enabled would test detection-defense overlap.

## References and prior art

- Red Canary's Atomic Red Team — [`atomicredteam.io`](https://atomicredteam.io/)
- SpecterOps, *Capability Abstraction* — the conceptual model for testing detections at the technique level
- Elastic Security, *Detection rule continuous validation* — internal practice openly discussed in their detection engineering team's public talks
- Florian Roth (SigmaHQ), *How to Write Sigma Rules* — for the rule authorship discipline
