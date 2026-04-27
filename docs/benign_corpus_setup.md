# Benign telemetry corpus

The backtest workflow needs a "known-benign" Splunk time window to query each rule's converted SPL against. A rule that fires more than its FP budget on this window will produce false positives in production — block the PR until it's tuned.

This document explains how the corpus is captured and configured.

## Why a benign corpus matters

Detection engineering at scale lives or dies on FP rates. A rule that catches the technique 100% of the time but also fires on benign administrative activity 50 times a week creates alert fatigue, drowns real signal, and gets disabled by tier-1 analysts within a month.

Backtesting against benign telemetry catches this *before* the rule reaches production. It's the same pattern modern SOCs follow internally: rule → atomic test (must fire) → benign backtest (must not fire) → deploy.

## What "benign" means here

A continuous time window in the lab Splunk where:

1. **No atomic detonations were running.** Phase 3 detonations should be excluded by setting `BACKTEST_LATEST` to before the most recent Phase 3 run window.
2. **No active red-team work was happening.** Self-discipline; mark a "benign capture" period in your calendar and don't do offensive lab work during it.
3. **Realistic background activity is occurring.** Logged-in users, scheduled tasks, software updates, automation. The point is to surface rules that fire on legitimate noise.

## How the lab captures it

The simplest approach: just designate a 30-day window with no atomic activity and use it directly. No special capture process needed — Splunk already has the data.

The orchestrator's default `BACKTEST_EARLIEST=-30d` and `BACKTEST_LATEST=-1d` does this implicitly: query the last 30 days excluding the last 24 hours. If you've been running atomics in CI, the last-24h exclusion handles the most recent runs; for older runs, either widen the exclusion window or capture a known-clean stretch separately.

### Marking a clean capture window

For the cleanest backtest results, capture a deliberate 7-14 day window where:

```
1. Pause the test-detections.yml workflow:
   GitHub → Actions → Test Detections → ⋯ → Disable workflow

2. Note the start time. Let normal lab activity run.

3. After 7-14 days, note the end time. Re-enable the workflow.

4. Configure backtest to use that window:
   In .github/workflows/backtest.yml, set:
     BACKTEST_EARLIEST: '@d-14d'   (or your specific earliest)
     BACKTEST_LATEST:   '@d-1d'    (or your specific latest)

   Or use Splunk's epoch format for absolute times:
     BACKTEST_EARLIEST: '03/01/2026:00:00:00'
     BACKTEST_LATEST:   '03/15/2026:00:00:00'
```

A rolling window (`-30d → -1d`) is fine for ongoing use; a fixed window is more rigorous when you're publishing benchmark numbers.

## Per-rule FP budgets

By default, every rule must fire **0 times** on the benign window — anything else fails the backtest. Some rules legitimately catch rare benign events. For those, declare a budget in the rule YAML:

```yaml
title: My Detection
id: ...
status: experimental
custom:
  fp_budget_per_30d: 5      # tolerate up to 5 fires on a 30-day benign window
description: |
  ...
```

Use this sparingly and document why. A budget of 5 means "we expect this to fire about 5 times a month on benign noise." If you can't justify the number in the rule's `falsepositives:` block, the budget is wrong.

## Public corpus fallback (optional)

For repos without a captured lab corpus, the Mordor Project (now SecurityDatasets) publishes ATT&CK-tagged datasets that include benign baseline subsets. You can ingest a benign subset into a separate Splunk index and point the backtest at it:

```
BACKTEST_EARLIEST: 0
BACKTEST_LATEST: now
# and prepend to the rule's SPL: index=mordor_benign
```

This is lower realism (curated, doesn't reflect your environment) but gives the backtest workflow something to chew on while you build a real corpus. Most users won't need this.

## How backtest results affect the PR

`tools/backtest.py` writes a JSON report with per-rule pass/fail. The CI workflow renders that as a sticky PR comment:

```
## ✅ Phase 5 — Backtest against benign corpus

3/4 rules passed. Window: `-30d` → `-1d`

| Rule                                     | Benign hits | Budget | Result |
|------------------------------------------|------------:|-------:|:------:|
| DaC - LSASS Memory Dump via Procdump     |           0 |      0 |   ✅   |
| DaC - PowerShell Encoded Command         |          12 |      0 |   ❌   |
| DaC - DCSync Domain Replication          |           0 |      0 |   ✅   |
| DaC - Suspicious Rundll32 Execution      |           0 |      0 |   ✅   |
```

Failing the backtest does not auto-revert anything — it blocks the PR. The author either:
- Tunes the rule (add filters, narrow selections)
- Declares a documented `fp_budget_per_30d` that justifies the noise
- Decides the rule is too noisy and abandons it

## Common gotchas

**Backtest passes locally but fails in CI.** The lab Splunk window probably includes traffic from a recent Phase 3 detonation. Widen the exclusion at the end of the window.

**Backtest takes >5 minutes.** A 30-day window with high-volume indexes is expensive. Either narrow the window or split the backtest into per-rule jobs (future enhancement).

**Rule fires zero times in the lab but you know it's noisy in production.** Your lab telemetry isn't realistic enough. Add more user activity, more software, more domain interaction — or accept that lab backtest is a floor not a ceiling.
