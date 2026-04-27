# Detection retirement workflow

When a detection is no longer useful — superseded by a better rule, fundamentally noisy, or detecting an obsolete technique — it gets **retired**, not deleted. Retirement preserves the rule file with documented context so future incident investigations can refer to it.

## When to retire a detection

A detection is a candidate for retirement when any of these is true:

- **Persistent FP rate above its budget.** Three consecutive nightly readings (see `docs/coverage/fp_history.jsonl`) at >2× budget without an obvious cause.
- **A better rule has replaced it.** Same technique, lower noise, more accurate.
- **The technique has fundamentally changed.** Adversaries have moved to a different procedure; this rule no longer matches real activity.
- **The platform/log source is gone.** Detection targets a log type the lab no longer ingests.
- **The rule has structural problems we can't tune.** Sometimes a rule's logic is wrong in a way that can't be fixed in place.

A detection is NOT a candidate for retirement just because:
- It hasn't fired recently (clean signal is good signal)
- It's older than other rules (age is not noise)
- It targets a technique you don't see in your environment (someone else might)

## How retirement works

The repo's `tools/retire_detection.py` automates the mechanics:

```bash
python tools/retire_detection.py <rule_id_or_path> --reason "<plain text reason>"
```

The script:

1. Locates the rule (by UUID or path)
2. Sets `status: deprecated` in the YAML
3. Adds `retired_at: <ISO timestamp>` and `retirement_reason: <text>`
4. Moves the file from `detections/<platform>/<tactic>/` to `detections/retired/<platform>/<tactic>/`
5. Prints the next-step git commands

Files under `detections/retired/` are excluded from:

- Sigma → SPL/EQL conversion (Phase 2)
- Live deployment to Splunk and Elastic (Phase 2)
- Phase 3 detonation testing
- The active-rules count in the coverage badge and Navigator layer

They ARE included in:

- The "Retired rules (audit log)" section of `docs/coverage/REPORT.md`
- Git history (forever)

## End-to-end example

A rule has been firing 12-15 times a night for two weeks; you've tried tuning twice without success. Time to retire.

```bash
# 1. Make sure you're up to date
git checkout main && git pull

# 2. Retire the rule
python tools/retire_detection.py 4d7e9c1a-2f83-4b56-a9e1-6c3d8f1b4e72 \
  --reason "Persistent FP rate >12/night for 14 consecutive readings; SCCM-wrapped scripts in this environment match too broadly. Replaced by T1059.001 v2 (id e8a3...) which excludes SCCM parent process by hash."

# 3. Branch + commit
git checkout -b retire/4d7e9c1a
git add detections/
git commit -m "chore(retire): PowerShell Encoded Command — Persistent FP, replaced by v2"

# 4. Push and open PR
git push -u origin retire/4d7e9c1a

# 5. Open PR via the GitHub UI or:
gh pr create --title "Retire: PowerShell Encoded Command (T1059.001 v1)" \
  --body "Retired due to persistent false-positive rate. Replaced by v2 with SCCM-aware filtering."
```

The PR description should include:

- Why this rule is being retired (link to FP history if applicable)
- What replaces it (if anything)
- What downstream consequences merging will have (deploys will stop pushing this rule on next merge to main)

## What happens after merge

On merge to `main`:

1. The next `deploy.yml` run will *not* convert or push this rule. The Splunk and Elastic deploy scripts walk `detections/` excluding `retired/`, so the rule simply stops being deployed.
2. The next `coverage.yml` run regenerates `docs/coverage/REPORT.md` with the rule listed under "Retired rules (audit log)".
3. The next `fp-tracking.yml` run will likely show this rule's name *missing* from the nightly reading (because it's no longer firing in production). That's expected.

The rule's last deployed instance in Splunk will remain until manually removed. To clean it up:

```bash
# In the lab Splunk:
# Settings → Searches, reports, and alerts → DaC - <rule name> → Delete
```

We don't currently auto-delete from the SIEM on retirement — that's a Phase 6 enhancement. The rationale: you might want the historical alert data to remain queryable for incident investigations.

## Reading the retirement audit trail

Anyone can read the audit trail without privileged access:

```bash
# All retired rules
ls detections/retired/

# Why a specific rule was retired
cat detections/retired/windows/execution/T1059.001_powershell_encoded_command.yml | head -20

# When it was retired
git log --follow detections/retired/windows/execution/T1059.001_powershell_encoded_command.yml
```

The `docs/coverage/REPORT.md` "Retired rules" table is the curated view. The git history is the full record.
