# Known issues and conversion gotchas

Real-world detection engineering means trusting your tools but verifying them. This page documents conversion behaviors and pipeline limitations that contributors should know about.

## pySigma Splunk backend: unparenthesized OR groups

**What happens:** When a Sigma rule has a condition like `(selection_a or selection_b) and selection_c`, the Splunk backend can emit:

```spl
A=x OR B=y C=z
```

instead of the safer:

```spl
(A=x OR B=y) C=z
```

**Why it matters:** Splunk gives implicit/explicit AND higher precedence than OR. The first form parses as `A=x OR (B=y AND C=z)`, which alerts on `A=x` alone — totally different semantics than the original Sigma rule, and a serious false-positive risk.

**How we handle it:**

1. `tools/spl_lint.py` runs in CI on every PR and flags the unsafe shape.
2. The PR author either restructures the Sigma condition to avoid the pattern (e.g. split into two separate rules) or hand-edits the converted SPL post-build.
3. Some Sigma logic is genuinely better expressed as multiple rules — the linter forces that conversation.

**When to override:** If the rule is a low-severity informational detection and the false-positive risk is acceptable, set `SPL_LINT_STRICT=0` (default) and the lint emits a warning without failing CI. For `high` and `critical` rules we recommend rewriting.

## pySigma Elasticsearch backend: live ATT&CK data fetch

The `pysigma-backend-elasticsearch` package fetches MITRE ATT&CK data from a remote URL at import time. This means:

- CI requires outbound network to the ATT&CK CDN
- Air-gapped builds need a local mirror or pre-cached `~/.cache/pysigma/` directory

In the lab self-hosted runner, this works because outbound HTTPS is allowed. For air-gapped use, mount a pre-fetched cache into the runner.

## Splunk savedsearch field interpolation

Sigma `description` fields are written verbatim into the saved search description. If you include characters like `|`, `=`, or backticks, Splunk's UI may render them oddly. The conversion script collapses whitespace but doesn't escape these characters — review the description after deploy.

## Elastic rule index patterns are hardcoded

`tools/sigma_convert.py` writes `index: ["winlogbeat-*", "logs-windows.*", "logs-system.*"]` for every Windows rule. If your lab uses different index patterns (e.g. `logs-endpoint.events.process-*` for Elastic Agent), edit the converter or override per-rule. Future improvement: per-rule index pattern via Sigma `custom.elastic.index` field.

## No automatic rollback

The deploy scripts are idempotent (re-run is safe) but don't track history. If a bad rule is deployed, the rollback procedure is:

1. `git revert` the offending commit
2. Push to `main`
3. The next deploy run will overwrite the bad rule with the previous version

For a "real" production deployment you'd want a separate undo workflow that snapshots the rule state before every change. This is on the Phase 5 roadmap.
