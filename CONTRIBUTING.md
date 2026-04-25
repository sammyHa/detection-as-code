# Contributing

This repo treats detections as code. Every change goes through the same workflow a mature SOC would use.

## Workflow

1. **Branch** from `main`: `git checkout -b detection/T1059.001-encoded-powershell`
2. **Add or modify** a Sigma rule under `detections/<platform>/<tactic>/`
3. **Add or reference** the matching Atomic Red Team test in `tests/atomics/`
4. **Run locally** before pushing:
   ```bash
   python tools/validate_sigma.py detections/
   pytest tests/unit/
   ```
5. **Open a pull request**. CI will run the same checks plus (Phase 3+) detonate the atomic in the lab and assert the alert fires.
6. **Merge** when CI is green. On merge to `main`, conversion and deployment workflows push the rule to Splunk and Elastic.

## Detection authoring standards

Every Sigma rule must:

- Have a unique UUID `id`
- Be tagged with at least one `attack.t####` technique (sub-techniques preferred where applicable)
- Document `falsepositives` in plain language an L1 analyst can act on
- Cite `references` — minimum: ATT&CK technique page and the Atomic Red Team test
- Include a meaningful `description` explaining *what the adversary is doing*, not just *what the rule matches*
- Set `level` honestly — `high`/`critical` should mean someone gets paged

## Naming conventions

- Files: `T<technique>_<short_descriptor>.yml` (e.g. `T1003.001_lsass_dump_procdump.yml`)
- Directory: `detections/<platform>/<tactic>/` where tactic is the lowercase ATT&CK tactic name with underscores
- Rule `title`: human readable, technique-first (e.g. "LSASS Memory Dump via Procdump")

## Code review checklist (for PR reviewers)

- [ ] Sigma syntax parses (CI enforces this)
- [ ] ATT&CK mapping is correct and uses the most specific sub-technique available
- [ ] False positives are documented and realistic
- [ ] Rule logic was tested against the corresponding atomic
- [ ] No hardcoded environment-specific values (hostnames, user names, paths)
