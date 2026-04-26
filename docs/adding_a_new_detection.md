# Adding a new detection

Step-by-step walkthrough for adding a new Sigma detection to this repo.

## 1. Pick a technique

Start with the ATT&CK technique you want to detect. Prefer sub-techniques over parent techniques — `T1003.001` (LSASS Memory) is more useful than `T1003` (OS Credential Dumping).

Find or create an [Atomic Red Team test](https://atomicredteam.io/) for the technique. If no atomic exists, you'll need to either contribute one upstream or write a custom detonation script — there is no detection without a way to test it.

## 2. Author the Sigma rule

Create a new YAML file under `detections/<platform>/<tactic>/`:

```
detections/windows/credential_access/T1003.001_lsass_dump_procdump.yml
```

Required fields (enforced by `tests/unit/test_sigma_structure.py`):

- `title` — human readable, technique-first
- `id` — generate a UUID4: `python -c "import uuid; print(uuid.uuid4())"`
- `status` — `experimental` for new rules, promote to `test` then `stable` over time
- `description` — what the adversary is doing, not what the rule matches
- `references` — ATT&CK page + atomic test, minimum
- `author` — your name
- `date` / `modified` — YYYY/MM/DD
- `tags` — at minimum, `attack.<tactic>` and `attack.t####`
- `logsource` — the platform/category/service the rule applies to
- `detection` — selection blocks and a `condition`
- `falsepositives` — be specific; "noise" is not an answer
- `level` — informational | low | medium | high | critical

## 3. Map to the atomic test

Add an entry to `tests/atomics/atomic_mapping.yml` linking your detection's UUID to the atomic test that should trigger it. Phase 3 CI uses this mapping to know what to detonate.

## 4. Validate locally

```bash
python tools/validate_sigma.py detections/
pytest tests/unit/ -v
```

Both must pass before pushing.

## 5. Open a PR

Branch naming: `detection/T<technique>-<short-descriptor>`

Example PR description:

```markdown
## Detection: T1003.001 LSASS Memory Dump via Procdump

### What this detects
Adversary use of Sysinternals procdump to dump LSASS process memory for credential extraction.

### Coverage
- ATT&CK: T1003.001 (Credential Access)
- Atomic test: T1003.001-1

### Validation
- [x] Sigma syntax validates locally
- [x] Unit tests pass
- [x] Manually detonated atomic in lab — alert fired in Splunk within 8s
- [x] False positive review: 0 hits in 30 days of normal lab telemetry
```

## 6. After merge

On merge to `main`, conversion and deployment workflows (Phase 2+) push the rule to Splunk and Elastic. The ATT&CK Navigator coverage layer is regenerated and committed back to the repo.
