"""
Deploy converted Sigma rules to Elastic via the Detection Engine API.

Reads build/elastic/*.ndjson rule documents and creates / updates rules
in the target Elastic Security instance via the Kibana API. Idempotent:
uses the rule's `rule_id` for upsert semantics.

Auth: Elastic API key via ELASTIC_API_KEY env var.

Usage:
    # Dry run
    python tools/deploy_elastic.py --build-dir build/elastic --dry-run

    # Real deploy
    KIBANA_URL=https://kibana.deltacode.local:5601 \\
    ELASTIC_API_KEY=VnVhQ2... \\
    python tools/deploy_elastic.py --build-dir build/elastic
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import requests

TIMEOUT = 30


@dataclass
class ElasticConfig:
    kibana_url: str
    api_key: str | None
    verify_tls: bool
    space: str

    def headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "kbn-xsrf": "true",
            "Authorization": f"ApiKey {self.api_key}" if self.api_key else "",
        }

    def rules_url(self) -> str:
        space_path = "" if self.space == "default" else f"/s/{self.space}"
        return f"{self.kibana_url.rstrip('/')}{space_path}/api/detection_engine/rules"


def load_config(args: argparse.Namespace) -> ElasticConfig:
    return ElasticConfig(
        kibana_url=args.kibana_url or os.environ.get("KIBANA_URL", "http://localhost:5601"),
        api_key=os.environ.get("ELASTIC_API_KEY"),
        verify_tls=os.environ.get("ELASTIC_VERIFY_TLS", "false").lower() == "true",
        space=args.space,
    )


def rule_exists(cfg: ElasticConfig, rule_id: str) -> bool:
    """Check whether a rule with this rule_id already exists."""
    resp = requests.get(
        cfg.rules_url(),
        params={"rule_id": rule_id},
        headers=cfg.headers(),
        verify=cfg.verify_tls,
        timeout=TIMEOUT,
    )
    return resp.status_code == 200


def upsert_rule(cfg: ElasticConfig, rule_doc: dict, dry_run: bool) -> str:
    """Create or update a rule. Returns 'created' | 'updated' | 'dry-run'."""
    if dry_run:
        return "dry-run"

    rule_id = rule_doc["rule_id"]
    if rule_exists(cfg, rule_id):
        # Update — PUT to /rules with rule_id-bearing body
        resp = requests.put(
            cfg.rules_url(),
            data=json.dumps(rule_doc),
            headers=cfg.headers(),
            verify=cfg.verify_tls,
            timeout=TIMEOUT,
        )
        action = "updated"
    else:
        # Create — POST to /rules
        resp = requests.post(
            cfg.rules_url(),
            data=json.dumps(rule_doc),
            headers=cfg.headers(),
            verify=cfg.verify_tls,
            timeout=TIMEOUT,
        )
        action = "created"

    if not resp.ok:
        raise RuntimeError(f"Elastic API {resp.status_code}: {resp.text[:300]}")
    return action


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("build/elastic"))
    parser.add_argument("--kibana-url", help="Kibana base URL (else KIBANA_URL env)")
    parser.add_argument("--space", default="default", help="Kibana space (default: default)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.build_dir.exists():
        print(f"ERROR: build dir {args.build_dir} not found. Run sigma_convert.py first.", file=sys.stderr)
        return 2

    cfg = load_config(args)
    if not args.dry_run and not cfg.api_key:
        print("ERROR: ELASTIC_API_KEY env var required (unless --dry-run)", file=sys.stderr)
        return 2

    rules = sorted(args.build_dir.glob("*.ndjson"))
    if not rules:
        print(f"WARNING: no .ndjson files in {args.build_dir}")
        return 0

    print(f"Target: {cfg.kibana_url} (space={cfg.space}) {'[DRY RUN]' if args.dry_run else ''}")
    print(f"Found {len(rules)} rule(s) to deploy")
    print()

    failures: list[tuple[Path, str]] = []
    for path in rules:
        try:
            rule_doc = json.loads(path.read_text(encoding="utf-8"))
            action = upsert_rule(cfg, rule_doc, args.dry_run)
            print(f"  [{action.upper():>8}] {rule_doc['name']}")
        except Exception as exc:  # noqa: BLE001
            print(f"  [   ERROR] {path.name}: {exc}", file=sys.stderr)
            failures.append((path, str(exc)))

    print()
    print(f"Deployed {len(rules) - len(failures)}/{len(rules)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
