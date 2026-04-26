"""
Deploy converted Sigma rules to Splunk via the REST API.

Reads build/splunk/*.conf savedsearch stanzas and creates / updates
saved searches in the target Splunk instance. Idempotent: re-running
deploys is safe and only updates rules that have changed.

Auth: Splunk auth token via SPLUNK_TOKEN env var (preferred) or
HTTP Basic via SPLUNK_USER + SPLUNK_PASSWORD.

Usage:
    # Dry run — show what would be deployed without touching Splunk
    python tools/deploy_splunk.py --build-dir build/splunk --dry-run

    # Real deploy
    SPLUNK_HOST=splunk.deltacode.local \\
    SPLUNK_TOKEN=eyJ... \\
    python tools/deploy_splunk.py --build-dir build/splunk
"""

from __future__ import annotations

import argparse
import configparser
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth

DEFAULT_APP = "search"
DEFAULT_OWNER = "nobody"
TIMEOUT = 30


@dataclass
class SplunkConfig:
    host: str
    port: int
    scheme: str
    verify_tls: bool
    token: str | None
    user: str | None
    password: str | None
    app: str
    owner: str

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def auth(self) -> dict | HTTPBasicAuth | None:
        if self.token:
            return None  # token goes in headers
        if self.user and self.password:
            return HTTPBasicAuth(self.user, self.password)
        return None

    def headers(self) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h


def load_config(args: argparse.Namespace) -> SplunkConfig:
    return SplunkConfig(
        host=args.host or os.environ.get("SPLUNK_HOST", "localhost"),
        port=int(args.port or os.environ.get("SPLUNK_PORT", "8089")),
        scheme=os.environ.get("SPLUNK_SCHEME", "https"),
        verify_tls=os.environ.get("SPLUNK_VERIFY_TLS", "false").lower() == "true",
        token=os.environ.get("SPLUNK_TOKEN"),
        user=os.environ.get("SPLUNK_USER"),
        password=os.environ.get("SPLUNK_PASSWORD"),
        app=args.app,
        owner=args.owner,
    )


def parse_stanza(path: Path) -> tuple[str, dict[str, str]]:
    """Parse one .conf file and return (savedsearch_name, params_dict)."""
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    # configparser doesn't love stanza names with brackets/spaces by default,
    # but with raw read it handles standard Splunk conf format fine.
    parser.read(path, encoding="utf-8")
    sections = parser.sections()
    if len(sections) != 1:
        raise ValueError(f"{path} must contain exactly one stanza, got {len(sections)}")
    name = sections[0]
    params = {k: v for k, v in parser.items(name)}
    return name, params


def search_exists(cfg: SplunkConfig, name: str) -> bool:
    """Return True if the saved search already exists."""
    url = f"{cfg.base_url}/servicesNS/{cfg.owner}/{cfg.app}/saved/searches/{name}"
    resp = requests.get(
        url, headers=cfg.headers(), auth=cfg.auth(), verify=cfg.verify_tls, timeout=TIMEOUT
    )
    return resp.status_code == 200


def upsert_savedsearch(
    cfg: SplunkConfig, name: str, params: dict[str, str], dry_run: bool
) -> str:
    """
    Create or update a saved search. Returns 'created' | 'updated' | 'dry-run' | 'error'.
    """
    if dry_run:
        return "dry-run"

    base = f"{cfg.base_url}/servicesNS/{cfg.owner}/{cfg.app}/saved/searches"

    if search_exists(cfg, name):
        # Update — POST to the named endpoint with all updateable params
        # 'name' is not updateable on existing searches; strip it
        update_params = {k: v for k, v in params.items() if k != "name"}
        url = f"{base}/{name}"
        resp = requests.post(
            url,
            data=update_params,
            headers=cfg.headers(),
            auth=cfg.auth(),
            verify=cfg.verify_tls,
            timeout=TIMEOUT,
        )
        action = "updated"
    else:
        # Create — POST to the collection endpoint with name in body
        create_params = {"name": name, **params}
        resp = requests.post(
            base,
            data=create_params,
            headers=cfg.headers(),
            auth=cfg.auth(),
            verify=cfg.verify_tls,
            timeout=TIMEOUT,
        )
        action = "created"

    if not resp.ok:
        raise RuntimeError(f"Splunk API {resp.status_code}: {resp.text[:300]}")
    return action


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("build/splunk"))
    parser.add_argument("--host", help="Splunk host (else SPLUNK_HOST env)")
    parser.add_argument("--port", type=int, help="Splunk mgmt port (else SPLUNK_PORT env, default 8089)")
    parser.add_argument("--app", default=DEFAULT_APP, help="Splunk app context (default: search)")
    parser.add_argument("--owner", default=DEFAULT_OWNER, help="Owner namespace (default: nobody)")
    parser.add_argument("--dry-run", action="store_true", help="Don't call Splunk; print plan")
    args = parser.parse_args()

    if not args.build_dir.exists():
        print(f"ERROR: build dir {args.build_dir} not found. Run sigma_convert.py first.", file=sys.stderr)
        return 2

    cfg = load_config(args)
    if not args.dry_run and not (cfg.token or (cfg.user and cfg.password)):
        print("ERROR: need SPLUNK_TOKEN or SPLUNK_USER+SPLUNK_PASSWORD env vars", file=sys.stderr)
        return 2

    stanzas = sorted(args.build_dir.glob("*.conf"))
    if not stanzas:
        print(f"WARNING: no .conf files in {args.build_dir}")
        return 0

    print(f"Target: {cfg.base_url} (app={cfg.app}, owner={cfg.owner}) {'[DRY RUN]' if args.dry_run else ''}")
    print(f"Found {len(stanzas)} rule(s) to deploy")
    print()

    failures: list[tuple[Path, str]] = []
    for path in stanzas:
        try:
            name, params = parse_stanza(path)
            action = upsert_savedsearch(cfg, name, params, args.dry_run)
            print(f"  [{action.upper():>8}] {name}")
        except Exception as exc:  # noqa: BLE001
            print(f"  [   ERROR] {path.name}: {exc}", file=sys.stderr)
            failures.append((path, str(exc)))

    print()
    print(f"Deployed {len(stanzas) - len(failures)}/{len(stanzas)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
