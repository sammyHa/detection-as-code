# Self-hosted GitHub Actions runner (lab integration)

GitHub-hosted runners can't reach `deltacode.local`. Deployment jobs that target the lab Splunk and Elastic instances run on a **self-hosted runner** living inside the lab. This document covers how it's configured.

## Why self-hosted

Three options were considered:

| Approach | Verdict |
|---|---|
| Self-hosted runner in lab | **Chosen** — direct lab network access, no exposed endpoints, reusable for Phase 3 atomic detonation |
| GitHub-hosted + Tailscale tunnel | Works but adds dependency and complexity |
| Cloudflare Tunnel exposing Splunk/Elastic | Rejected — increases attack surface for marginal convenience |

## Topology

```
                  GitHub.com
                      │
                      │ (long-poll over HTTPS, outbound only)
                      ▼
    ┌─────────────────────────────────────────────┐
    │ deltacode.local — Proxmox host               │
    │                                              │
    │  ┌───────────────────────────────────────┐   │
    │  │ runner VM (Ubuntu 22.04, VLAN MGMT)   │   │
    │  │  - actions-runner installed as systemd│   │
    │  │  - python3.11, requests, pyyaml       │   │
    │  │  - non-root service account           │   │
    │  └───────────┬───────────────┬───────────┘   │
    │              │               │               │
    │              ▼               ▼               │
    │  ┌───────────────────┐  ┌──────────────────┐│
    │  │ splunk.deltacode  │  │ kibana.deltacode ││
    │  │   :8089 mgmt API  │  │   :5601 Kibana   ││
    │  └───────────────────┘  └──────────────────┘│
    └─────────────────────────────────────────────┘
```

Runner network is outbound-only to GitHub. No inbound ports are exposed.

## Setup

### 1. Provision the runner VM

Minimum spec: 2 vCPU, 2 GB RAM, 20 GB disk, Ubuntu 22.04 LTS. Place in a management VLAN that can reach Splunk's management port (8089) and Kibana (5601). No public internet ingress required.

### 2. Register the runner with GitHub

1. Repo → Settings → Actions → Runners → New self-hosted runner
2. Pick Linux x64. Follow the displayed download + token commands on the runner VM.
3. When prompted for labels, accept defaults (`self-hosted`, `linux`, `x64`).
4. Configure as a service so it survives reboots:
   ```bash
   sudo ./svc.sh install
   sudo ./svc.sh start
   ```

### 3. Configure GitHub repo secrets

Repo → Settings → Secrets and variables → Actions:

| Secret | Value |
|---|---|
| `SPLUNK_HOST` | `splunk.deltacode.local` |
| `SPLUNK_PORT` | `8089` |
| `SPLUNK_TOKEN` | Splunk auth token (Settings → Tokens in Splunk UI) |
| `KIBANA_URL` | `https://kibana.deltacode.local:5601` |
| `ELASTIC_API_KEY` | Elastic API key (Stack Management → Security → API keys) |

### 4. Create deployment environments

Repo → Settings → Environments. Create `lab-splunk` and `lab-elastic`. Optionally require manual approval for deploys (defense-in-depth — gives you a chance to reject a bad merge).

### 5. Verify with workflow_dispatch

Trigger `Deploy Detections` manually with `dry_run: true`. Confirm the deploy job picks up the self-hosted runner and that the dry-run output lists all four rules.

## Splunk auth token

Splunk → Settings → Tokens → New token. Owner: `admin` or a dedicated DaC service account. Audience: `dac-deploy`. No expiration in lab; in production set 90 days.

The deploy script accepts either a token (preferred) or HTTP Basic. Token is preferred because it doesn't require the password to be stored.

## Elastic API key

Kibana → Stack Management → Security → API keys → Create API key. Name: `dac-deploy`. Privileges:
```json
{
  "cluster": [],
  "index": [],
  "applications": [
    {
      "application": "kibana-.kibana",
      "privileges": ["feature_securitySolution.all"],
      "resources": ["space:default"]
    }
  ]
}
```

The encoded API key (returned after creation) goes in the `ELASTIC_API_KEY` secret.

## Hardening notes

- The runner VM should not have local admin credentials for Splunk or Elastic — only the API tokens scoped to the deploy permission.
- `actions-runner` runs as a non-root service account.
- The runner repo URL is restricted to `sammyHa/detection-as-code` (configured during registration).
- Consider snapshotting the runner VM after setup so a rebuild is one click away.
