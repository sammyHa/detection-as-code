"""
Proxmox VE REST API client for victim VM snapshot/revert lifecycle.

Used by the detonation orchestrator to ensure each Atomic Red Team test
runs against a clean victim VM. Workflow per detection test:

  1. snapshot(vmid, name) — capture pre-detonation state
  2. (test runs)
  3. revert(vmid, name)   — restore pre-detonation state
  4. delete_snapshot(vmid, name)

Auth uses an API token (preferred over root password). Create the token in
Proxmox UI: Datacenter → Permissions → API Tokens. Grant the token user
PVEAuditor + VM.Snapshot + VM.Snapshot.Rollback on the victim VM.

Environment variables:
  PROXMOX_HOST          — pve.deltacode.local
  PROXMOX_NODE          — name of the node hosting the VM (e.g. 'pve1')
  PROXMOX_TOKEN_USER    — e.g. 'dac-runner@pve!ci'
  PROXMOX_TOKEN_SECRET  — the token UUID secret
  PROXMOX_VERIFY_TLS    — 'true' to verify, 'false' for self-signed lab certs
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

import requests

log = logging.getLogger(__name__)

DEFAULT_PORT = 8006
DEFAULT_TIMEOUT = 30
TASK_POLL_INTERVAL = 2
TASK_POLL_TIMEOUT = 300  # 5 min — snapshot/revert can take a while with large RAM


class ProxmoxError(RuntimeError):
    """Raised when the Proxmox API returns a non-OK response or a task fails."""


@dataclass
class ProxmoxConfig:
    host: str
    port: int
    node: str
    token_user: str
    token_secret: str
    verify_tls: bool

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}/api2/json"

    def headers(self) -> dict[str, str]:
        # PVEAPIToken=<user>@<realm>!<tokenid>=<secret>
        return {"Authorization": f"PVEAPIToken={self.token_user}={self.token_secret}"}

    @classmethod
    def from_env(cls) -> "ProxmoxConfig":
        try:
            return cls(
                host=os.environ["PROXMOX_HOST"],
                port=int(os.environ.get("PROXMOX_PORT", DEFAULT_PORT)),
                node=os.environ["PROXMOX_NODE"],
                token_user=os.environ["PROXMOX_TOKEN_USER"],
                token_secret=os.environ["PROXMOX_TOKEN_SECRET"],
                verify_tls=os.environ.get("PROXMOX_VERIFY_TLS", "false").lower() == "true",
            )
        except KeyError as exc:
            raise ProxmoxError(f"missing required env var: {exc.args[0]}") from None


class ProxmoxClient:
    """
    Thin wrapper around the Proxmox VE REST API. Only implements the operations
    the orchestrator needs: snapshot, revert (rollback), delete snapshot, and
    VM status.
    """

    def __init__(self, cfg: ProxmoxConfig | None = None):
        self.cfg = cfg or ProxmoxConfig.from_env()
        self._sess = requests.Session()
        self._sess.headers.update(self.cfg.headers())
        self._sess.verify = self.cfg.verify_tls

    # ---- low-level ---------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self.cfg.base_url}{path}"

    def _request(self, method: str, path: str, **kwargs) -> dict:
        url = self._url(path)
        resp = self._sess.request(method, url, timeout=DEFAULT_TIMEOUT, **kwargs)
        if not resp.ok:
            raise ProxmoxError(f"{method} {path}: {resp.status_code} {resp.text[:200]}")
        return resp.json().get("data", {})

    def _wait_task(self, upid: str) -> None:
        """
        Snapshot/rollback are async. Proxmox returns a UPID; poll until done.
        Raises ProxmoxError if the task fails or times out.
        """
        deadline = time.time() + TASK_POLL_TIMEOUT
        path = f"/nodes/{self.cfg.node}/tasks/{upid}/status"
        while time.time() < deadline:
            data = self._request("GET", path)
            status = data.get("status")
            if status == "stopped":
                exit_status = data.get("exitstatus", "")
                if exit_status != "OK":
                    raise ProxmoxError(f"task {upid} failed: {exit_status}")
                return
            time.sleep(TASK_POLL_INTERVAL)
        raise ProxmoxError(f"task {upid} timed out after {TASK_POLL_TIMEOUT}s")

    # ---- public API --------------------------------------------------------

    def vm_status(self, vmid: int) -> dict:
        """Return the current status payload for a VM."""
        return self._request("GET", f"/nodes/{self.cfg.node}/qemu/{vmid}/status/current")

    def list_snapshots(self, vmid: int) -> list[dict]:
        """List existing snapshots on a VM."""
        return self._request("GET", f"/nodes/{self.cfg.node}/qemu/{vmid}/snapshot")

    def snapshot(self, vmid: int, name: str, description: str = "", *, vmstate: bool = True) -> None:
        """
        Create a snapshot of the VM. By default includes RAM (vmstate=1), so a
        revert restores the exact running state — much faster and more reliable
        than restarting the VM and waiting for boot.
        """
        log.info("snapshotting VM %d as %r (vmstate=%s)", vmid, name, vmstate)
        data = self._request(
            "POST",
            f"/nodes/{self.cfg.node}/qemu/{vmid}/snapshot",
            data={
                "snapname": name,
                "description": description or f"automated snapshot for DaC test",
                "vmstate": 1 if vmstate else 0,
            },
        )
        # Proxmox returns the UPID as the bare data string for this endpoint
        upid = data if isinstance(data, str) else data.get("upid", "")
        if upid:
            self._wait_task(upid)

    def revert(self, vmid: int, name: str) -> None:
        """Roll the VM back to the named snapshot. Blocks until rollback completes."""
        log.info("reverting VM %d to snapshot %r", vmid, name)
        data = self._request(
            "POST", f"/nodes/{self.cfg.node}/qemu/{vmid}/snapshot/{name}/rollback"
        )
        upid = data if isinstance(data, str) else data.get("upid", "")
        if upid:
            self._wait_task(upid)

    def delete_snapshot(self, vmid: int, name: str) -> None:
        """Delete a snapshot. Used after a successful test cycle to keep snapshot list tidy."""
        log.info("deleting snapshot %r on VM %d", name, vmid)
        data = self._request(
            "DELETE", f"/nodes/{self.cfg.node}/qemu/{vmid}/snapshot/{name}"
        )
        upid = data if isinstance(data, str) else data.get("upid", "")
        if upid:
            self._wait_task(upid)
