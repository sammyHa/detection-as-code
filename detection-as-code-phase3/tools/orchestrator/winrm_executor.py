"""
WinRM-based command execution against a Windows victim VM.

Runs Invoke-AtomicRedTeam (IART) commands remotely. Wraps pywinrm so the
orchestrator gets a clean async-like interface for atomic detonation.

The IART module must be pre-installed on the victim (see docs/victim_vm_setup.md).
This script does not bootstrap IART — bootstrapping in CI would slow each run
to multiple minutes. Pre-baking the victim image is the right design.

Environment variables:
  VICTIM_HOST       — fqdn or IP, e.g. 'win10-victim.deltacode.local'
  VICTIM_USER       — local admin or domain admin user, e.g. 'lab\\detonator'
  VICTIM_PASSWORD   — password (NOT secret-able well — prefer kerberos in prod)
  WINRM_TRANSPORT   — 'ntlm' (default) | 'kerberos' | 'ssl'
  WINRM_PORT        — 5985 (http) or 5986 (https). Default 5985.
  WINRM_VERIFY_TLS  — 'true' to verify, 'false' for self-signed lab certs
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

import winrm

log = logging.getLogger(__name__)

DEFAULT_HTTP_PORT = 5985
DEFAULT_HTTPS_PORT = 5986
COMMAND_TIMEOUT = 120  # IART tests usually run in <30s; allow headroom


class WinRMError(RuntimeError):
    """Raised when WinRM execution fails or returns a non-zero exit code we care about."""


@dataclass
class WinRMConfig:
    host: str
    user: str
    password: str
    transport: str
    port: int
    verify_tls: bool

    @property
    def endpoint(self) -> str:
        scheme = "https" if self.port == DEFAULT_HTTPS_PORT or self.transport == "ssl" else "http"
        return f"{scheme}://{self.host}:{self.port}/wsman"

    @classmethod
    def from_env(cls) -> "WinRMConfig":
        try:
            transport = os.environ.get("WINRM_TRANSPORT", "ntlm")
            default_port = DEFAULT_HTTPS_PORT if transport == "ssl" else DEFAULT_HTTP_PORT
            return cls(
                host=os.environ["VICTIM_HOST"],
                user=os.environ["VICTIM_USER"],
                password=os.environ["VICTIM_PASSWORD"],
                transport=transport,
                port=int(os.environ.get("WINRM_PORT", default_port)),
                verify_tls=os.environ.get("WINRM_VERIFY_TLS", "false").lower() == "true",
            )
        except KeyError as exc:
            raise WinRMError(f"missing required env var: {exc.args[0]}") from None


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_sec: float

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class WinRMExecutor:
    def __init__(self, cfg: WinRMConfig | None = None):
        self.cfg = cfg or WinRMConfig.from_env()
        self._session = winrm.Session(
            self.cfg.endpoint,
            auth=(self.cfg.user, self.cfg.password),
            transport=self.cfg.transport,
            server_cert_validation="validate" if self.cfg.verify_tls else "ignore",
            read_timeout_sec=COMMAND_TIMEOUT,
            operation_timeout_sec=COMMAND_TIMEOUT - 10,
        )

    def run_powershell(self, script: str) -> CommandResult:
        """
        Run a PowerShell script block on the victim. Returns CommandResult.
        Raises WinRMError only on transport failures, not on non-zero exit.
        Caller decides whether non-zero is acceptable (atomic prereq checks
        often exit non-zero deliberately).
        """
        start = time.monotonic()
        try:
            r = self._session.run_ps(script)
        except Exception as exc:  # noqa: BLE001 — pywinrm wraps many lower-level errors
            raise WinRMError(f"WinRM transport failure: {exc}") from exc
        duration = time.monotonic() - start
        return CommandResult(
            stdout=r.std_out.decode("utf-8", errors="replace"),
            stderr=r.std_err.decode("utf-8", errors="replace"),
            exit_code=r.status_code,
            duration_sec=duration,
        )

    # ---- IART convenience wrappers -----------------------------------------

    def check_iart_installed(self) -> bool:
        """Verify IART is importable on the victim before we waste time."""
        result = self.run_powershell(
            "if (Get-Module -ListAvailable -Name Invoke-AtomicRedTeam) "
            "{ Write-Output 'present' } else { Write-Output 'missing'; exit 1 }"
        )
        return result.ok and "present" in result.stdout

    def run_atomic_test(
        self,
        technique: str,
        test_number: int,
        *,
        get_prereqs: bool = True,
        cleanup: bool = False,
    ) -> CommandResult:
        """
        Execute a single Atomic Red Team test by technique + test number.

        IART numbers tests starting at 1, matching atomic_mapping.yml.
        We run prereqs first (auto-resolve missing tools), then the test itself.
        Cleanup is run as a separate call after detection assertion.
        """
        flags = []
        if get_prereqs:
            flags.append("-GetPrereqs")
        # IART runs the test by default; cleanup needs the explicit flag
        if cleanup:
            flags = ["-Cleanup"]

        flag_str = " ".join(flags)
        script = (
            "Import-Module Invoke-AtomicRedTeam -Force; "
            f"Invoke-AtomicTest {technique} -TestNumbers {test_number} {flag_str} "
            "-PathToAtomicsFolder C:\\AtomicRedTeam\\atomics "
            "-ExecutionLogPath C:\\AtomicRedTeam\\last-execution.log "
            "*>&1 | Out-String"
        )
        log.info(
            "executing atomic %s #%d on %s (prereqs=%s, cleanup=%s)",
            technique,
            test_number,
            self.cfg.host,
            get_prereqs,
            cleanup,
        )
        return self.run_powershell(script)
