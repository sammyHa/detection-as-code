"""
Detonation orchestrator: snapshot → detonate → assert → revert → report.

This is the core of Phase 3. For each detection ID requested, it:

  1. Looks up the atomic test(s) in tests/atomics/atomic_mapping.yml
  2. Loads the converted SPL from build/splunk/<id>.conf
  3. Snapshots the victim VM via Proxmox API
  4. Verifies IART is installed on the victim
  5. Runs Invoke-AtomicTest -GetPrereqs (resolves missing tools)
  6. Captures detonation_start (monotonic time)
  7. Runs Invoke-AtomicTest (the actual detonation)
  8. Polls Splunk ad-hoc search until the detection fires (or timeout)
  9. Records pass/fail, latency, sample event
 10. Runs Invoke-AtomicTest -Cleanup
 11. Reverts VM to snapshot
 12. Deletes snapshot
 13. Writes JSON report consumed by the GitHub Actions step that posts it to the PR

Designed for failure: a hung WinRM, a Splunk timeout, or a snapshot revert
error must not leave the lab in a corrupted state. Every step is wrapped in
try/finally with cleanup that runs no matter what.
"""

from __future__ import annotations

import argparse
import configparser
import json
import logging
import os
import sys
import time
import uuid as uuidlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Local imports — added to path below if running standalone
sys.path.insert(0, str(Path(__file__).resolve().parent))
from proxmox_client import ProxmoxClient, ProxmoxError  # noqa: E402
from splunk_query import DetectionAssertion, SplunkQueryClient, SplunkQueryError  # noqa: E402
from winrm_executor import WinRMError, WinRMExecutor  # noqa: E402

log = logging.getLogger("orchestrator")


@dataclass
class AtomicTest:
    technique: str
    test_number: int
    test_name: str
    platform: str
    elevation: str
    expected_alert: str


@dataclass
class TestRun:
    detection_id: str
    detection_path: str
    atomic: AtomicTest
    started_at: str
    detonation_log: str = ""
    cleanup_log: str = ""
    snapshot_name: str = ""
    snapshot_created: bool = False
    detonated: bool = False
    cleaned: bool = False
    reverted: bool = False
    detection: dict[str, Any] | None = None
    error: str | None = None

    @property
    def passed(self) -> bool:
        return (
            self.detection is not None
            and self.detection.get("fired", False)
            and self.error is None
        )


@dataclass
class OrchestratorReport:
    started_at: str
    finished_at: str = ""
    runs: list[TestRun] = field(default_factory=list)
    victim_host: str = ""
    splunk_host: str = ""
    proxmox_host: str = ""
    victim_vmid: int = 0

    @property
    def total(self) -> int:
        return len(self.runs)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.runs if r.passed)

    @property
    def failed(self) -> int:
        return self.total - self.passed


def load_atomic_mapping(path: Path) -> dict[str, list[AtomicTest]]:
    """Return {detection_id: [AtomicTest, ...]} from the mapping file."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    out: dict[str, list[AtomicTest]] = {}
    for entry in raw:
        did = str(entry["detection_id"])
        atomics = []
        for a in entry.get("atomics", []):
            atomics.append(
                AtomicTest(
                    technique=a["technique"],
                    test_number=int(a["test_number"]),
                    test_name=a.get("test_name", ""),
                    platform=a.get("platform", "windows"),
                    elevation=a.get("elevation", "user"),
                    expected_alert=a.get("expected_alert", ""),
                )
            )
        out[did] = atomics
    return out


def load_detection_path_map(mapping_path: Path) -> dict[str, str]:
    """Return {detection_id: detection_path} for human-readable reporting."""
    raw = yaml.safe_load(mapping_path.read_text(encoding="utf-8")) or []
    return {str(e["detection_id"]): e.get("detection_path", "") for e in raw}


def load_spl_for_detection(detection_id: str, build_dir: Path) -> str:
    """Read the converted SPL from build/splunk/<id>.conf."""
    safe_id = detection_id.replace("-", "_")
    conf = build_dir / f"{safe_id}.conf"
    if not conf.exists():
        raise FileNotFoundError(f"converted SPL not found: {conf}")
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.read(conf, encoding="utf-8")
    for section in parser.sections():
        if parser.has_option(section, "search"):
            return parser.get(section, "search")
    raise ValueError(f"no 'search' field in {conf}")


def run_one(
    detection_id: str,
    detection_path: str,
    atomic: AtomicTest,
    spl: str,
    pve: ProxmoxClient,
    winrm_exec: WinRMExecutor,
    splunk: SplunkQueryClient,
    vmid: int,
    detection_timeout_sec: int,
) -> TestRun:
    """Execute one detection ↔ atomic round-trip."""
    snapshot_name = f"dac-{int(time.time())}-{uuidlib.uuid4().hex[:6]}"
    run = TestRun(
        detection_id=detection_id,
        detection_path=detection_path,
        atomic=atomic,
        started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        snapshot_name=snapshot_name,
    )

    try:
        # 1. Snapshot
        pve.snapshot(vmid, snapshot_name, description=f"DaC test for {detection_id}")
        run.snapshot_created = True

        # 2. Verify IART
        if not winrm_exec.check_iart_installed():
            raise WinRMError("Invoke-AtomicRedTeam module not found on victim")

        # 3. Prereqs (resolve any tool downloads — should be cached on the
        # pre-baked victim, but call this anyway for honesty)
        winrm_exec.run_atomic_test(atomic.technique, atomic.test_number, get_prereqs=True)

        # 4. Detonate. Capture monotonic time AT DETONATION, not before prereqs.
        detonation_start = time.monotonic()
        det_result = winrm_exec.run_atomic_test(
            atomic.technique, atomic.test_number, get_prereqs=False
        )
        run.detonated = True
        run.detonation_log = (det_result.stdout + det_result.stderr)[:4000]

        # 5. Assert detection
        try:
            assertion = splunk.assert_detection(
                spl,
                detonation_start=detonation_start,
                timeout_sec=detection_timeout_sec,
            )
            run.detection = asdict(assertion)
        except SplunkQueryError as exc:
            run.error = f"splunk query failed: {exc}"

        # 6. Cleanup the atomic (restore registry/files/etc the test created)
        try:
            cleanup_result = winrm_exec.run_atomic_test(
                atomic.technique, atomic.test_number, cleanup=True
            )
            run.cleaned = True
            run.cleanup_log = (cleanup_result.stdout + cleanup_result.stderr)[:2000]
        except WinRMError as exc:
            log.warning("atomic cleanup failed (will revert anyway): %s", exc)

    except (ProxmoxError, WinRMError, FileNotFoundError) as exc:
        run.error = f"{type(exc).__name__}: {exc}"
        log.exception("orchestrator error for %s", detection_id)
    finally:
        # 7. ALWAYS attempt revert + snapshot delete, even on error.
        # If snapshot was never created we skip, otherwise we try our best.
        if run.snapshot_created:
            try:
                pve.revert(vmid, snapshot_name)
                run.reverted = True
            except ProxmoxError as exc:
                # This is the worst-case: revert failed. The lab needs human
                # attention. Surface it loudly.
                rev_err = f"REVERT FAILED for {snapshot_name}: {exc}"
                log.error(rev_err)
                run.error = (run.error + " | " if run.error else "") + rev_err
            else:
                try:
                    pve.delete_snapshot(vmid, snapshot_name)
                except ProxmoxError as exc:
                    log.warning("snapshot delete failed (non-fatal): %s", exc)

    return run


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
    )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--detection-ids",
        type=str,
        required=True,
        help="JSON array of detection IDs (UUIDs) OR '-' to read from stdin",
    )
    parser.add_argument(
        "--mapping",
        type=Path,
        default=Path("tests/atomics/atomic_mapping.yml"),
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path("build/splunk"),
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("phase3-report.json"),
    )
    parser.add_argument(
        "--vmid",
        type=int,
        default=int(os.environ.get("VICTIM_VMID", "0")) or None,
        required=os.environ.get("VICTIM_VMID") is None,
        help="Proxmox VMID of the victim (or env VICTIM_VMID)",
    )
    parser.add_argument(
        "--detection-timeout",
        type=int,
        default=int(os.environ.get("DETECTION_TIMEOUT_SEC", "300")),
    )
    args = parser.parse_args()

    if args.detection_ids == "-":
        ids = json.loads(sys.stdin.read())
    else:
        ids = json.loads(args.detection_ids)
    if not isinstance(ids, list):
        print("ERROR: --detection-ids must be a JSON array", file=sys.stderr)
        return 2

    if not ids:
        log.info("no detections to test (empty input)")
        report = OrchestratorReport(started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        report.finished_at = report.started_at
        args.report.write_text(json.dumps(asdict(report), indent=2))
        return 0

    mapping = load_atomic_mapping(args.mapping)
    path_map = load_detection_path_map(args.mapping)

    pve = ProxmoxClient()
    winrm_exec = WinRMExecutor()
    splunk = SplunkQueryClient()

    report = OrchestratorReport(
        started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        victim_host=winrm_exec.cfg.host,
        splunk_host=splunk.cfg.host,
        proxmox_host=pve.cfg.host,
        victim_vmid=args.vmid,
    )

    for detection_id in ids:
        atomics = mapping.get(detection_id, [])
        if not atomics:
            log.warning("no atomic mapping for detection %s — skipping", detection_id)
            continue

        try:
            spl = load_spl_for_detection(detection_id, args.build_dir)
        except (FileNotFoundError, ValueError) as exc:
            log.error("could not load SPL for %s: %s", detection_id, exc)
            for atomic in atomics:
                report.runs.append(
                    TestRun(
                        detection_id=detection_id,
                        detection_path=path_map.get(detection_id, ""),
                        atomic=atomic,
                        started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        error=f"SPL load failed: {exc}",
                    )
                )
            continue

        for atomic in atomics:
            run = run_one(
                detection_id=detection_id,
                detection_path=path_map.get(detection_id, ""),
                atomic=atomic,
                spl=spl,
                pve=pve,
                winrm_exec=winrm_exec,
                splunk=splunk,
                vmid=args.vmid,
                detection_timeout_sec=args.detection_timeout,
            )
            report.runs.append(run)

    report.finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Custom JSON encoder for dataclass-of-dataclass nesting
    args.report.write_text(json.dumps(asdict(report), indent=2, default=str))
    log.info("report written to %s", args.report)
    log.info("Summary: %d total, %d passed, %d failed", report.total, report.passed, report.failed)

    return 0 if report.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
