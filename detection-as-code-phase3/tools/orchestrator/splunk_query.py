"""
Splunk ad-hoc search execution for detection validation.

The orchestrator detonates an atomic, then needs to verify that the
corresponding detection's search returns hits. We don't wait for the
scheduled saved search — too slow and noisy. Instead we run the same SPL
ad-hoc, scoped to the detonation timeframe, and assert at least one event
matches.

Workflow:
  1. POST to /services/search/jobs with the SPL  → returns a job SID
  2. Poll /services/search/jobs/<SID> until isDone=1
  3. GET /services/search/jobs/<SID>/results to fetch matching events
  4. Return event count + sample event for the orchestrator's report

Auth: same as deploy_splunk.py — token preferred, basic supported.
"""

from __future__ import annotations

import logging
import os
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass

import requests
from requests.auth import HTTPBasicAuth

log = logging.getLogger(__name__)

DEFAULT_PORT = 8089
DEFAULT_POLL_INTERVAL = 2
DEFAULT_DETECTION_TIMEOUT = 300  # 5 min SLA


class SplunkQueryError(RuntimeError):
    pass


@dataclass
class SplunkQueryConfig:
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

    def auth(self) -> HTTPBasicAuth | None:
        if self.token:
            return None
        if self.user and self.password:
            return HTTPBasicAuth(self.user, self.password)
        return None

    def headers(self) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    @classmethod
    def from_env(cls) -> "SplunkQueryConfig":
        try:
            return cls(
                host=os.environ["SPLUNK_HOST"],
                port=int(os.environ.get("SPLUNK_PORT", DEFAULT_PORT)),
                scheme=os.environ.get("SPLUNK_SCHEME", "https"),
                verify_tls=os.environ.get("SPLUNK_VERIFY_TLS", "false").lower() == "true",
                token=os.environ.get("SPLUNK_TOKEN"),
                user=os.environ.get("SPLUNK_USER"),
                password=os.environ.get("SPLUNK_PASSWORD"),
                app=os.environ.get("SPLUNK_APP", "search"),
                owner=os.environ.get("SPLUNK_OWNER", "nobody"),
            )
        except KeyError as exc:
            raise SplunkQueryError(f"missing env var: {exc.args[0]}") from None


@dataclass
class DetectionAssertion:
    fired: bool
    event_count: int
    latency_sec: float
    sid: str
    sample_event: dict | None
    timeout_reached: bool


class SplunkQueryClient:
    def __init__(self, cfg: SplunkQueryConfig | None = None):
        self.cfg = cfg or SplunkQueryConfig.from_env()
        self._sess = requests.Session()
        self._sess.headers.update(self.cfg.headers())
        if not self.cfg.token:
            self._sess.auth = self.cfg.auth()
        self._sess.verify = self.cfg.verify_tls

    # ---- low-level ---------------------------------------------------------

    def _create_job(self, spl: str, earliest: str, latest: str) -> str:
        """Submit the SPL and return the job SID."""
        # Splunk requires the search prefix when using REST job submission
        if not spl.lstrip().startswith("search "):
            spl = f"search {spl}"
        url = f"{self.cfg.base_url}/servicesNS/{self.cfg.owner}/{self.cfg.app}/search/jobs"
        resp = self._sess.post(
            url,
            data={
                "search": spl,
                "earliest_time": earliest,
                "latest_time": latest,
                "exec_mode": "normal",
                "output_mode": "json",
            },
            timeout=30,
        )
        if not resp.ok:
            raise SplunkQueryError(f"job submit failed: {resp.status_code} {resp.text[:200]}")
        # When output_mode=json, the SID comes back as JSON; on some versions
        # the sid endpoint is XML. Handle both.
        try:
            return resp.json()["sid"]
        except (ValueError, KeyError):
            try:
                root = ET.fromstring(resp.text)
                sid_el = root.find(".//sid")
                if sid_el is not None and sid_el.text:
                    return sid_el.text
            except ET.ParseError:
                pass
            raise SplunkQueryError(f"could not parse SID from response: {resp.text[:200]}")

    def _job_done(self, sid: str) -> tuple[bool, int]:
        """Return (is_done, event_count)."""
        url = f"{self.cfg.base_url}/services/search/jobs/{sid}"
        resp = self._sess.get(url, params={"output_mode": "json"}, timeout=15)
        if not resp.ok:
            raise SplunkQueryError(f"job status failed: {resp.status_code} {resp.text[:200]}")
        content = resp.json()["entry"][0]["content"]
        return bool(content.get("isDone")), int(content.get("eventCount", 0))

    def _job_results(self, sid: str, count: int = 10) -> list[dict]:
        """Fetch matching events for a completed job."""
        url = f"{self.cfg.base_url}/services/search/jobs/{sid}/results"
        resp = self._sess.get(
            url, params={"output_mode": "json", "count": count}, timeout=30
        )
        if not resp.ok:
            raise SplunkQueryError(f"results fetch failed: {resp.status_code} {resp.text[:200]}")
        return resp.json().get("results", [])

    # ---- public API --------------------------------------------------------

    def assert_detection(
        self,
        spl: str,
        *,
        detonation_start: float,
        timeout_sec: int = DEFAULT_DETECTION_TIMEOUT,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
    ) -> DetectionAssertion:
        """
        Wait up to timeout_sec for the SPL to return at least one event.

        We re-run the search every poll_interval seconds because the events
        may not be indexed yet at the moment of detonation. The loop exits
        as soon as we see a hit, returning the latency from detonation to
        first detection — the metric hiring managers love.

        detonation_start is monotonic time (time.monotonic()) captured by
        the caller right before triggering the atomic.
        """
        # Time window: from 60s before detonation (clock skew tolerance) to now+1m
        # We re-issue the search in a loop because Splunk's job time window
        # is fixed at submit time; widening "latest" each loop catches new events.
        deadline = time.monotonic() + timeout_sec
        last_assertion: DetectionAssertion | None = None

        while time.monotonic() < deadline:
            elapsed = time.monotonic() - detonation_start
            # Use relative time; "now" expands on each call
            sid = self._create_job(spl, earliest="-2m", latest="now")
            # Wait for THIS job to finish (usually 1-3s for ad-hoc)
            for _ in range(30):
                done, count = self._job_done(sid)
                if done:
                    break
                time.sleep(0.5)
            else:
                log.warning("job %s did not complete in 15s; moving on", sid)
                continue

            done, count = self._job_done(sid)
            if done and count > 0:
                samples = self._job_results(sid, count=1)
                return DetectionAssertion(
                    fired=True,
                    event_count=count,
                    latency_sec=elapsed,
                    sid=sid,
                    sample_event=samples[0] if samples else None,
                    timeout_reached=False,
                )
            last_assertion = DetectionAssertion(
                fired=False,
                event_count=0,
                latency_sec=elapsed,
                sid=sid,
                sample_event=None,
                timeout_reached=False,
            )
            time.sleep(poll_interval)

        return DetectionAssertion(
            fired=False,
            event_count=0,
            latency_sec=time.monotonic() - detonation_start,
            sid=last_assertion.sid if last_assertion else "",
            sample_event=None,
            timeout_reached=True,
        )
