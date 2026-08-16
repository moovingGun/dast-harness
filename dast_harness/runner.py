"""Scan lifecycle orchestration: start a scan, poll its status, read results.

The runner is the only place scans are launched, and it enforces the safety
guardrail before any scanner process starts.
"""

from __future__ import annotations

import threading
import time
import uuid

from .models import (
    CompletionEvidence,
    Finding,
    ScanConfig,
    ScanOutcome,
    ScanState,
    ScanStatus,
    Target,
)
from .safety import authorize_target
from .scanners.base import Scanner


class ScanRunner:
    def __init__(self, scanner: Scanner, allowlist: set[str] | None = None) -> None:
        self.scanner = scanner
        self.allowlist = allowlist or set()
        self._scans: dict[str, ScanState] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._stop_events: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def start_scan(self, target: Target, config: ScanConfig | None = None) -> str:
        """Authorize the target, then launch the scan in the background.

        Raises TargetNotAuthorizedError (from safety) before anything runs if the
        target is not local or allowlisted.
        """
        config = config or ScanConfig()
        auth = authorize_target(target.url, self.allowlist)  # may raise

        scan_id = uuid.uuid4().hex[:12]
        state = ScanState(
            scan_id=scan_id,
            target=target,
            authorization_reason=auth.reason,
        )
        stop_event = threading.Event()
        with self._lock:
            self._scans[scan_id] = state
            self._stop_events[scan_id] = stop_event

        thread = threading.Thread(
            target=self._run, args=(state, config, stop_event), daemon=True
        )
        with self._lock:
            self._threads[scan_id] = thread
        thread.start()
        return scan_id

    @staticmethod
    def _status_from_outcome(
        outcome: ScanOutcome, stop_effective: bool
    ) -> ScanStatus:
        if stop_effective:
            return ScanStatus.STOPPED
        if outcome.fatal or (outcome.exit_code is not None and outcome.exit_code != 0):
            return ScanStatus.FAILED
        if outcome.invalid_records > 0:
            return ScanStatus.COMPLETED_WITH_WARNINGS
        return ScanStatus.COMPLETED

    def _run(
        self, state: ScanState, config: ScanConfig, stop_event: threading.Event
    ) -> None:
        state.mark_running(time.time())
        started_at = state.started_at
        run_error: str | None = None
        outcome: ScanOutcome | None = None
        try:
            outcome = self.scanner.run(
                state.target,
                config,
                state.add_finding,
                stop_event,
                state.add_warning,
            )
        except Exception as exc:  # noqa: BLE001 - record any scanner failure
            run_error = str(exc)

        finished_at = time.time()
        if outcome is None:
            # run() raised: still record what we can as fatal evidence.
            outcome = ScanOutcome(
                exit_code=None, output_present=False, output_parseable=False,
                fatal=True, error=run_error,
            )

        stop_effective = bool(outcome.stopped)
        status = self._status_from_outcome(outcome, stop_effective)
        evidence_error = outcome.error or run_error
        if status == ScanStatus.FAILED and not evidence_error:
            if outcome.exit_code not in (0, None):
                evidence_error = (
                    f"{self.scanner.name} exited with code {outcome.exit_code}"
                )
            else:
                evidence_error = f"{self.scanner.name} failed"

        state.record_evidence(
            CompletionEvidence(
                scanner=self.scanner.name,
                scanner_version=outcome.scanner_version,
                started_at=started_at,
                finished_at=finished_at,
                exit_code=outcome.exit_code,
                stop_requested=state.stop_requested,
                stop_effective=stop_effective,
                output_present=outcome.output_present,
                output_parseable=outcome.output_parseable,
                parsed_records=outcome.parsed_records,
                invalid_records=outcome.invalid_records,
                warnings_count=len(state.warnings()),
                findings_count=len(state.findings()),
                config=config.snapshot(),
                template_version=outcome.template_version,
                error=evidence_error,
            )
        )
        state.mark_finished(
            status,
            finished_at,
            exit_code=outcome.exit_code,
            error=evidence_error if status == ScanStatus.FAILED else None,
        )

    def _get(self, scan_id: str) -> ScanState:
        with self._lock:
            if scan_id not in self._scans:
                raise KeyError(f"unknown scan_id {scan_id!r}")
            return self._scans[scan_id]

    def get_status(self, scan_id: str) -> dict:
        return self._get(scan_id).snapshot()

    def get_results(self, scan_id: str) -> list[Finding]:
        return self._get(scan_id).findings()

    def get_warnings(self, scan_id: str) -> list[str]:
        return self._get(scan_id).warnings()

    def stop_scan(self, scan_id: str) -> None:
        state = self._get(scan_id)
        with self._lock:
            event = self._stop_events.get(scan_id)
        if event is not None and state.is_active():
            # Only running scanners get the stop signal; finished ones are left
            # as-is so their COMPLETED status and results are preserved.
            state.mark_stop_requested()
            event.set()

    def wait(self, scan_id: str, timeout: float | None = None) -> dict:
        with self._lock:
            thread = self._threads.get(scan_id)
        if thread is not None:
            thread.join(timeout)
        return self.get_status(scan_id)

    def list_scans(self) -> list[dict]:
        with self._lock:
            states = list(self._scans.values())
        return [s.snapshot() for s in states]
