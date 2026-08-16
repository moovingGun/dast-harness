"""Scan lifecycle orchestration: start a scan, poll its status, read results.

The runner is the only place scans are launched, and it enforces the safety
guardrail before any scanner process starts.
"""

from __future__ import annotations

import threading
import time
import uuid

from .models import ScanConfig, ScanState, ScanStatus, Target, Finding
from .safety import authorize_target
from .scanners.base import Scanner, ScannerExecutionError


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

    def _run(
        self, state: ScanState, config: ScanConfig, stop_event: threading.Event
    ) -> None:
        state.mark_running(time.time())
        code: int | None = None
        status = ScanStatus.FAILED
        error: str | None = None
        try:
            code = self.scanner.run(
                state.target, config, state.add_finding, stop_event
            )
            if stop_event.is_set():
                status = ScanStatus.STOPPED
                error = None
            elif code == 0:
                status = ScanStatus.COMPLETED
                error = None
            else:
                status = ScanStatus.FAILED
                error = f"{self.scanner.name} exited with code {code}"
        except Exception as exc:  # noqa: BLE001 - record any scanner failure
            if isinstance(exc, ScannerExecutionError):
                code = exc.exit_code
            if stop_event.is_set():
                status = ScanStatus.STOPPED
                error = None
            else:
                status = ScanStatus.FAILED
                error = str(exc)
        finally:
            state.mark_finished(
                status,
                time.time(),
                exit_code=code,
                error=error,
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

    def stop_scan(self, scan_id: str) -> None:
        state = self._get(scan_id)
        with self._lock:
            event = self._stop_events.get(scan_id)
        if event is not None and state.is_active():
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
