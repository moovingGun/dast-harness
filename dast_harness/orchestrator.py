"""Run several scanners against one target and expose a single, merged view.

Built on top of ScanRunner: each scanner gets its own runner, and a "scan" here
is a group of per-scanner sub-scans. Status/results/warnings are the same method
names as ScanRunner, so `build_report` and the reporters work unchanged.
"""

from __future__ import annotations

import threading
import time
import uuid

from .models import Finding, ScanConfig, ScanStatus, Target
from .runner import ScanRunner
from .safety import authorize_target
from .scanners.base import Scanner

# One short, shared grace window for settling stopped scanners (cleanup and
# rollback). Shared, never multiplied per scanner.
_STOP_GRACE = 2.0


class MultiScanRunner:
    def __init__(
        self, scanners: list[Scanner], allowlist: set[str] | None = None
    ) -> None:
        if not scanners:
            raise ValueError("at least one scanner is required")
        names = [s.name for s in scanners]
        if len(names) != len(set(names)):
            raise ValueError(f"scanner names must be unique, got {names}")
        self.allowlist = allowlist or set()
        self._runners: dict[str, ScanRunner] = {
            s.name: ScanRunner(s, self.allowlist) for s in scanners
        }
        self._groups: dict[str, dict[str, str]] = {}  # group_id -> {name: child_id}
        self._timed_out: dict[str, bool] = {}  # group_id -> deadline was hit
        self._lock = threading.Lock()

    def start_scan(self, target: Target, config: ScanConfig | None = None) -> str:
        # Authorize once up front so no scanner launches for a bad target.
        authorize_target(target.url, self.allowlist)  # may raise

        group_id = uuid.uuid4().hex[:12]
        # Start children one at a time, tracking what we started, so a later
        # start failure can roll back the ones already running (no orphans).
        started: dict[str, str] = {}
        try:
            for name, runner in self._runners.items():
                started[name] = runner.start_scan(target, config)
        except Exception:
            self._stop_and_reap(started)
            raise
        with self._lock:
            self._groups[group_id] = started
        return group_id

    def _stop_and_reap(self, mapping: dict[str, str]) -> None:
        """Stop the given child scans and wait for them within one shared grace
        deadline (not per-child)."""
        for name, child_id in mapping.items():
            self._runners[name].stop_scan(child_id)
        deadline = time.monotonic() + _STOP_GRACE
        for name, child_id in mapping.items():
            remaining = max(0.0, deadline - time.monotonic())
            self._runners[name].wait(child_id, remaining)

    def _mapping(self, group_id: str) -> dict[str, str]:
        with self._lock:
            if group_id not in self._groups:
                raise KeyError(f"unknown scan_id {group_id!r}")
            return self._groups[group_id]

    @staticmethod
    def _rollup(statuses: list[str]) -> str:
        """Combine per-scanner statuses into one overall status.

        running                 : any scanner still active
        stopped                 : an effective user stop dominates
        completed               : every scanner completed cleanly
        completed_with_warnings : all succeeded, at least one had warnings
        partial                 : some succeeded, some failed (results exist)
        failed                  : none succeeded
        """
        succeeded = {
            ScanStatus.COMPLETED.value,
            ScanStatus.COMPLETED_WITH_WARNINGS.value,
        }
        active = {ScanStatus.PENDING.value, ScanStatus.RUNNING.value}
        if any(s in active for s in statuses):
            return ScanStatus.RUNNING.value
        if any(s == ScanStatus.STOPPED.value for s in statuses):
            return ScanStatus.STOPPED.value

        ok = [s for s in statuses if s in succeeded]
        if len(ok) == len(statuses):
            if any(s == ScanStatus.COMPLETED_WITH_WARNINGS.value for s in statuses):
                return ScanStatus.COMPLETED_WITH_WARNINGS.value
            return ScanStatus.COMPLETED.value
        if ok:
            return ScanStatus.PARTIAL.value
        return ScanStatus.FAILED.value

    def get_status(self, group_id: str) -> dict:
        mapping = self._mapping(group_id)
        per = {
            name: self._runners[name].get_status(child_id)
            for name, child_id in mapping.items()
        }
        overall = self._rollup([p["status"] for p in per.values()])
        clean = {
            ScanStatus.COMPLETED.value,
            ScanStatus.COMPLETED_WITH_WARNINGS.value,
        }
        results_partial = any(p["status"] not in clean for p in per.values())

        first = next(iter(per.values()))
        return {
            "scan_id": group_id,
            "target": first["target"],
            "status": overall,
            "results_partial": results_partial,
            "exit_code": None,  # not meaningful across multiple processes
            "findings_count": sum(p.get("findings_count", 0) for p in per.values()),
            "warnings_count": sum(p.get("warnings_count", 0) for p in per.values()),
            "scanners": per,
        }

    def get_results(self, group_id: str) -> list[Finding]:
        mapping = self._mapping(group_id)
        results: list[Finding] = []
        for name, child_id in mapping.items():
            results.extend(self._runners[name].get_results(child_id))
        return results

    def get_warnings(self, group_id: str) -> list[str]:
        mapping = self._mapping(group_id)
        warnings: list[str] = []
        for name, child_id in mapping.items():
            for w in self._runners[name].get_warnings(child_id):
                warnings.append(f"[{name}] {w}")
        return warnings

    def stop_scan(self, group_id: str) -> None:
        mapping = self._mapping(group_id)
        for name, child_id in mapping.items():
            self._runners[name].stop_scan(child_id)

    def wait(self, group_id: str, timeout: float | None = None) -> dict:
        """Wait for the group. `timeout` is a single deadline for the whole
        group, not a per-scanner budget. On deadline expiry with scanners still
        running, they are stopped so the group settles."""
        mapping = self._mapping(group_id)
        deadline = None if timeout is None else time.monotonic() + timeout
        for name, child_id in mapping.items():
            remaining = (
                None if deadline is None else max(0.0, deadline - time.monotonic())
            )
            self._runners[name].wait(child_id, remaining)

        # On deadline expiry, ask still-running scanners to stop and give them a
        # single shared grace window. Scanners that ignore the stop stay RUNNING
        # (honestly), rather than being falsely reported STOPPED.
        if (
            deadline is not None
            and self.get_status(group_id)["status"] == ScanStatus.RUNNING.value
        ):
            # Record that the deadline actually expired and we initiated a stop,
            # so callers don't have to infer timeout from the final status
            # (which may become 'completed' during the grace window).
            with self._lock:
                self._timed_out[group_id] = True
            self._stop_and_reap(mapping)
        return self.get_status(group_id)

    def timed_out(self, group_id: str) -> bool:
        """True if wait() hit the group deadline and initiated a stop."""
        self._mapping(group_id)  # KeyError if unknown
        with self._lock:
            return self._timed_out.get(group_id, False)
