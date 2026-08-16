"""Run several scanners against one target and expose a single, merged view.

Built on top of ScanRunner: each scanner gets its own runner, and a "scan" here
is a group of per-scanner sub-scans. Status/results/warnings are the same method
names as ScanRunner, so `build_report` and the reporters work unchanged.
"""

from __future__ import annotations

import threading
import uuid

from .models import Finding, ScanConfig, Target
from .runner import ScanRunner
from .safety import authorize_target
from .scanners.base import Scanner


class MultiScanRunner:
    def __init__(
        self, scanners: list[Scanner], allowlist: set[str] | None = None
    ) -> None:
        names = [s.name for s in scanners]
        if len(names) != len(set(names)):
            raise ValueError(f"scanner names must be unique, got {names}")
        self.allowlist = allowlist or set()
        self._runners: dict[str, ScanRunner] = {
            s.name: ScanRunner(s, self.allowlist) for s in scanners
        }
        self._groups: dict[str, dict[str, str]] = {}  # group_id -> {name: child_id}
        self._lock = threading.Lock()

    def start_scan(self, target: Target, config: ScanConfig | None = None) -> str:
        # Authorize once up front so no scanner launches for a bad target.
        authorize_target(target.url, self.allowlist)  # may raise

        group_id = uuid.uuid4().hex[:12]
        mapping = {
            name: runner.start_scan(target, config)
            for name, runner in self._runners.items()
        }
        with self._lock:
            self._groups[group_id] = mapping
        return group_id

    def _mapping(self, group_id: str) -> dict[str, str]:
        with self._lock:
            if group_id not in self._groups:
                raise KeyError(f"unknown scan_id {group_id!r}")
            return self._groups[group_id]

    def get_status(self, group_id: str) -> dict:
        mapping = self._mapping(group_id)
        per = {
            name: self._runners[name].get_status(child_id)
            for name, child_id in mapping.items()
        }
        statuses = [p["status"] for p in per.values()]
        if any(s in ("pending", "running") for s in statuses):
            overall = "running"
        elif any(s == "failed" for s in statuses):
            overall = "failed"
        elif any(s == "stopped" for s in statuses):
            overall = "stopped"
        else:
            overall = "completed"

        first = next(iter(per.values()))
        return {
            "scan_id": group_id,
            "target": first["target"],
            "status": overall,
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
        mapping = self._mapping(group_id)
        for name, child_id in mapping.items():
            self._runners[name].wait(child_id, timeout)
        return self.get_status(group_id)
