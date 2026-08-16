"""Scanner abstraction. Every scanner adapter implements this contract so the
runner and the rest of the harness stay scanner-agnostic."""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from typing import Callable

from ..models import Finding, ScanConfig, Target

OnFinding = Callable[[Finding], None]


class Scanner(ABC):
    name: str

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the underlying tool is installed and runnable."""

    @abstractmethod
    def run(
        self,
        target: Target,
        config: ScanConfig,
        on_finding: OnFinding,
        stop_event: threading.Event | None = None,
    ) -> int:
        """Run a scan to completion (blocking).

        Invokes `on_finding` for each normalized Finding as it is produced, so
        callers can observe results while the scan is still running. Returns the
        process exit code. `stop_event`, if set mid-run, requests early
        termination.
        """
