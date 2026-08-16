"""Scanner abstraction. Every scanner adapter implements this contract so the
runner and the rest of the harness stay scanner-agnostic."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
from abc import ABC, abstractmethod
from typing import Callable

from ..models import Finding, ScanConfig, ScanOutcome, Target

OnFinding = Callable[[Finding], None]
OnWarning = Callable[[str], None]

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def stop_process_group(proc: subprocess.Popen, grace: float = 5.0) -> None:
    """Terminate a scanner and any children it spawned.

    The process must have been started with ``start_new_session=True`` so it
    leads its own group; we signal the whole group (SIGTERM, then SIGKILL after
    a grace period) so no child survives. Races with an already-exited process
    or a vanished group are swallowed.
    """
    if proc.poll() is not None:
        return
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError):
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, OSError):
        return
    try:
        proc.wait(timeout=grace)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass


def detect_version(argv: list[str], pattern: str, timeout: int = 20) -> str | None:
    """Run a version command and extract a version string, or None if unknown.

    Never raises: an unreadable/absent tool yields None so evidence records
    `null` rather than guessing.
    """
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    text = _ANSI.sub("", (proc.stdout or "") + (proc.stderr or ""))
    match = re.search(pattern, text)
    return match.group(1).strip() if match else None


class ScannerExecutionError(RuntimeError):
    """A scanner process failed and supplied a concrete exit code."""

    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


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
        on_warning: OnWarning | None = None,
    ) -> ScanOutcome:
        """Run a scan to completion (blocking).

        Invokes `on_finding` per normalized Finding and `on_warning` per
        non-fatal issue (a skipped output line) as they are produced. Returns a
        ScanOutcome describing exit code, output/parse state, and record counts
        so the runner can judge the final status and record completion evidence.
        `stop_event`, if set mid-run, requests early termination.
        """
