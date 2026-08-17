"""Core data models for the DAST harness."""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    UNKNOWN = "unknown"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_str(cls, value: str | None) -> "Severity":
        if not value:
            return cls.UNKNOWN
        try:
            return cls(value.strip().lower())
        except ValueError:
            return cls.UNKNOWN


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"
    # A scan that completed but had non-fatal parse warnings (usable results).
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    # Multi-scanner rollup only: some scanners completed, others did not.
    # A single scan never reaches this state.
    PARTIAL = "partial"


@dataclass(frozen=True)
class Target:
    """A scan target. `url` must include an http/https scheme."""

    url: str


@dataclass
class ScanConfig:
    """Minimal knobs passed through to the underlying scanner."""

    severities: list[Severity] = field(default_factory=list)  # empty = all
    tags: list[str] = field(default_factory=list)
    template_ids: list[str] = field(default_factory=list)
    rate_limit: int | None = None          # requests/sec, nuclei -rate-limit
    request_timeout: int | None = None     # per-request seconds, nuclei -timeout
    # OAST/interactsh coaxes the target into calling out to an external server.
    # Off by default to keep scans locally isolated; enable for blind/OOB checks.
    enable_interactsh: bool = False

    def __post_init__(self) -> None:
        if self.rate_limit is not None and self.rate_limit <= 0:
            raise ValueError("rate_limit must be greater than zero")
        if self.request_timeout is not None and self.request_timeout <= 0:
            raise ValueError("request_timeout must be greater than zero")

    def snapshot(self) -> dict[str, Any]:
        """A JSON-safe copy of this config, for completion evidence."""
        return {
            "severities": [s.value for s in self.severities],
            "tags": list(self.tags),
            "template_ids": list(self.template_ids),
            "rate_limit": self.rate_limit,
            "request_timeout": self.request_timeout,
            "enable_interactsh": self.enable_interactsh,
        }


@dataclass
class ScanOutcome:
    """What a scanner's run() reports back, beyond the findings it streamed.

    The runner turns this (plus stop state) into a per-scanner ScanStatus and a
    CompletionEvidence record. `fatal` forces FAILED regardless of exit code
    (e.g. a required output file was missing or unparseable).
    """

    exit_code: int | None
    output_present: bool
    output_parseable: bool
    parsed_records: int = 0
    invalid_records: int = 0
    fatal: bool = False
    stopped: bool = False
    scanner_version: str | None = None
    template_version: str | None = None
    error: str | None = None


@dataclass
class CompletionEvidence:
    """Per-scanner proof of what actually happened, recorded on the scan state."""

    scanner: str
    scanner_version: str | None
    started_at: float | None
    finished_at: float | None
    exit_code: int | None
    stop_requested: bool
    stop_effective: bool
    output_present: bool
    output_parseable: bool
    parsed_records: int
    invalid_records: int
    warnings_count: int
    findings_count: int
    config: dict
    template_version: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A single normalized result, scanner-agnostic."""

    scanner: str
    finding_id: str          # e.g. nuclei template-id
    name: str
    severity: Severity
    matched_at: str          # URL/location the finding was observed at
    description: str = ""
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanState:
    """Live, mutable state of one scan. Access is guarded by `_lock`."""

    scan_id: str
    target: Target
    status: ScanStatus = ScanStatus.PENDING
    started_at: float | None = None
    finished_at: float | None = None
    exit_code: int | None = None
    error: str | None = None
    authorization_reason: str = ""
    stop_requested: bool = False
    evidence: "CompletionEvidence | None" = None
    # Set when _run finishes. wait() blocks on this instead of thread.join(),
    # which a KeyboardInterrupt can corrupt into returning early.
    done: threading.Event = field(default_factory=threading.Event, repr=False)
    _findings: list[Finding] = field(default_factory=list)
    _warnings: list[str] = field(default_factory=list)
    _warnings_total: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add_finding(self, finding: Finding) -> None:
        with self._lock:
            self._findings.append(finding)

    def add_warning(self, message: str) -> None:
        """Record a non-fatal scanner warning. The stored sample is bounded; the
        total count is always exact."""
        with self._lock:
            self._warnings_total += 1
            if len(self._warnings) < 200:
                self._warnings.append(message)

    def mark_running(self, started_at: float) -> None:
        with self._lock:
            self.status = ScanStatus.RUNNING
            self.started_at = started_at

    def mark_finished(
        self,
        status: ScanStatus,
        finished_at: float,
        *,
        exit_code: int | None = None,
        error: str | None = None,
    ) -> None:
        if status in (ScanStatus.PENDING, ScanStatus.RUNNING):
            raise ValueError(f"{status.value!r} is not a terminal scan status")
        with self._lock:
            self.status = status
            self.finished_at = finished_at
            self.exit_code = exit_code
            self.error = error

    def is_active(self) -> bool:
        with self._lock:
            return self.status in (ScanStatus.PENDING, ScanStatus.RUNNING)

    def mark_stop_requested(self) -> None:
        with self._lock:
            self.stop_requested = True

    def record_evidence(self, evidence: "CompletionEvidence") -> None:
        with self._lock:
            self.evidence = evidence

    def findings(self) -> list[Finding]:
        """Return a snapshot copy so callers can poll safely mid-scan."""
        with self._lock:
            return list(self._findings)

    def warnings(self) -> list[str]:
        """Return a snapshot copy of the accumulated warning sample."""
        with self._lock:
            return list(self._warnings)

    def snapshot(self) -> dict[str, Any]:
        """Serializable status view for `get_status`."""
        with self._lock:
            return {
                "scan_id": self.scan_id,
                "target": self.target.url,
                "status": self.status.value,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "exit_code": self.exit_code,
                "error": self.error,
                "authorization_reason": self.authorization_reason,
                "findings_count": len(self._findings),
                "warnings_count": self._warnings_total,
                "stop_requested": self.stop_requested,
                "evidence": self.evidence.to_dict() if self.evidence else None,
            }
