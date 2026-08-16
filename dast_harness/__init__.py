"""Minimal DAST harness around a single scanner (nuclei)."""

from .models import (
    CompletionEvidence,
    Finding,
    ScanConfig,
    ScanOutcome,
    ScanState,
    ScanStatus,
    Severity,
    Target,
)
from .reporters import ConsoleReporter, JSONReporter, Reporter, ScanReport, build_report
from .orchestrator import MultiScanRunner
from .runner import ScanRunner
from .safety import TargetNotAuthorizedError, authorize_target
from .scanners.base import ScannerExecutionError
from .scanners.nikto import NiktoScanner
from .scanners.nuclei import NucleiScanner

__all__ = [
    "Finding",
    "ScanConfig",
    "ScanOutcome",
    "CompletionEvidence",
    "ScanState",
    "ScanStatus",
    "Severity",
    "Target",
    "ScanRunner",
    "MultiScanRunner",
    "ScannerExecutionError",
    "NucleiScanner",
    "NiktoScanner",
    "authorize_target",
    "TargetNotAuthorizedError",
    "Reporter",
    "ScanReport",
    "build_report",
    "ConsoleReporter",
    "JSONReporter",
]
