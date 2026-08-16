"""Reporting layer: turn a scan's results into an output format.

Reporters are output-only. They consume a `ScanReport` (status snapshot +
findings + warnings) and return a string; the caller decides where it goes
(stdout, a file, ...). Findings are already scanner-agnostic, so this layer does
not change when new scanners are added.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..models import Finding, Severity

# High-to-low, used for sorting findings and ordering summaries.
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.UNKNOWN: 5,
}


@dataclass
class ScanReport:
    """Everything a reporter needs, assembled from a scan."""

    status: dict
    findings: list[Finding]
    warnings: list[str]

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered most severe first."""
        return sorted(
            self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
        )

    def severity_counts(self) -> dict[str, int]:
        """Count of findings per severity, in severity order (zeros included)."""
        counts = {
            sev.value: 0
            for sev in sorted(SEVERITY_ORDER, key=lambda s: SEVERITY_ORDER[s])
        }
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts


class Reporter(ABC):
    name: str

    @abstractmethod
    def render(self, report: ScanReport) -> str:
        """Render the report to a string."""


def build_report(runner, scan_id: str) -> ScanReport:
    """Assemble a ScanReport from a runner's current view of a scan."""
    return ScanReport(
        status=runner.get_status(scan_id),
        findings=runner.get_results(scan_id),
        warnings=runner.get_warnings(scan_id),
    )
