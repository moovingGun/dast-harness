"""JSON reporter: machine-readable output for storage, diffing, or hand-off."""

from __future__ import annotations

import json

from ..models import Finding, finding_to_dict
from .base import Reporter, ScanReport

_CLEAN = {"completed", "completed_with_warnings"}


class JSONReporter(Reporter):
    name = "json"

    def __init__(self, indent: int | None = 2, include_raw: bool = False) -> None:
        # include_raw defaults to False: raw scanner output can be large and may
        # echo response bodies, so it is preserved internally on every Finding
        # but only emitted when the caller explicitly opts in.
        self.indent = indent
        self.include_raw = include_raw

    def render(self, report: ScanReport) -> str:
        s = report.status
        results_partial = s.get("results_partial", s.get("status") not in _CLEAN)
        payload = {
            "target": s.get("target"),
            "status": s.get("status"),
            "results_partial": results_partial,
            "started_at": s.get("started_at"),
            "finished_at": s.get("finished_at"),
            "exit_code": s.get("exit_code"),
            "error": s.get("error"),
            "severity_counts": report.severity_counts(),
            "findings_count": len(report.findings),
            "warnings_count": s.get("warnings_count", len(report.warnings)),
            "scanners": s.get("scanners"),  # per-scanner status/error/evidence
            # Per-agent status plus each agent's own deliverable: coverage,
            # completion, and recon's request_seeds — the hand-off input for the
            # injection/IDOR agents. Findings are not repeated here; they are in
            # "findings" like every other finding.
            "agents": s.get("agents"),
            "findings": [self._finding_dict(f) for f in report.sorted_findings()],
            "warnings": report.warnings,
        }
        return json.dumps(payload, indent=self.indent, ensure_ascii=False)

    def _finding_dict(self, f: Finding) -> dict:
        # Delegated so agent fields (confidence, category, evidence, agent_data)
        # cannot silently vanish here: this used to be a hand-kept whitelist and
        # it dropped every one of them without raising.
        return finding_to_dict(f, include_raw=self.include_raw)
