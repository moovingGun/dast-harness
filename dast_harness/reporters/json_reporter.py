"""JSON reporter: machine-readable output for storage, diffing, or hand-off."""

from __future__ import annotations

import json

from ..models import Finding
from .base import Reporter, ScanReport


class JSONReporter(Reporter):
    name = "json"

    def __init__(self, indent: int | None = 2) -> None:
        self.indent = indent

    def render(self, report: ScanReport) -> str:
        s = report.status
        payload = {
            "target": s.get("target"),
            "status": s.get("status"),
            "started_at": s.get("started_at"),
            "finished_at": s.get("finished_at"),
            "exit_code": s.get("exit_code"),
            "error": s.get("error"),
            "severity_counts": report.severity_counts(),
            "findings_count": len(report.findings),
            "warnings_count": s.get("warnings_count", len(report.warnings)),
            "findings": [self._finding_dict(f) for f in report.sorted_findings()],
            "warnings": report.warnings,
        }
        return json.dumps(payload, indent=self.indent, ensure_ascii=False)

    @staticmethod
    def _finding_dict(f: Finding) -> dict:
        return {
            "scanner": f.scanner,
            "id": f.finding_id,
            "name": f.name,
            "severity": f.severity.value,
            "matched_at": f.matched_at,
            "description": f.description,
            "tags": f.tags,
        }
