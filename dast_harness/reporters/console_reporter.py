"""Console reporter: a compact human-readable summary for the terminal."""

from __future__ import annotations

from .base import Reporter, ScanReport


class ConsoleReporter(Reporter):
    name = "console"

    def render(self, report: ScanReport) -> str:
        s = report.status
        lines = [
            f"Target : {s.get('target')}",
            f"Status : {s.get('status')}  (exit={s.get('exit_code')})",
        ]
        counts = report.severity_counts()
        summary = "  ".join(f"{sev}={n}" for sev, n in counts.items() if n)
        lines.append(
            f"Summary: {summary or 'no findings'}  "
            f"({len(report.findings)} findings, "
            f"{s.get('warnings_count', 0)} warnings)"
        )
        if report.findings:
            lines.append("")
            for f in report.sorted_findings():
                lines.append(f"  [{f.severity.value:8}] {f.finding_id}  @ {f.matched_at}")
        if s.get("error"):
            lines.append("")
            lines.append(f"Error  : {s['error']}")
        return "\n".join(lines)
