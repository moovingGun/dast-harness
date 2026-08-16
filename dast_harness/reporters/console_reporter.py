"""Console reporter: a compact human-readable summary for the terminal."""

from __future__ import annotations

from .base import Reporter, ScanReport


class ConsoleReporter(Reporter):
    name = "console"

    def render(self, report: ScanReport) -> str:
        s = report.status
        status_line = f"Status : {s.get('status')}"
        if s.get("exit_code") is not None:
            status_line += f"  (exit={s['exit_code']})"
        lines = [f"Target : {s.get('target')}", status_line]

        # Per-scanner breakdown, if this is a multi-scanner report.
        scanners = s.get("scanners")
        if scanners:
            for name, st in scanners.items():
                lines.append(
                    f"  - {name}: {st.get('status')} "
                    f"({st.get('findings_count', 0)} findings)"
                )

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
