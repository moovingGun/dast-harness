"""Console reporter: a compact human-readable summary for the terminal."""

from __future__ import annotations

from ..models import DEFAULT_CONFIDENCE, confidence_value
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
        # Per-agent breakdown. Coverage comes along because "0 findings" means
        # nothing without "out of how many, and did it finish".
        for name, st in (s.get("agents") or {}).items():
            line = (
                f"  - agent:{name}: {st.get('status')} "
                f"({st.get('findings_count', 0)} findings"
            )
            coverage = (st.get("result") or {}).get("coverage") or {}
            if coverage:
                line += (
                    f", {coverage.get('tested', 0)} "
                    f"{coverage.get('unit', 'unit')} tested"
                )
            lines.append(line + ")")
            # Which identities it ran as. "no findings" means something very
            # different logged in than logged out, so never leave it implicit.
            for who, auth in (st.get("auth") or {}).items():
                mark = "ok" if auth.get("ok") else f"FAILED — {auth.get('reason')}"
                lines.append(f"      as {who}: {mark}")

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
                # Severity says how bad it would be, so an unsure finding still
                # sorts high. Flagging only the unsure ones keeps scanner output
                # unchanged while telling a triager which ones need a human.
                conf = confidence_value(f)
                mark = "" if conf == DEFAULT_CONFIDENCE else f"  ({conf})"
                lines.append(
                    f"  [{f.severity.value:8}] {f.finding_id}  @ {f.matched_at}{mark}"
                )
        if s.get("error"):
            lines.append("")
            lines.append(f"Error  : {s['error']}")
        return "\n".join(lines)
