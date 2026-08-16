import json
import unittest

from dast_harness import Finding, Severity
from dast_harness.reporters import ConsoleReporter, JSONReporter, ScanReport


def make_finding(severity: Severity, finding_id: str) -> Finding:
    return Finding(
        scanner="nuclei",
        finding_id=finding_id,
        name=finding_id,
        severity=severity,
        matched_at=f"http://127.0.0.1/{finding_id}",
    )


class ReporterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = ScanReport(
            status={
                "target": "http://127.0.0.1",
                "status": "completed",
                "exit_code": 0,
                "started_at": 1.0,
                "finished_at": 2.0,
                "error": None,
                "warnings_count": 1,
            },
            findings=[
                make_finding(Severity.LOW, "a"),
                make_finding(Severity.CRITICAL, "b"),
                make_finding(Severity.MEDIUM, "c"),
            ],
            warnings=["skipped a bad line"],
        )

    def test_json_reporter_structure(self) -> None:
        data = json.loads(JSONReporter().render(self.report))
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["findings_count"], 3)
        self.assertEqual(data["severity_counts"]["critical"], 1)
        self.assertEqual(data["severity_counts"]["high"], 0)
        self.assertEqual(data["warnings"], ["skipped a bad line"])

    def test_json_reporter_sorts_by_severity(self) -> None:
        data = json.loads(JSONReporter().render(self.report))
        ids = [f["id"] for f in data["findings"]]
        self.assertEqual(ids, ["b", "c", "a"])  # critical, medium, low

    def test_console_reporter_summary(self) -> None:
        out = ConsoleReporter().render(self.report)
        self.assertIn("127.0.0.1", out)
        self.assertIn("critical=1", out)
        self.assertIn("1 warnings", out)

    def test_console_reporter_handles_no_findings(self) -> None:
        empty = ScanReport(status=self.report.status, findings=[], warnings=[])
        out = ConsoleReporter().render(empty)
        self.assertIn("no findings", out)


if __name__ == "__main__":
    unittest.main()
