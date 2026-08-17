import json
import unittest

from dast_harness import Finding, Severity
from dast_harness.agent_kit.contract import (AgentFinding, Confidence, Evidence,
                                             HttpExchange, Probe)
from dast_harness.reporters import ConsoleReporter, JSONReporter, ScanReport


def make_finding(severity: Severity, finding_id: str) -> Finding:
    return Finding(
        scanner="nuclei",
        finding_id=finding_id,
        name=finding_id,
        severity=severity,
        matched_at=f"http://127.0.0.1/{finding_id}",
    )


def make_agent_finding(confidence=Confidence.FIRM) -> AgentFinding:
    return AgentFinding(
        scanner="agent:idor",
        finding_id="idor-order-object-access",
        name="order API has no ownership check",
        severity=Severity.HIGH,
        matched_at="http://127.0.0.1:8080/api/orders/1002",
        confidence=confidence,
        category="idor",
        evidence=Evidence(
            baseline_index=0,
            rationale="alice read bob's order",
            exchanges=[
                HttpExchange(method="GET", url="http://127.0.0.1:8080/api/orders/1001",
                             status=200, actor="alice", note="baseline"),
                HttpExchange(method="GET", url="http://127.0.0.1:8080/api/orders/1002",
                             status=200, actor="alice",
                             request_headers={"Cookie": "session=secret"},
                             note="attack"),
            ],
        ),
        agent_data={"idor": Probe(strategy="sequential-id", target="id",
                                  target_kind="object-id", hits=["1002"])},
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


class AgentFindingReportingTest(unittest.TestCase):
    """Agent findings have to survive the reporters.

    The JSON reporter used to pick fields from a hand-kept whitelist, so
    confidence / category / evidence / agent_data were dropped from every
    report without raising. Agreeing on a contract and not wiring the reporter
    to it means the evidence never reaches whoever reads the report.
    """

    def _report(self, finding) -> ScanReport:
        return ScanReport(
            status={"target": "http://127.0.0.1:8080", "status": "completed",
                    "exit_code": 0, "error": None, "warnings_count": 0},
            findings=[finding],
            warnings=[],
        )

    def _rendered(self, finding, **kw) -> dict:
        data = json.loads(JSONReporter(**kw).render(self._report(finding)))
        return data["findings"][0]

    def test_v0_fields_reach_the_json_report(self) -> None:
        out = self._rendered(make_agent_finding())
        self.assertEqual(out["confidence"], "firm")
        self.assertEqual(out["category"], "idor")
        self.assertEqual(out["evidence"]["baseline_index"], 0)
        self.assertEqual(out["agent_data"]["idor"]["target_kind"], "object-id")

    def test_evidence_exchanges_are_serialized(self) -> None:
        out = self._rendered(make_agent_finding())
        actors = [e["actor"] for e in out["evidence"]["exchanges"]]
        self.assertEqual(actors, ["alice", "alice"])

    def test_credentials_stay_masked_in_the_report(self) -> None:
        # The report is a file that gets shared around; a live session cookie
        # must not ride along in it.
        rendered = JSONReporter().render(self._report(make_agent_finding()))
        self.assertNotIn("session=secret", rendered)
        self.assertIn("***", rendered)

    def test_scanner_findings_keep_their_shape(self) -> None:
        out = self._rendered(make_finding(Severity.LOW, "a"))
        self.assertEqual(out["confidence"], "confirmed")
        self.assertEqual(out["category"], "")
        self.assertNotIn("evidence", out)
        self.assertNotIn("agent_data", out)

    def test_raw_is_still_opt_in(self) -> None:
        f = make_finding(Severity.LOW, "a")
        f.raw = {"template-id": "x"}
        self.assertNotIn("raw", self._rendered(f))
        self.assertIn("raw", self._rendered(f, include_raw=True))

    def test_console_flags_unsure_findings(self) -> None:
        out = ConsoleReporter().render(self._report(make_agent_finding()))
        self.assertIn("(firm)", out)

    def test_console_does_not_annotate_confirmed_findings(self) -> None:
        # Scanner output must look exactly as it did before.
        out = ConsoleReporter().render(self._report(make_finding(Severity.LOW, "a")))
        self.assertNotIn("(confirmed)", out)


if __name__ == "__main__":
    unittest.main()
