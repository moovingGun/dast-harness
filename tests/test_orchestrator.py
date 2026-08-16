import unittest

from dast_harness import (
    Finding,
    MultiScanRunner,
    ScanConfig,
    Severity,
    Target,
    build_report,
)
from dast_harness.safety import TargetNotAuthorizedError
from dast_harness.scanners.base import Scanner


class FindingScanner(Scanner):
    def __init__(self, name: str, count: int) -> None:
        self.name = name
        self.count = count

    def is_available(self) -> bool:
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None) -> int:
        for i in range(self.count):
            on_finding(
                Finding(self.name, f"{self.name}-{i}", "x", Severity.HIGH, target.url)
            )
        return 0


class FailScanner(Scanner):
    name = "fail"

    def is_available(self) -> bool:
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None) -> int:
        raise RuntimeError("boom")


class WarnScanner(Scanner):
    name = "warn"

    def is_available(self) -> bool:
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None) -> int:
        if on_warning is not None:
            on_warning("something odd")
        return 0


class MultiScanRunnerTests(unittest.TestCase):
    def test_merges_findings_and_reports_per_scanner(self) -> None:
        runner = MultiScanRunner([FindingScanner("a", 2), FindingScanner("b", 3)])
        scan_id = runner.start_scan(Target("http://127.0.0.1"))
        status = runner.wait(scan_id, timeout=2)

        self.assertEqual(status["status"], "completed")
        self.assertEqual(status["findings_count"], 5)
        self.assertEqual(set(status["scanners"]), {"a", "b"})
        by_scanner = {f.scanner for f in runner.get_results(scan_id)}
        self.assertEqual(by_scanner, {"a", "b"})

    def test_one_failure_makes_overall_failed_but_keeps_others(self) -> None:
        runner = MultiScanRunner([FindingScanner("a", 2), FailScanner()])
        scan_id = runner.start_scan(Target("http://127.0.0.1"))
        status = runner.wait(scan_id, timeout=2)

        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["scanners"]["a"]["status"], "completed")
        self.assertEqual(status["scanners"]["fail"]["status"], "failed")
        # the healthy scanner's findings still survive
        self.assertEqual(len(runner.get_results(scan_id)), 2)

    def test_warnings_are_prefixed_by_scanner(self) -> None:
        runner = MultiScanRunner([WarnScanner()])
        scan_id = runner.start_scan(Target("http://127.0.0.1"))
        runner.wait(scan_id, timeout=2)
        self.assertEqual(runner.get_warnings(scan_id), ["[warn] something odd"])

    def test_safety_is_enforced_before_any_scanner(self) -> None:
        runner = MultiScanRunner([FindingScanner("a", 1)])
        with self.assertRaises(TargetNotAuthorizedError):
            runner.start_scan(Target("https://example.com"))

    def test_duplicate_scanner_names_rejected(self) -> None:
        with self.assertRaises(ValueError):
            MultiScanRunner([FindingScanner("a", 1), FindingScanner("a", 1)])

    def test_build_report_works_on_multi_runner(self) -> None:
        runner = MultiScanRunner([FindingScanner("a", 1), FindingScanner("b", 1)])
        scan_id = runner.start_scan(Target("http://127.0.0.1"))
        runner.wait(scan_id, timeout=2)
        report = build_report(runner, scan_id)
        self.assertEqual(len(report.findings), 2)
        self.assertEqual(report.status["status"], "completed")


if __name__ == "__main__":
    unittest.main()
