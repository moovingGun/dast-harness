import threading
import unittest

from dast_harness import (
    Finding,
    MultiScanRunner,
    ScanConfig,
    ScanOutcome,
    ScanStatus,
    Severity,
    Target,
    build_report,
)
from dast_harness.safety import TargetNotAuthorizedError
from dast_harness.scanners.base import Scanner


def _ok(**kw):
    base = dict(exit_code=0, output_present=True, output_parseable=True,
               parsed_records=0, invalid_records=0, fatal=False, stopped=False)
    base.update(kw)
    return ScanOutcome(**base)


class FindingScanner(Scanner):
    def __init__(self, name: str, count: int) -> None:
        self.name = name
        self.count = count

    def is_available(self) -> bool:
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        for i in range(self.count):
            on_finding(
                Finding(self.name, f"{self.name}-{i}", "x", Severity.HIGH, target.url)
            )
        return _ok(parsed_records=self.count)


class FailScanner(Scanner):
    name = "fail"

    def is_available(self) -> bool:
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        raise RuntimeError("boom")


class WarnScanner(Scanner):
    name = "warn"

    def is_available(self) -> bool:
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        if on_warning is not None:
            on_warning("something odd")
        return _ok(invalid_records=1)


class ControlledScanner(Scanner):
    """Emits its findings, then blocks until released (or stopped), so tests can
    observe the mid-scan 'running' state and control timing deterministically."""

    def __init__(self, name: str, findings: int = 0) -> None:
        self.name = name
        self._findings = findings
        self.entered = threading.Event()   # set once findings are delivered
        self.release = threading.Event()   # test sets this to let run() finish

    def is_available(self) -> bool:
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        for i in range(self._findings):
            on_finding(
                Finding(self.name, f"{self.name}-{i}", "x", Severity.HIGH, target.url)
            )
        self.entered.set()
        while not self.release.is_set():
            if stop_event is not None and stop_event.is_set():
                return _ok(exit_code=-15, output_present=False,
                           output_parseable=False, stopped=True)
            self.release.wait(timeout=0.01)
        return _ok(parsed_records=self._findings)


class RollupTests(unittest.TestCase):
    """The decided overall-status model, encoded directly (no threads)."""

    C = ScanStatus.COMPLETED.value
    F = ScanStatus.FAILED.value
    S = ScanStatus.STOPPED.value
    R = ScanStatus.RUNNING.value
    P = ScanStatus.PENDING.value

    def assertRollup(self, statuses, expected) -> None:
        self.assertEqual(MultiScanRunner._rollup(statuses), expected)

    def test_all_completed(self) -> None:
        self.assertRollup([self.C, self.C], ScanStatus.COMPLETED.value)

    def test_any_active_is_running(self) -> None:
        self.assertRollup([self.C, self.R], ScanStatus.RUNNING.value)
        self.assertRollup([self.P, self.F], ScanStatus.RUNNING.value)

    def test_some_completed_some_failed_is_partial(self) -> None:
        self.assertRollup([self.C, self.F], ScanStatus.PARTIAL.value)

    def test_effective_stop_dominates(self) -> None:
        # An effective stop makes the whole group STOPPED, even alongside a
        # completed child.
        self.assertRollup([self.C, self.S], ScanStatus.STOPPED.value)
        self.assertRollup([self.C, self.F, self.S], ScanStatus.STOPPED.value)
        self.assertRollup([self.S, self.S], ScanStatus.STOPPED.value)
        self.assertRollup([self.F, self.S], ScanStatus.STOPPED.value)

    def test_all_failed_is_failed(self) -> None:
        self.assertRollup([self.F, self.F], ScanStatus.FAILED.value)


class MultiScanRunnerConcurrencyTests(unittest.TestCase):
    def test_scanners_run_in_parallel(self) -> None:
        a, b = ControlledScanner("a"), ControlledScanner("b")
        runner = MultiScanRunner([a, b])
        scan_id = runner.start_scan(Target("http://127.0.0.1"))
        try:
            # Both enter run() while neither has been released -> both alive at
            # once, which only happens if they run concurrently.
            self.assertTrue(a.entered.wait(2))
            self.assertTrue(b.entered.wait(2))
            self.assertEqual(runner.get_status(scan_id)["status"], "running")
        finally:
            a.release.set()
            b.release.set()
        self.assertEqual(runner.wait(scan_id, timeout=2)["status"], "completed")

    def test_running_status_and_partial_results_midscan(self) -> None:
        a = ControlledScanner("a", findings=2)
        runner = MultiScanRunner([a])
        scan_id = runner.start_scan(Target("http://127.0.0.1"))
        try:
            self.assertTrue(a.entered.wait(2))
            status = runner.get_status(scan_id)
            self.assertEqual(status["status"], "running")
            self.assertEqual(status["scanners"]["a"]["status"], "running")
            # findings are already observable before the scan finishes
            self.assertEqual(len(runner.get_results(scan_id)), 2)
        finally:
            a.release.set()
        runner.wait(scan_id, timeout=2)

    def test_stop_marks_multi_stopped(self) -> None:
        a, b = ControlledScanner("a"), ControlledScanner("b")
        runner = MultiScanRunner([a, b])
        scan_id = runner.start_scan(Target("http://127.0.0.1"))
        self.assertTrue(a.entered.wait(2))
        self.assertTrue(b.entered.wait(2))

        runner.stop_scan(scan_id)
        status = runner.wait(scan_id, timeout=2)
        self.assertEqual(status["status"], "stopped")

    def test_completed_plus_stopped_rolls_up_to_stopped(self) -> None:
        done = FindingScanner("done", 1)      # finishes immediately
        blocked = ControlledScanner("blocked")
        runner = MultiScanRunner([done, blocked])
        scan_id = runner.start_scan(Target("http://127.0.0.1"))
        self.assertTrue(blocked.entered.wait(2))

        runner.stop_scan(scan_id)             # only 'blocked' is still active
        status = runner.wait(scan_id, timeout=2)
        # an effective stop dominates the rollup, but the completed child is kept
        self.assertEqual(status["status"], "stopped")
        self.assertEqual(status["scanners"]["done"]["status"], "completed")
        self.assertEqual(status["scanners"]["blocked"]["status"], "stopped")

    def test_unknown_scan_id_raises(self) -> None:
        runner = MultiScanRunner([FindingScanner("a", 1)])
        with self.assertRaises(KeyError):
            runner.get_status("nope")

    def test_empty_scanner_list_rejected(self) -> None:
        with self.assertRaises(ValueError):
            MultiScanRunner([])


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

    def test_one_failure_makes_overall_partial_but_keeps_others(self) -> None:
        runner = MultiScanRunner([FindingScanner("a", 2), FailScanner()])
        scan_id = runner.start_scan(Target("http://127.0.0.1"))
        status = runner.wait(scan_id, timeout=2)

        # some completed, some failed -> partial (results still exist)
        self.assertEqual(status["status"], "partial")
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
