import unittest

from dast_harness import ScanOutcome, ScanRunner, ScanStatus, Target
from dast_harness.scanners.base import Scanner


def _outcome(exit_code, **kw):
    base = dict(output_present=True, output_parseable=True, parsed_records=0,
               invalid_records=0, fatal=False, stopped=False)
    base.update(kw)
    return ScanOutcome(exit_code=exit_code, **base)


class ExitScanner(Scanner):
    name = "exit-scanner"

    def __init__(self, exit_code: int) -> None:
        self.exit_code = exit_code

    def is_available(self) -> bool:
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        return _outcome(self.exit_code)


class ErrorScanner(ExitScanner):
    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        raise RuntimeError("scanner exploded")


class ProcessErrorScanner(ExitScanner):
    # A scanner that reports a nonzero exit via the outcome (not by raising).
    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        return _outcome(9, fatal=True)


class BlockingScanner(ExitScanner):
    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        assert stop_event is not None
        stop_event.wait(timeout=2)
        if stop_event.is_set():
            return _outcome(-15, stopped=True)
        return _outcome(0)


class WarningScanner(ExitScanner):
    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        if on_warning is not None:
            on_warning("skipped a bad line")
        return _outcome(0, invalid_records=1)


class ScanRunnerTests(unittest.TestCase):
    def test_zero_exit_code_completes(self) -> None:
        runner = ScanRunner(ExitScanner(0))
        scan_id = runner.start_scan(Target("http://127.0.0.1"))

        status = runner.wait(scan_id, timeout=2)

        self.assertEqual(status["status"], ScanStatus.COMPLETED.value)
        self.assertEqual(status["exit_code"], 0)

    def test_nonzero_exit_code_fails(self) -> None:
        runner = ScanRunner(ExitScanner(7))
        scan_id = runner.start_scan(Target("http://127.0.0.1"))

        status = runner.wait(scan_id, timeout=2)

        self.assertEqual(status["status"], ScanStatus.FAILED.value)
        self.assertEqual(status["exit_code"], 7)
        self.assertIn("exited with code 7", status["error"])

    def test_scanner_exception_fails(self) -> None:
        runner = ScanRunner(ErrorScanner(0))
        scan_id = runner.start_scan(Target("http://127.0.0.1"))

        status = runner.wait(scan_id, timeout=2)

        self.assertEqual(status["status"], ScanStatus.FAILED.value)
        self.assertEqual(status["error"], "scanner exploded")

    def test_scanner_execution_error_preserves_exit_code(self) -> None:
        runner = ScanRunner(ProcessErrorScanner(0))
        scan_id = runner.start_scan(Target("http://127.0.0.1"))

        status = runner.wait(scan_id, timeout=2)

        self.assertEqual(status["status"], ScanStatus.FAILED.value)
        self.assertEqual(status["exit_code"], 9)
        self.assertIn("exited with code 9", status["error"])

    def test_stop_marks_scan_stopped(self) -> None:
        runner = ScanRunner(BlockingScanner(0))
        scan_id = runner.start_scan(Target("http://127.0.0.1"))

        runner.stop_scan(scan_id)
        status = runner.wait(scan_id, timeout=2)

        self.assertEqual(status["status"], ScanStatus.STOPPED.value)
        self.assertEqual(status["exit_code"], -15)

    def test_warnings_yield_completed_with_warnings(self) -> None:
        runner = ScanRunner(WarningScanner(0))
        scan_id = runner.start_scan(Target("http://127.0.0.1"))

        status = runner.wait(scan_id, timeout=2)

        # non-fatal parse warnings -> COMPLETED_WITH_WARNINGS, still not a failure
        self.assertEqual(status["status"], ScanStatus.COMPLETED_WITH_WARNINGS.value)
        self.assertEqual(status["warnings_count"], 1)
        self.assertEqual(runner.get_warnings(scan_id), ["skipped a bad line"])

    def test_stopping_finished_scan_does_not_change_status(self) -> None:
        runner = ScanRunner(ExitScanner(0))
        scan_id = runner.start_scan(Target("http://127.0.0.1"))
        runner.wait(scan_id, timeout=2)

        runner.stop_scan(scan_id)

        self.assertEqual(
            runner.get_status(scan_id)["status"], ScanStatus.COMPLETED.value
        )


if __name__ == "__main__":
    unittest.main()
