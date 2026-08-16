import unittest

from dast_harness import ScanRunner, ScannerExecutionError, ScanStatus, Target
from dast_harness.scanners.base import Scanner


class ExitScanner(Scanner):
    name = "exit-scanner"

    def __init__(self, exit_code: int) -> None:
        self.exit_code = exit_code

    def is_available(self) -> bool:
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None) -> int:
        return self.exit_code


class ErrorScanner(ExitScanner):
    def run(self, target, config, on_finding, stop_event=None, on_warning=None) -> int:
        raise RuntimeError("scanner exploded")


class ProcessErrorScanner(ExitScanner):
    def run(self, target, config, on_finding, stop_event=None, on_warning=None) -> int:
        raise ScannerExecutionError("scanner exited with code 9", 9)


class BlockingScanner(ExitScanner):
    def run(self, target, config, on_finding, stop_event=None, on_warning=None) -> int:
        assert stop_event is not None
        stop_event.wait(timeout=2)
        return -15 if stop_event.is_set() else 0


class WarningScanner(ExitScanner):
    def run(self, target, config, on_finding, stop_event=None, on_warning=None) -> int:
        if on_warning is not None:
            on_warning("skipped a bad line")
        return 0


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
        self.assertEqual(status["error"], "scanner exited with code 9")

    def test_stop_marks_scan_stopped(self) -> None:
        runner = ScanRunner(BlockingScanner(0))
        scan_id = runner.start_scan(Target("http://127.0.0.1"))

        runner.stop_scan(scan_id)
        status = runner.wait(scan_id, timeout=2)

        self.assertEqual(status["status"], ScanStatus.STOPPED.value)
        self.assertEqual(status["exit_code"], -15)

    def test_warnings_do_not_fail_a_scan(self) -> None:
        runner = ScanRunner(WarningScanner(0))
        scan_id = runner.start_scan(Target("http://127.0.0.1"))

        status = runner.wait(scan_id, timeout=2)

        self.assertEqual(status["status"], ScanStatus.COMPLETED.value)
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
