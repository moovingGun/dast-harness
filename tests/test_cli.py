import contextlib
import io
import json
import os
import tempfile
import time
import unittest

from dast_harness import Finding, ScanOutcome, Severity
from dast_harness import cli
from dast_harness.orchestrator import MultiScanRunner
from dast_harness.scanners.base import Scanner

LOCAL = "http://127.0.0.1"


def _outcome(**kw):
    base = dict(exit_code=0, output_present=True, output_parseable=True,
               parsed_records=1, invalid_records=0, fatal=False, stopped=False)
    base.update(kw)
    return ScanOutcome(**base)


class Good(Scanner):
    name = "good"

    def is_available(self):
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        on_finding(Finding("good", "g-1", "n", Severity.HIGH, target.url,
                           raw={"k": "v"}))
        return _outcome(parsed_records=1)


class Bad(Scanner):
    name = "bad"

    def is_available(self):
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        return _outcome(exit_code=1, fatal=True, parsed_records=0)


class Unavailable(Scanner):
    name = "off"

    def is_available(self):
        return False

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        return _outcome()


class Deaf(Scanner):
    name = "deaf"

    def is_available(self):
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        time.sleep(3)
        return _outcome(parsed_records=0)


def run_cli(argv):
    """Run the CLI, swallowing stdout, returning (exit_code, stdout)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(argv)
    return code, out.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self._orig = dict(cli.SCANNERS)

    def tearDown(self):
        cli.SCANNERS = self._orig

    def test_completed_exits_0(self):
        cli.SCANNERS = {"good": Good}
        code, out = run_cli(["scan", LOCAL, "--scanner", "good"])
        self.assertEqual(code, 0)
        self.assertIn("good", out)

    def test_partial_exits_1(self):
        cli.SCANNERS = {"good": Good, "bad": Bad}
        code, _ = run_cli(["scan", LOCAL, "--scanner", "good,bad"])
        self.assertEqual(code, 1)

    def test_all_failed_exits_1(self):
        cli.SCANNERS = {"bad": Bad}
        code, _ = run_cli(["scan", LOCAL, "--scanner", "bad"])
        self.assertEqual(code, 1)

    def test_target_refused_exits_2(self):
        cli.SCANNERS = {"good": Good}
        # a non-loopback literal IP is refused without any DNS lookup
        code, _ = run_cli(["scan", "http://8.8.8.8", "--scanner", "good"])
        self.assertEqual(code, 2)

    def test_unknown_scanner_exits_2(self):
        cli.SCANNERS = {"good": Good}
        code, _ = run_cli(["scan", LOCAL, "--scanner", "nope"])
        self.assertEqual(code, 2)

    def test_no_available_scanner_exits_2(self):
        cli.SCANNERS = {"off": Unavailable}
        code, _ = run_cli(["scan", LOCAL, "--scanner", "off"])
        self.assertEqual(code, 2)

    def test_invalid_severity_exits_2(self):
        cli.SCANNERS = {"good": Good}
        code, _ = run_cli(["scan", LOCAL, "--scanner", "good", "--severity", "bogus"])
        self.assertEqual(code, 2)

    def test_json_output_to_file(self):
        cli.SCANNERS = {"good": Good}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.json")
            code, _ = run_cli(
                ["scan", LOCAL, "--scanner", "good", "--format", "json", "-o", path]
            )
            self.assertEqual(code, 0)
            with open(path) as fh:
                data = json.load(fh)
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["findings_count"], 1)
        # raw is off by default in output
        self.assertNotIn("raw", data["findings"][0])

    def test_include_raw_in_json(self):
        cli.SCANNERS = {"good": Good}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.json")
            run_cli(["scan", LOCAL, "--scanner", "good", "--format", "json",
                     "-o", path, "--include-raw"])
            with open(path) as fh:
                data = json.load(fh)
        self.assertEqual(data["findings"][0]["raw"], {"k": "v"})

    def test_timeout_exits_124(self):
        cli.SCANNERS = {"deaf": Deaf}
        code, _ = run_cli(["scan", LOCAL, "--scanner", "deaf", "--timeout", "0.3"])
        self.assertEqual(code, 124)

    def test_keyboard_interrupt_exits_130(self):
        cli.SCANNERS = {"good": Good}
        calls = {"n": 0}
        orig = MultiScanRunner.wait

        def fake_wait(self, group_id, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise KeyboardInterrupt
            return orig(self, group_id, timeout)

        MultiScanRunner.wait = fake_wait
        try:
            code, _ = run_cli(["scan", LOCAL, "--scanner", "good"])
        finally:
            MultiScanRunner.wait = orig
        self.assertEqual(code, 130)


if __name__ == "__main__":
    unittest.main()
