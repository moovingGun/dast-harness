import json
import sys
import threading
import time
import unittest

from dast_harness import (
    NucleiScanner,
    ScanConfig,
    Severity,
    Target,
)


class ScriptedNucleiScanner(NucleiScanner):
    """Run a local Python snippet while exercising NucleiScanner's process code."""

    def __init__(self, script: str) -> None:
        super().__init__(binary=sys.executable)
        self.script = script

    def _build_command(self, target: Target, config: ScanConfig) -> list[str]:
        return [sys.executable, "-c", self.script]


class NucleiScannerTests(unittest.TestCase):
    def test_builds_command_from_structured_options(self) -> None:
        command = NucleiScanner()._build_command(
            Target("http://127.0.0.1:8080"),
            ScanConfig(
                severities=[Severity.HIGH, Severity.CRITICAL],
                tags=["cve"],
                template_ids=["example-template"],
                rate_limit=20,
                request_timeout=5,
            ),
        )

        self.assertEqual(command.count("-u"), 1)
        self.assertIn("high,critical", command)
        self.assertIn("cve", command)
        self.assertIn("example-template", command)
        self.assertIn("20", command)
        self.assertIn("5", command)
        # safety hardening defaults
        self.assertIn("-disable-redirects", command)
        self.assertIn("-no-interactsh", command)

    def test_interactsh_can_be_enabled(self) -> None:
        command = NucleiScanner()._build_command(
            Target("http://127.0.0.1:8080"),
            ScanConfig(enable_interactsh=True),
        )
        self.assertIn("-disable-redirects", command)  # still enforced
        self.assertNotIn("-no-interactsh", command)

    def test_rejects_invalid_limits(self) -> None:
        with self.assertRaises(ValueError):
            ScanConfig(rate_limit=0)
        with self.assertRaises(ValueError):
            ScanConfig(request_timeout=-1)

    def test_streams_and_normalizes_jsonl(self) -> None:
        payload = {
            "template-id": "missing-header",
            "matched-at": "http://127.0.0.1:8080",
            "info": {
                "name": "Missing Header",
                "severity": "low",
                "description": "A security header is absent.",
                "tags": ["headers"],
            },
        }
        script = f"print({json.dumps(json.dumps(payload))}, flush=True)"
        scanner = ScriptedNucleiScanner(script)
        findings = []

        outcome = scanner.run(
            Target("http://127.0.0.1"), ScanConfig(), findings.append
        )

        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(outcome.parsed_records, 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_id, "missing-header")
        self.assertEqual(findings[0].severity, Severity.LOW)
        self.assertEqual(findings[0].raw, payload)

    def test_nonzero_exit_reported_in_outcome(self) -> None:
        scanner = ScriptedNucleiScanner("raise SystemExit(7)")

        outcome = scanner.run(Target("http://127.0.0.1"), ScanConfig(), lambda _: None)
        self.assertEqual(outcome.exit_code, 7)

    def test_invalid_jsonl_is_skipped_and_warned(self) -> None:
        # A malformed line must not abort the scan: it is skipped, recorded as a
        # warning, and a following valid line is still delivered.
        good = json.dumps({"template-id": "ok", "info": {"severity": "info"}})
        script = (
            "print('not-json', flush=True)\n"
            f"print({json.dumps(good)}, flush=True)"
        )
        scanner = ScriptedNucleiScanner(script)
        findings = []
        warnings = []

        outcome = scanner.run(
            Target("http://127.0.0.1"),
            ScanConfig(),
            findings.append,
            on_warning=warnings.append,
        )

        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(outcome.parsed_records, 1)
        self.assertEqual(outcome.invalid_records, 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_id, "ok")
        self.assertEqual(len(warnings), 1)
        self.assertIn("invalid JSONL", warnings[0])

    def test_stop_terminates_process_with_no_stdout(self) -> None:
        scanner = ScriptedNucleiScanner("import time; time.sleep(30)")
        stop_event = threading.Event()
        timer = threading.Timer(0.1, stop_event.set)
        timer.start()
        started = time.monotonic()
        try:
            outcome = scanner.run(
                Target("http://127.0.0.1"),
                ScanConfig(),
                lambda _: None,
                stop_event,
            )
        finally:
            timer.cancel()

        self.assertTrue(outcome.stopped)
        self.assertLess(time.monotonic() - started, 3)


if __name__ == "__main__":
    unittest.main()
