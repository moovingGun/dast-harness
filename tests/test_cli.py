import contextlib
import io
import json
import os
import tempfile
import time
import unittest

from dast_harness import Finding, ScanOutcome, Severity
from dast_harness import cli
from dast_harness.agent_kit import (AgentFinding, Confidence, Evidence,
                                    HttpExchange, Probe)
from dast_harness.agent_kit.base import Agent
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


class Good2(Good):
    name = "good2"


class SpyGood(Scanner):
    name = "spy"
    runs = 0

    def is_available(self):
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        type(self).runs += 1
        return _outcome(parsed_records=0)


class SlowButStops(Scanner):
    """Runs past the deadline but completes promptly once stop is requested;
    its final status is COMPLETED (not stopped)."""

    name = "slow"

    def is_available(self):
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        for _ in range(300):
            if stop_event is not None and stop_event.is_set():
                break
            time.sleep(0.02)
        return _outcome(parsed_records=0)


class ProbeAgent(Agent):
    """A stand-in agent that reports one finding without touching the network."""

    name = "probe"
    unit = "endpoint"

    def run(self, base):
        exchange = HttpExchange(
            method="GET", url=f"{base}/x", status=200, actor="anon",
            response_headers={"Content-Type": "text/html"}, response_excerpt="hi",
        )
        finding = AgentFinding(
            scanner="agent:probe", finding_id="p-1", name="probe finding",
            severity=Severity.MEDIUM, matched_at=f"{base}/x",
            confidence=Confidence.TENTATIVE, category="injection",
            evidence=Evidence(exchanges=[exchange], rationale="테스트용",
                              baseline_index=0),
            agent_data={"probe": Probe(strategy="s", target="q",
                                       target_kind="parameter")},
        )
        return self.finish([finding], tested=2)


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

    # --- Problem 1: explicitly requested scanner missing -----------------
    def test_explicit_missing_scanner_exits_2_without_scanning(self):
        SpyGood.runs = 0
        cli.SCANNERS = {"spy": SpyGood, "off": Unavailable}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, out = run_cli(["scan", LOCAL, "--scanner", "spy,off"])
        self.assertEqual(code, 2)
        self.assertEqual(SpyGood.runs, 0)          # no scan was started
        self.assertIn("off", err.getvalue())       # names the missing scanner

    def test_explicit_all_available_runs(self):
        cli.SCANNERS = {"good": Good, "good2": Good2}
        code, _ = run_cli(["scan", LOCAL, "--scanner", "good,good2"])
        self.assertEqual(code, 0)

    def test_scanner_omitted_selects_available(self):
        cli.SCANNERS = {"good": Good, "off": Unavailable}
        code, _ = run_cli(["scan", LOCAL])  # no --scanner
        self.assertEqual(code, 0)


class AgentSelectionTests(unittest.TestCase):
    """Agents are picked through the same -s flag, as 'agent:<name>'."""

    def setUp(self):
        self._scanners = dict(cli.SCANNERS)
        self._agents = dict(cli.AGENTS)
        cli.AGENTS = {"probe": ProbeAgent}

    def tearDown(self):
        cli.SCANNERS = self._scanners
        cli.AGENTS = self._agents

    def test_agent_only_runs_without_any_scanner_installed(self):
        # A teammate with no nuclei/nikto must still be able to run their agent.
        cli.SCANNERS = {"off": Unavailable}
        code, out = run_cli(["scan", LOCAL, "-s", "agent:probe"])
        self.assertEqual(code, 0)
        self.assertIn("agent:probe", out)

    def test_scanner_and_agent_appear_in_one_report(self):
        cli.SCANNERS = {"good": Good}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.json")
            code, _ = run_cli(["scan", LOCAL, "-s", "good,agent:probe",
                               "--format", "json", "-o", path])
            with open(path) as fh:
                data = json.load(fh)
        self.assertEqual(code, 0)
        self.assertEqual(data["findings_count"], 2)
        self.assertIn("good", data["scanners"])
        self.assertIn("probe", data["agents"])
        # The agent's own deliverable rides along, not just its findings.
        self.assertEqual(data["agents"]["probe"]["result"]["coverage"]["tested"], 2)

    def test_unknown_agent_exits_2(self):
        cli.SCANNERS = {"good": Good}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, _ = run_cli(["scan", LOCAL, "-s", "agent:nope"])
        self.assertEqual(code, 2)
        self.assertIn("nope", err.getvalue())

    def test_agents_are_off_unless_named(self):
        cli.SCANNERS = {"good": Good}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.json")
            run_cli(["scan", LOCAL, "--format", "json", "-o", path])
            with open(path) as fh:
                data = json.load(fh)
        self.assertIsNone(data["agents"])

    def test_bad_auth_file_exits_2_before_scanning(self):
        SpyGood.runs = 0
        cli.SCANNERS = {"spy": SpyGood}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "actors.json")
            with open(path, "w") as fh:
                # No 'verify' block — rejected at load time.
                json.dump({"actors": {"alice": {"cookies": {"s": "x"}}}}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code, _ = run_cli(["scan", LOCAL, "-s", "spy,agent:probe",
                                   "--auth", path])
        self.assertEqual(code, 2)
        self.assertEqual(SpyGood.runs, 0)          # nothing was started
        self.assertIn("verify", err.getvalue())

    def test_auth_without_an_agent_exits_2(self):
        cli.SCANNERS = {"good": Good}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "actors.json")
            with open(path, "w") as fh:
                json.dump({"actors": {"alice": {"cookies": {"s": "x"},
                                                "verify": {"path": "/"}}}}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code, _ = run_cli(["scan", LOCAL, "-s", "good", "--auth", path])
        self.assertEqual(code, 2)
        self.assertIn("agent", err.getvalue())

    def test_agent_target_is_still_authorized(self):
        cli.SCANNERS = {"good": Good}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, _ = run_cli(["scan", "http://8.8.8.8", "-s", "agent:probe"])
        self.assertEqual(code, 2)

    # --- Problem 2: deadline expiry must win over a late completion -------
    def test_timeout_then_completion_in_grace_exits_124(self):
        cli.SCANNERS = {"slow": SlowButStops}
        code, _ = run_cli(["scan", LOCAL, "--scanner", "slow", "--timeout", "0.1"])
        self.assertEqual(code, 124)

    def test_completes_before_deadline_exits_0(self):
        cli.SCANNERS = {"good": Good}
        code, _ = run_cli(["scan", LOCAL, "--scanner", "good", "--timeout", "10"])
        self.assertEqual(code, 0)

    # --- Problem 3: output write errors ----------------------------------
    def test_output_nonexistent_dir_exits_2(self):
        cli.SCANNERS = {"good": Good}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, out = run_cli(
                ["scan", LOCAL, "--scanner", "good", "-o", "/no/such/dir/r.json"]
            )
        self.assertEqual(code, 2)
        self.assertIn("error", err.getvalue())
        self.assertNotIn("wrote", out)  # no partial success on stdout

    def test_output_write_error_mock_exits_2(self):
        import unittest.mock as mock
        cli.SCANNERS = {"good": Good}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            with mock.patch("builtins.open", side_effect=OSError("disk full")):
                code, out = run_cli(
                    ["scan", LOCAL, "--scanner", "good", "-o", "/tmp/whatever.json"]
                )
        self.assertEqual(code, 2)
        self.assertIn("error", err.getvalue())
        self.assertNotIn("wrote", out)

    # --- Problem 4: option combination validation ------------------------
    def test_include_raw_requires_json(self):
        cli.SCANNERS = {"good": Good}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, _ = run_cli(["scan", LOCAL, "--scanner", "good", "--include-raw"])
        self.assertEqual(code, 2)
        self.assertIn("json", err.getvalue().lower())

    def test_invalid_timeout_values_exit_2(self):
        cli.SCANNERS = {"good": Good}
        for bad in ("0", "-1", "nan", "inf"):
            with self.subTest(timeout=bad):
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    code, _ = run_cli(
                        ["scan", LOCAL, "--scanner", "good", "--timeout", bad]
                    )
                self.assertEqual(code, 2, f"timeout={bad}")


if __name__ == "__main__":
    unittest.main()
