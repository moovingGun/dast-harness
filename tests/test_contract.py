"""Contract tests for status judgement and completion evidence.

These encode the required behavior; they are the source of truth. Fakes return
a ScanOutcome (the new Scanner.run contract).
"""

import json
import os
import sys
import tempfile
import threading
import time
import unittest

from dast_harness import (
    CompletionEvidence,
    Finding,
    JSONReporter,
    MultiScanRunner,
    NiktoScanner,
    NucleiScanner,
    ScanConfig,
    ScanOutcome,
    ScanRunner,
    ScanStatus,
    Severity,
    Target,
    build_report,
)
from dast_harness.scanners.base import Scanner

LOCAL = "http://127.0.0.1"


def ok_outcome(**kw):
    base = dict(exit_code=0, output_present=True, output_parseable=True,
               parsed_records=1, invalid_records=0, fatal=False, stopped=False,
               scanner_version="x-1.0")
    base.update(kw)
    return ScanOutcome(**base)


class OutcomeScanner(Scanner):
    def __init__(self, name, outcome, findings=(), warnings=()):
        self.name = name
        self._outcome = outcome
        self._findings = findings
        self._warnings = warnings

    def is_available(self):
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        for f in self._findings:
            on_finding(f)
        for w in self._warnings:
            if on_warning is not None:
                on_warning(w)
        return self._outcome


class RaisingScanner(Scanner):
    def __init__(self, name="boom"):
        self.name = name

    def is_available(self):
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        raise FileNotFoundError("scanner binary not found")


class StopOutcomeScanner(Scanner):
    def __init__(self, name="blk"):
        self.name = name
        self.entered = threading.Event()

    def is_available(self):
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        self.entered.set()
        while not (stop_event and stop_event.is_set()):
            time.sleep(0.01)
        return ScanOutcome(exit_code=-15, output_present=False,
                          output_parseable=False, stopped=True)


def run_single(scanner, config=None):
    r = ScanRunner(scanner)
    sid = r.start_scan(Target(LOCAL), config or ScanConfig())
    r.wait(sid, timeout=5)
    return r, sid


# --------------------------------------------------------------------------
# Per-scanner status judgement from a ScanOutcome
# --------------------------------------------------------------------------
class PerScannerStatusTests(unittest.TestCase):
    def test_clean_outcome_is_completed(self):
        r, sid = run_single(OutcomeScanner("a", ok_outcome(),
                                           findings=[Finding("a", "1", "n", Severity.LOW, LOCAL)]))
        self.assertEqual(r.get_status(sid)["status"], ScanStatus.COMPLETED.value)

    def test_warnings_make_completed_with_warnings(self):
        r, sid = run_single(OutcomeScanner(
            "a", ok_outcome(invalid_records=2),
            findings=[Finding("a", "1", "n", Severity.LOW, LOCAL)],
            warnings=["bad line", "bad line 2"]))
        self.assertEqual(r.get_status(sid)["status"],
                         ScanStatus.COMPLETED_WITH_WARNINGS.value)

    def test_fatal_outcome_is_failed(self):
        r, sid = run_single(OutcomeScanner("a", ok_outcome(fatal=True)))
        self.assertEqual(r.get_status(sid)["status"], ScanStatus.FAILED.value)

    def test_nonzero_exit_is_failed(self):
        r, sid = run_single(OutcomeScanner("a", ok_outcome(exit_code=7)))
        self.assertEqual(r.get_status(sid)["status"], ScanStatus.FAILED.value)

    def test_stopped_outcome_is_stopped(self):
        s = StopOutcomeScanner()
        r = ScanRunner(s)
        sid = r.start_scan(Target(LOCAL))
        self.assertTrue(s.entered.wait(2))
        r.stop_scan(sid)
        r.wait(sid, timeout=2)
        self.assertEqual(r.get_status(sid)["status"], ScanStatus.STOPPED.value)


# --------------------------------------------------------------------------
# Completion evidence
# --------------------------------------------------------------------------
class CompletionEvidenceTests(unittest.TestCase):
    REQUIRED = {
        "scanner", "scanner_version", "started_at", "finished_at", "exit_code",
        "stop_requested", "stop_effective", "output_present", "output_parseable",
        "parsed_records", "invalid_records", "warnings_count", "findings_count",
        "config", "template_version",
    }

    def test_evidence_has_all_required_fields(self):
        cfg = ScanConfig(request_timeout=5)
        r, sid = run_single(OutcomeScanner(
            "a", ok_outcome(parsed_records=1, scanner_version="nuclei-3", template_version="v10"),
            findings=[Finding("a", "1", "n", Severity.LOW, LOCAL)]), cfg)
        ev = r.get_status(sid)["evidence"]
        self.assertIsNotNone(ev)
        self.assertTrue(self.REQUIRED.issubset(ev.keys()), ev.keys())
        self.assertEqual(ev["scanner"], "a")
        self.assertEqual(ev["exit_code"], 0)
        self.assertEqual(ev["scanner_version"], "nuclei-3")
        self.assertEqual(ev["template_version"], "v10")
        self.assertEqual(ev["findings_count"], 1)
        self.assertEqual(ev["config"], cfg.snapshot())

    def test_evidence_records_stop_effectiveness(self):
        s = StopOutcomeScanner()
        r = ScanRunner(s)
        sid = r.start_scan(Target(LOCAL))
        self.assertTrue(s.entered.wait(2))
        r.stop_scan(sid)
        r.wait(sid, timeout=2)
        ev = r.get_status(sid)["evidence"]
        self.assertTrue(ev["stop_requested"])
        self.assertTrue(ev["stop_effective"])

    def test_evidence_recorded_even_when_run_raises(self):
        r, sid = run_single(RaisingScanner("boom"))
        st = r.get_status(sid)
        self.assertEqual(st["status"], ScanStatus.FAILED.value)
        self.assertIsNotNone(st["evidence"])
        self.assertIn("not found", st["evidence"]["error"] or "")


# --------------------------------------------------------------------------
# Multi-scanner rollup (with COMPLETED_WITH_WARNINGS + stop domination)
# --------------------------------------------------------------------------
class RollupTests(unittest.TestCase):
    C = ScanStatus.COMPLETED.value
    W = ScanStatus.COMPLETED_WITH_WARNINGS.value
    F = ScanStatus.FAILED.value
    S = ScanStatus.STOPPED.value
    R = ScanStatus.RUNNING.value

    def rollup(self, statuses):
        return MultiScanRunner._rollup(statuses)

    def test_all_completed(self):
        self.assertEqual(self.rollup([self.C, self.C]), self.C)

    def test_both_success_one_with_warnings(self):
        self.assertEqual(self.rollup([self.C, self.W]), self.W)

    def test_one_success_one_fail_is_partial(self):
        self.assertEqual(self.rollup([self.C, self.F]), ScanStatus.PARTIAL.value)
        self.assertEqual(self.rollup([self.W, self.F]), ScanStatus.PARTIAL.value)

    def test_all_fail(self):
        self.assertEqual(self.rollup([self.F, self.F]), self.F)

    def test_effective_stop_dominates(self):
        # a completed child + a stopped child -> overall STOPPED
        self.assertEqual(self.rollup([self.C, self.S]), self.S)
        self.assertEqual(self.rollup([self.F, self.S]), self.S)

    def test_any_running(self):
        self.assertEqual(self.rollup([self.C, self.R]), self.R)


# --------------------------------------------------------------------------
# Multi-scanner behavior: preservation, stop, timeout, start-failure
# --------------------------------------------------------------------------
class MultiBehaviorTests(unittest.TestCase):
    def _findings(self, name, k):
        return OutcomeScanner(
            name, ok_outcome(parsed_records=k),
            findings=[Finding(name, f"{name}-{i}", "n", Severity.LOW, LOCAL)
                      for i in range(k)])

    def test_completed_results_preserved_when_other_fails(self):
        runner = MultiScanRunner([self._findings("good", 2),
                                  OutcomeScanner("bad", ok_outcome(exit_code=1, fatal=True))])
        sid = runner.start_scan(Target(LOCAL))
        status = runner.wait(sid, timeout=3)
        self.assertEqual(status["status"], ScanStatus.PARTIAL.value)
        self.assertEqual(len(runner.get_results(sid)), 2)
        self.assertEqual(status["scanners"]["good"]["status"], ScanStatus.COMPLETED.value)

    def test_completed_child_survives_group_stop(self):
        good = self._findings("good", 1)
        blocked = StopOutcomeScanner("blk")
        runner = MultiScanRunner([good, blocked])
        sid = runner.start_scan(Target(LOCAL))
        self.assertTrue(blocked.entered.wait(2))
        runner.stop_scan(sid)
        status = runner.wait(sid, timeout=3)
        self.assertEqual(status["status"], ScanStatus.STOPPED.value)
        self.assertEqual(status["scanners"]["good"]["status"], ScanStatus.COMPLETED.value)
        self.assertEqual(len(runner.get_results(sid)), 1)  # good's result kept

    def test_stop_after_all_completed_does_not_change_status(self):
        runner = MultiScanRunner([self._findings("a", 1), self._findings("b", 1)])
        sid = runner.start_scan(Target(LOCAL))
        runner.wait(sid, timeout=3)
        self.assertEqual(runner.get_status(sid)["status"], ScanStatus.COMPLETED.value)
        runner.stop_scan(sid)
        self.assertEqual(runner.get_status(sid)["status"], ScanStatus.COMPLETED.value)

    def test_group_timeout_is_a_shared_deadline(self):
        a, b = StopOutcomeScanner("a"), StopOutcomeScanner("b")
        runner = MultiScanRunner([a, b])
        sid = runner.start_scan(Target(LOCAL))
        self.assertTrue(a.entered.wait(2))
        self.assertTrue(b.entered.wait(2))
        start = time.monotonic()
        runner.wait(sid, timeout=0.5)
        elapsed = time.monotonic() - start
        # per-child repetition would take ~1.0s for two blocked scanners
        self.assertLess(elapsed, 0.9, f"timeout applied per-child, took {elapsed:.2f}s")

    def test_second_child_start_failure_is_isolated(self):
        runner = MultiScanRunner([self._findings("good", 1), RaisingScanner("boom")])
        sid = runner.start_scan(Target(LOCAL))
        status = runner.wait(sid, timeout=3)
        self.assertEqual(status["scanners"]["good"]["status"], ScanStatus.COMPLETED.value)
        self.assertEqual(status["scanners"]["boom"]["status"], ScanStatus.FAILED.value)
        self.assertEqual(len(runner.get_results(sid)), 1)


# --------------------------------------------------------------------------
# Unified JSON report
# --------------------------------------------------------------------------
class UnifiedReportTests(unittest.TestCase):
    def _multi(self):
        good = OutcomeScanner("good", ok_outcome(parsed_records=1),
                              findings=[Finding("good", "g1", "n", Severity.HIGH, LOCAL,
                                                raw={"secret": "x"})])
        bad = OutcomeScanner("bad", ok_outcome(exit_code=1, fatal=True, error="died"))
        runner = MultiScanRunner([good, bad])
        sid = runner.start_scan(Target(LOCAL))
        runner.wait(sid, timeout=3)
        return runner, sid

    def test_report_has_status_partial_flag_and_per_scanner(self):
        runner, sid = self._multi()
        data = json.loads(JSONReporter().render(build_report(runner, sid)))
        self.assertEqual(data["status"], ScanStatus.PARTIAL.value)
        self.assertTrue(data["results_partial"])
        self.assertIn("good", data["scanners"])
        self.assertEqual(data["scanners"]["bad"]["status"], ScanStatus.FAILED.value)
        self.assertIsNotNone(data["scanners"]["good"]["evidence"])

    def test_include_raw_default_is_off(self):
        runner, sid = self._multi()
        data = json.loads(JSONReporter().render(build_report(runner, sid)))
        self.assertNotIn("raw", data["findings"][0])

    def test_include_raw_true_emits_raw(self):
        runner, sid = self._multi()
        data = json.loads(JSONReporter(include_raw=True).render(build_report(runner, sid)))
        self.assertEqual(data["findings"][0]["raw"], {"secret": "x"})


# --------------------------------------------------------------------------
# Nuclei output policy (scripted through real NucleiScanner.run)
# --------------------------------------------------------------------------
class ScriptedNuclei(NucleiScanner):
    def __init__(self, script):
        super().__init__(binary=sys.executable)
        self._script = script

    def _build_command(self, target, config):
        return [sys.executable, "-c", self._script]


def line_script(*lines):
    body = "\n".join(f"print({json.dumps(l)}, flush=True)" for l in lines)
    return body


class NucleiPolicyTests(unittest.TestCase):
    def test_command_has_safe_defaults(self):
        cmd = NucleiScanner()._build_command(Target(LOCAL), ScanConfig())
        for flag in ("-disable-redirects", "-no-interactsh", "-disable-update-check"):
            self.assertIn(flag, cmd)

    def test_empty_output_exit0_is_completed(self):
        r, sid = run_single(ScriptedNuclei("pass"))
        st = r.get_status(sid)
        self.assertEqual(st["status"], ScanStatus.COMPLETED.value)
        self.assertFalse(st["evidence"]["output_present"])
        self.assertEqual(st["evidence"]["findings_count"], 0)

    def test_partial_parse_is_completed_with_warnings(self):
        good = json.dumps({"template-id": "ok", "info": {"severity": "low"}})
        r, sid = run_single(ScriptedNuclei(line_script(good, "not-json")))
        st = r.get_status(sid)
        self.assertEqual(st["status"], ScanStatus.COMPLETED_WITH_WARNINGS.value)
        self.assertEqual(st["evidence"]["parsed_records"], 1)
        self.assertEqual(st["evidence"]["invalid_records"], 1)

    def test_all_invalid_nonempty_is_failed(self):
        r, sid = run_single(ScriptedNuclei(line_script("not-json", "also-bad")))
        st = r.get_status(sid)
        self.assertEqual(st["status"], ScanStatus.FAILED.value)
        self.assertEqual(st["evidence"]["parsed_records"], 0)

    def test_valid_json_wrong_schema_counts_as_invalid(self):
        good = json.dumps({"template-id": "ok", "info": {"severity": "low"}})
        r, sid = run_single(ScriptedNuclei(line_script(good, "123")))  # 123 is valid json, not object
        st = r.get_status(sid)
        self.assertEqual(st["status"], ScanStatus.COMPLETED_WITH_WARNINGS.value)
        self.assertGreaterEqual(st["evidence"]["invalid_records"], 1)


# --------------------------------------------------------------------------
# Nikto output policy (file parsing through NiktoScanner)
# --------------------------------------------------------------------------
class NiktoPolicyTests(unittest.TestCase):
    def _write(self, d, content):
        path = os.path.join(d, "nikto.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def test_command_blocks_updates(self):
        cmd = NiktoScanner()._build_command(Target(LOCAL), ScanConfig(), "/tmp/o.json")
        self.assertIn("-nocheck", cmd)
        self.assertIn("-ask", cmd)

    def test_valid_json_zero_vulns_is_ok(self):
        scanner = NiktoScanner()
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, json.dumps([{"host": "127.0.0.1", "vulnerabilities": []}]))
            res = scanner._parse_file(path, LOCAL, lambda _: None, lambda _: None)
        self.assertTrue(res["output_present"])
        self.assertTrue(res["output_parseable"])
        self.assertFalse(res["fatal"])
        self.assertEqual(res["parsed_records"], 0)

    def test_missing_file_is_fatal(self):
        res = NiktoScanner()._parse_file("/nope/x.json", LOCAL, lambda _: None, lambda _: None)
        self.assertFalse(res["output_present"])
        self.assertTrue(res["fatal"])

    def test_empty_file_is_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, "")
            res = NiktoScanner()._parse_file(path, LOCAL, lambda _: None, lambda _: None)
        self.assertTrue(res["output_present"])
        self.assertTrue(res["fatal"])

    def test_corrupt_json_is_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, "not json")
            res = NiktoScanner()._parse_file(path, LOCAL, lambda _: None, lambda _: None)
        self.assertTrue(res["fatal"])
        self.assertFalse(res["output_parseable"])

    def test_bad_schema_is_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, json.dumps(12345))  # valid json, wrong shape
            res = NiktoScanner()._parse_file(path, LOCAL, lambda _: None, lambda _: None)
        self.assertTrue(res["fatal"])

    def test_host_metadata_and_raw_preserved_and_url_joined(self):
        findings = []
        doc = [{
            "host": "127.0.0.1", "ip": "127.0.0.1", "port": 8091, "banner": "x",
            "vulnerabilities": [{"id": "600720", "method": "GET",
                                 "msg": "outdated", "url": "/admin"}],
        }]
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, json.dumps(doc))
            NiktoScanner()._parse_file(path, "http://127.0.0.1:8091", findings.append, lambda _: None)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        # safe URL join, not naive concat
        self.assertEqual(f.matched_at, "http://127.0.0.1:8091/admin")
        # both host metadata and the raw vulnerability preserved
        self.assertEqual(f.raw["vulnerability"]["id"], "600720")
        self.assertEqual(f.raw["host"]["port"], 8091)
        self.assertNotIn("vulnerabilities", f.raw["host"])


# --------------------------------------------------------------------------
# Issue 1: Nuclei parse-thread exceptions must not be swallowed
# --------------------------------------------------------------------------
class NucleiSchemaTests(unittest.TestCase):
    def test_info_string_schema_only_is_failed(self):
        # valid JSON object but info is a string -> _to_finding() raises; the
        # record must be counted invalid, not silently succeed.
        bad = json.dumps({"template-id": "x", "info": "not-an-object"})
        r, sid = run_single(ScriptedNuclei(line_script(bad)))
        st = r.get_status(sid)
        self.assertEqual(st["status"], ScanStatus.FAILED.value)
        self.assertEqual(st["evidence"]["parsed_records"], 0)
        self.assertGreaterEqual(st["evidence"]["invalid_records"], 1)

    def test_mixed_valid_and_schema_error_is_cww(self):
        good = json.dumps({"template-id": "ok", "info": {"severity": "low"}})
        bad = json.dumps({"template-id": "x", "info": "not-an-object"})
        r, sid = run_single(ScriptedNuclei(line_script(good, bad)))
        st = r.get_status(sid)
        self.assertEqual(st["status"], ScanStatus.COMPLETED_WITH_WARNINGS.value)
        self.assertEqual(st["evidence"]["parsed_records"], 1)
        self.assertEqual(st["evidence"]["invalid_records"], 1)

    def test_callback_exception_is_counted_invalid_not_swallowed(self):
        good = json.dumps({"template-id": "ok", "info": {"severity": "low"}})
        scanner = ScriptedNuclei(line_script(good))

        def boom(_f):
            raise ValueError("callback boom")

        outcome = scanner.run(Target(LOCAL), ScanConfig(), boom)
        # parsed_records only counts convert+deliver success
        self.assertEqual(outcome.parsed_records, 0)
        self.assertGreaterEqual(outcome.invalid_records, 1)
        self.assertTrue(outcome.fatal)  # nothing usable -> fatal


# --------------------------------------------------------------------------
# Issue 2: Nikto schema validation
# --------------------------------------------------------------------------
class NiktoSchemaTests(unittest.TestCase):
    def _parse(self, doc):
        findings = []
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nikto.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(doc if isinstance(doc, str) else json.dumps(doc))
            res = NiktoScanner()._parse_file(path, LOCAL, findings.append, lambda _: None)
        return res, findings

    def test_missing_vulnerabilities_field_is_fatal(self):
        res, _ = self._parse([{"host": "127.0.0.1"}])
        self.assertTrue(res["fatal"])

    def test_vulnerabilities_not_a_list_is_fatal(self):
        res, _ = self._parse([{"host": "127.0.0.1", "vulnerabilities": "oops"}])
        self.assertTrue(res["fatal"])

    def test_non_object_vuln_is_invalid_not_fatal(self):
        res, findings = self._parse(
            [{"host": "127.0.0.1", "vulnerabilities": ["oops"]}]
        )
        self.assertFalse(res["fatal"])
        self.assertEqual(res["parsed_records"], 0)
        self.assertEqual(res["invalid_records"], 1)
        self.assertEqual(findings, [])

    def test_zero_vulns_is_ok(self):
        res, findings = self._parse([{"host": "127.0.0.1", "vulnerabilities": []}])
        self.assertFalse(res["fatal"])
        self.assertEqual(res["parsed_records"], 0)
        self.assertEqual(findings, [])

    def test_vulns_compat_field_is_accepted(self):
        res, findings = self._parse(
            [{"host": "127.0.0.1", "vulns": [{"id": "1", "msg": "x", "url": "/a"}]}]
        )
        self.assertFalse(res["fatal"])
        self.assertEqual(res["parsed_records"], 1)


# --------------------------------------------------------------------------
# Issue 3: stop must kill the scanner's whole process group
# --------------------------------------------------------------------------
GRANDCHILD_SCRIPT = (
    "import subprocess, time\n"
    "p = subprocess.Popen(['sleep', '300'])\n"
    "open({pidfile!r}, 'w').write(str(p.pid))\n"
    "time.sleep(300)\n"
)


class ScriptedNikto(NiktoScanner):
    def __init__(self, script):
        super().__init__(binary=sys.executable)
        self._script = script

    def _build_command(self, target, config, output_path):
        return [sys.executable, "-c", self._script]


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class ProcessGroupStopTests(unittest.TestCase):
    def _assert_stop_kills_grandchild(self, make_scanner):
        with tempfile.TemporaryDirectory() as d:
            pidfile = os.path.join(d, "gc.pid")
            scanner = make_scanner(GRANDCHILD_SCRIPT.format(pidfile=pidfile))
            stop_event = threading.Event()
            done = threading.Event()

            def go():
                scanner.run(Target(LOCAL), ScanConfig(), lambda _: None, stop_event)
                done.set()

            threading.Thread(target=go, daemon=True).start()
            txt = ""
            for _ in range(250):
                try:
                    with open(pidfile) as fh:
                        txt = fh.read().strip()
                    if txt:
                        break
                except OSError:
                    pass
                time.sleep(0.02)
            gpid = int(txt)
            self.assertTrue(_alive(gpid), "grandchild should be running")

            stop_event.set()
            self.assertTrue(done.wait(10), "run() did not return after stop")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and _alive(gpid):
                time.sleep(0.05)
            self.assertFalse(_alive(gpid), "grandchild survived stop")

    def test_nuclei_stop_kills_grandchild(self):
        self._assert_stop_kills_grandchild(ScriptedNuclei)

    def test_nikto_stop_kills_grandchild(self):
        self._assert_stop_kills_grandchild(ScriptedNikto)


# --------------------------------------------------------------------------
# Issue 4 & 5: group timeout deadline + start atomicity
# --------------------------------------------------------------------------
class DeafScanner(Scanner):
    """Ignores stop entirely and runs for a bounded time."""

    def __init__(self, name):
        self.name = name
        self.entered = threading.Event()

    def is_available(self):
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        self.entered.set()
        time.sleep(4)
        return ok_outcome(parsed_records=0)


class MultiTimeoutAtomicityTests(unittest.TestCase):
    def test_group_timeout_with_uncooperative_scanners_is_bounded(self):
        a, b = DeafScanner("a"), DeafScanner("b")
        runner = MultiScanRunner([a, b])
        sid = runner.start_scan(Target(LOCAL))
        self.assertTrue(a.entered.wait(2))
        self.assertTrue(b.entered.wait(2))
        start = time.monotonic()
        runner.wait(sid, timeout=0.1)
        elapsed = time.monotonic() - start
        # must not balloon to 5s (per-child grace) or 10s (two children)
        self.assertLess(elapsed, 4.0, f"timeout grace not shared, took {elapsed:.2f}s")
        # scanners that ignore stop stay RUNNING, not falsely STOPPED
        self.assertEqual(runner.get_status(sid)["status"], ScanStatus.RUNNING.value)

    def test_start_scan_failure_rolls_back_started_children(self):
        good = StopOutcomeScanner("good")   # blocks until stopped
        other = OutcomeScanner("other", ok_outcome())
        runner = MultiScanRunner([good, other])

        def boom(*a, **k):
            raise RuntimeError("start_scan failed")

        runner._runners["other"].start_scan = boom
        with self.assertRaises(RuntimeError):
            runner.start_scan(Target(LOCAL))

        # the already-started 'good' child must be stopped, not orphaned
        good_scans = runner._runners["good"].list_scans()
        self.assertEqual(len(good_scans), 1)
        self.assertEqual(good_scans[0]["status"], ScanStatus.STOPPED.value)


if __name__ == "__main__":
    unittest.main()
