"""ffuf adapter — content discovery inside the safety boundary.

Parsing is tested against canned ffuf JSON so the suite needs no ffuf binary.
The command-building tests pin two invariants that were decided by measurement,
not preference; if someone "optimizes" them back, these fail.
"""

import json
import os
import tempfile
import unittest

from dast_harness.models import ScanConfig, Severity, Target
from dast_harness.scanners.ffuf import FfufScanner

BASE = "http://127.0.0.1:8080"


def _result(fuzz, status=200, length=42, url=None):
    return {
        "input": {"FFUFHASH": "abc123", "FUZZ": fuzz},
        "url": url if url is not None else f"{BASE}/{fuzz}",
        "status": status,
        "length": length,
    }


class _Sink:
    def __init__(self):
        self.findings = []
        self.warnings = []


def _wordlist(entries):
    fh = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    fh.write("\n".join(entries) + "\n")
    fh.close()
    return fh.name


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.scanner = FfufScanner(wordlist=_wordlist([".env", "admin"]))
        self.addCleanup(os.unlink, self.scanner.wordlist)

    def _cmd(self, config=None):
        return self.scanner._build_command(Target(BASE), config or ScanConfig(),
                                           "/tmp/out.json")

    def test_never_follows_redirects(self):
        # Safety invariant for the whole repo: a redirect can walk a scan onto a
        # host nobody authorized. ffuf's `-r` must never appear.
        self.assertNotIn("-r", self._cmd())

    def test_auto_calibration_stays_off(self):
        # Measured, not preferred: with `-ac` the same target gave a different
        # answer on every run (/.env and /.git/config vanished at random) and
        # calibration probes leaked into results. Without it, 6/6 runs matched.
        # A silently dropped finding reads as "not vulnerable"; a soft-404 flood
        # is obvious. See _parse_file for how the loud case is surfaced.
        self.assertNotIn("-ac", self._cmd())

    def test_fuzzes_the_path_under_the_target(self):
        cmd = self._cmd()
        self.assertIn(f"{BASE}/FUZZ", cmd)

    def test_target_with_trailing_slash_does_not_double_up(self):
        cmd = self.scanner._build_command(Target(BASE + "/"), ScanConfig(), "/tmp/o")
        self.assertIn(f"{BASE}/FUZZ", cmd)

    def test_thread_default_is_conservative(self):
        # 10 threads made the target drop requests, losing findings with no
        # warning. Speed is not the constraint here — 113 words take 0.14s.
        cmd = self._cmd()
        self.assertLessEqual(int(cmd[cmd.index("-t") + 1]), 5)

    def test_rate_limit_and_timeout_pass_through(self):
        cmd = self._cmd(ScanConfig(rate_limit=7, request_timeout=3))
        self.assertEqual(cmd[cmd.index("-rate") + 1], "7")
        self.assertEqual(cmd[cmd.index("-timeout") + 1], "3")

    def test_unavailable_without_a_wordlist(self):
        scanner = FfufScanner(wordlist="/nonexistent/words.txt")
        self.assertFalse(scanner.is_available())


class ParseTests(unittest.TestCase):
    def setUp(self):
        self.scanner = FfufScanner(wordlist=_wordlist([".env", "admin", "backup.sql"]))
        self.addCleanup(os.unlink, self.scanner.wordlist)

    def _parse(self, payload):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8")
        json.dump(payload, fh)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        sink = _Sink()
        out = self.scanner._parse_file(fh.name, BASE, sink.findings.append,
                                       sink.warnings.append)
        return out, sink

    def test_results_become_findings(self):
        out, sink = self._parse({"results": [_result(".env"), _result("admin")]})
        self.assertFalse(out["fatal"])
        self.assertEqual(out["parsed_records"], 2)
        self.assertEqual([f.finding_id for f in sink.findings],
                         ["content-discovery/.env", "content-discovery/admin"])

    def test_the_path_comes_from_the_url_not_the_fuzz_input(self):
        # Regression: ffuf emitted a record whose input.FUZZ and url disagreed
        # (FUZZ=".htaccessKcSMtePO", url=".../.env"), which produced a finding
        # whose id pointed at one path and whose location pointed at another.
        # The URL is what was actually requested and matched.
        out, sink = self._parse({"results": [_result(".env", url=f"{BASE}/.env")]})
        finding = sink.findings[0]
        self.assertEqual(finding.finding_id, "content-discovery/.env")
        self.assertTrue(finding.matched_at.endswith("/.env"))

    def test_a_path_we_never_asked_for_is_dropped(self):
        # Auto-calibration probes are wordlist entries plus a random suffix.
        # Reporting one would invent an endpoint that does not exist.
        out, sink = self._parse({"results": [
            _result(".env"), _result(".htaccessKcSMtePO"),
        ]})
        self.assertEqual([f.finding_id for f in sink.findings],
                         ["content-discovery/.env"])
        self.assertEqual(out["invalid_records"], 1)
        self.assertTrue(any("never asked for" in w for w in sink.warnings))

    def test_soft_404_target_is_flagged_not_silently_filtered(self):
        # Everything matching means the target 200s on paths that don't exist.
        # We report it loudly rather than guessing which ones are real — that
        # judgement needs a human, and filtering would remove the evidence.
        out, sink = self._parse({"results": [
            _result(".env"), _result("admin"), _result("backup.sql"),
        ]})
        self.assertEqual(out["parsed_records"], 3)      # nothing was removed
        self.assertTrue(any("soft 404" in w for w in sink.warnings))

    def test_severity_is_not_invented(self):
        # ffuf says a path exists; how bad that is depends on what it is.
        _, sink = self._parse({"results": [_result(".env")]})
        self.assertEqual(sink.findings[0].severity, Severity.INFO)

    def test_status_and_size_reach_the_report(self):
        _, sink = self._parse({"results": [_result("admin", status=403, length=9)]})
        finding = sink.findings[0]
        self.assertIn("403", finding.description)
        self.assertIn("status-403", finding.tags)

    def test_empty_results_is_a_clean_run(self):
        out, sink = self._parse({"results": []})
        self.assertFalse(out["fatal"])
        self.assertEqual(sink.findings, [])

    def test_missing_results_field_is_fatal(self):
        out, _ = self._parse({"commandline": "ffuf ..."})
        self.assertTrue(out["fatal"])
        self.assertIn("results", out["error"])

    def test_non_object_entry_is_counted_and_skipped(self):
        out, sink = self._parse({"results": [_result(".env"), "nope"]})
        self.assertEqual(out["invalid_records"], 1)
        self.assertEqual(len(sink.findings), 1)

    def test_missing_file_is_fatal(self):
        sink = _Sink()
        out = self.scanner._parse_file("/nonexistent/ffuf.json", BASE,
                                       sink.findings.append, sink.warnings.append)
        self.assertTrue(out["fatal"])
        self.assertFalse(out["output_present"])

    def test_unparseable_file_is_fatal(self):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        fh.write("{not json")
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        sink = _Sink()
        out = self.scanner._parse_file(fh.name, BASE, sink.findings.append,
                                       sink.warnings.append)
        self.assertTrue(out["fatal"])
        self.assertTrue(out["output_present"])


if __name__ == "__main__":
    unittest.main()
