"""Detection-accuracy scoring: findings vs. the target's ground truth."""

import contextlib
import io
import json
import os
import tempfile
import unittest

from dast_harness import Finding, ScanOutcome, Severity
from dast_harness import cli, validate
from dast_harness.scanners.base import Scanner


def _entry(id_, path, match_any, category="exposure"):
    return {
        "id": id_,
        "path": path,
        "category": category,
        "description": id_,
        "match_any": match_any,
    }


EXPECTED = [
    _entry("exposed-dotenv", "/.env", ["dotenv", ".env"]),
    _entry("phpinfo-disclosure", "/phpinfo.php", ["phpinfo"]),
    _entry("directory-listing", "/uploads/", ["directory listing"],
           category="misconfiguration"),
]


def _finding(name, *, finding_id="tpl", scanner="nuclei",
             severity=Severity.INFO, path="/", matched_at=None):
    # A finding now credits an entry only when it was observed at that entry's
    # path, so every test has to say where the finding came from.
    return Finding(scanner=scanner, finding_id=finding_id, name=name,
                   severity=severity,
                   matched_at=matched_at or f"http://127.0.0.1:8080{path}")


class ScoreTest(unittest.TestCase):
    def test_keyword_match_is_case_insensitive(self):
        report = validate.score([_finding("Exposed DOTENV file", path="/.env")], EXPECTED)
        detected = {e.id: e.detected for e in report.entries}
        self.assertTrue(detected["exposed-dotenv"])
        self.assertFalse(detected["phpinfo-disclosure"])

    def test_matches_on_finding_id_too(self):
        report = validate.score(
            [_finding("Config exposure", finding_id="phpinfo-files", path="/phpinfo.php")], EXPECTED)
        self.assertTrue({e.id: e.detected for e in report.entries}["phpinfo-disclosure"])

    def test_recall_counts_distinct_entries(self):
        report = validate.score([], EXPECTED)
        self.assertEqual(report.detected_count, 0)
        self.assertEqual(report.recall, 0.0)

        findings = [_finding("dotenv exposure", path="/.env"),
                    _finding("phpinfo() page", path="/phpinfo.php"),
                    _finding("Directory listing enabled", path="/uploads/")]
        report = validate.score(findings, EXPECTED)
        self.assertEqual(report.detected_count, 3)
        self.assertEqual(report.recall, 1.0)

    def test_duplicate_findings_do_not_inflate_recall(self):
        findings = [_finding("dotenv exposure", path="/.env"),
                    _finding("Exposed .env file", path="/.env")]
        report = validate.score(findings, EXPECTED)
        self.assertEqual(report.detected_count, 1)
        self.assertEqual(len(report.unexpected), 0)

    def test_a_finding_credits_only_its_most_specific_entry(self):
        expected = EXPECTED + [_entry("generic-exposure", "/", ["exposure"])]
        report = validate.score([_finding("dotenv exposure", path="/.env")], expected)
        detected = {e.id: e.detected for e in report.entries}
        self.assertTrue(detected["exposed-dotenv"])   # listed first = more specific
        self.assertFalse(detected["generic-exposure"])

    def test_unmatched_findings_are_reported_as_unexpected(self):
        noise = _finding("robots.txt endpoint prober", scanner="nikto",
                         severity=Severity.MEDIUM,
                         matched_at="http://127.0.0.1:8080/robots.txt")
        report = validate.score([_finding("dotenv exposure", path="/.env"), noise], EXPECTED)
        self.assertEqual(len(report.unexpected), 1)
        self.assertEqual(report.unexpected[0].name, noise.name)
        # Unexpected findings are not auto-labelled false positives; the report
        # only groups them so a human can triage.
        self.assertEqual(report.unexpected_by_severity()["medium"], 1)

    def test_entry_records_which_scanner_detected_it(self):
        report = validate.score(
            [_finding("dotenv exposure", scanner="nuclei", path="/.env"),
             _finding("dotenv file found", scanner="nikto", path="/.env")], EXPECTED)
        entry = {e.id: e for e in report.entries}["exposed-dotenv"]
        self.assertEqual(sorted(entry.scanners), ["nikto", "nuclei"])
        self.assertEqual(len(entry.findings), 2)

    def test_report_serializes_to_json(self):
        report = validate.score([_finding("phpinfo() page", path="/phpinfo.php")], EXPECTED)
        data = json.loads(json.dumps(report.to_dict()))
        self.assertEqual(data["recall"], round(1 / 3, 4))
        self.assertEqual(data["expected_count"], 3)
        self.assertEqual(len(data["entries"]), 3)

    def test_render_shows_misses_and_recall(self):
        text = validate.render(validate.score([_finding("phpinfo() page", path="/phpinfo.php")], EXPECTED))
        self.assertIn("phpinfo-disclosure", text)
        self.assertIn("exposed-dotenv", text)
        self.assertIn("1/3", text)


class PathMatchTest(unittest.TestCase):
    """A finding credits an entry only if it was seen at that entry's path."""

    def test_right_keyword_at_the_wrong_path_does_not_count(self):
        # Real regression: nuclei fired its `chamilo-lms-sqli` template at
        # /main/inc/ajax/extra_field.ajax.php — a path this target does not
        # serve — and keyword matching credited it to the documented /search
        # SQL injection, because both strings contain "sqli". Recall read 90%
        # when the scanners had not found that weakness at all.
        expected = [_entry("sqli-error-based-search-q", "/search",
                           ["sqli", "sql injection"], category="injection")]
        stray = _finding("Chamilo 1.11.14 - SQL Injection",
                         finding_id="chamilo-lms-sqli",
                         path="/main/inc/ajax/extra_field.ajax.php")
        report = validate.score([stray], expected)
        self.assertEqual([e.id for e in report.entries if e.detected], [])
        self.assertEqual(len(report.unexpected), 1)

    def test_the_same_keyword_at_the_documented_path_counts(self):
        expected = [_entry("sqli-error-based-search-q", "/search",
                           ["sqli"], category="injection")]
        real = _finding("SQL injection in q", finding_id="sqli-error-based-q",
                        path="/search")
        report = validate.score([real], expected)
        self.assertEqual([e.id for e in report.entries if e.detected],
                         ["sqli-error-based-search-q"])

    def test_a_directory_entry_covers_paths_below_it(self):
        expected = [_entry("directory-listing", "/uploads/", ["listing"],
                           category="misconfiguration")]
        found = _finding("Directory listing enabled", path="/uploads/2024/")
        report = validate.score([found], expected)
        self.assertTrue(report.entries[0].detected)

    def test_query_strings_do_not_break_the_path_check(self):
        expected = [_entry("sqli", "/search", ["sqli"], category="injection")]
        found = _finding("sqli", path="/search")
        found = Finding(scanner="a", finding_id="sqli", name="sqli",
                        severity=Severity.INFO,
                        matched_at="http://127.0.0.1:8080/search?q=x%27")
        report = validate.score([found], expected)
        self.assertTrue(report.entries[0].detected)


class LoadGroundTruthTest(unittest.TestCase):
    def _write(self, payload):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(payload, fh)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_loads_expected_entries(self):
        path = self._write({"target": "http://127.0.0.1:8080", "expected": EXPECTED})
        truth = validate.load_ground_truth(path)
        self.assertEqual(truth.target, "http://127.0.0.1:8080")
        self.assertEqual(len(truth.expected), 3)

    def test_rejects_entry_missing_required_keys(self):
        path = self._write({"target": "http://x", "expected": [{"id": "a"}]})
        with self.assertRaises(ValueError):
            validate.load_ground_truth(path)

    def test_rejects_file_without_expected_list(self):
        path = self._write({"target": "http://x"})
        with self.assertRaises(ValueError):
            validate.load_ground_truth(path)

    def test_repo_ground_truth_file_loads(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        truth = validate.load_ground_truth(
            os.path.join(root, "targets", "vulnerable_app", "ground_truth.json"))
        self.assertGreaterEqual(len(truth.expected), 5)


class FakeScanner(Scanner):
    """Reports one finding per ground-truth entry it is told to detect.

    `detects` maps keyword -> the path the finding was observed at. Both halves
    matter now: scoring requires the keyword *and* the location, so a fake that
    reports the right words at the wrong URL is correctly scored as a miss.
    """

    name = "fake"
    detects = {"dotenv": "/.env"}

    def is_available(self):
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        for keyword, path in self.detects.items():
            on_finding(Finding(self.name, f"{keyword}-tpl", f"{keyword} exposure",
                               Severity.HIGH, target.url.rstrip("/") + path))
        return ScanOutcome(exit_code=0, output_present=True, output_parseable=True,
                           parsed_records=len(self.detects))


class ValidateCliTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(setattr, cli, "SCANNERS", cli.SCANNERS)
        cli.SCANNERS = {"fake": FakeScanner}
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"target": "http://127.0.0.1:8080", "expected": EXPECTED}, fh)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        self.truth_path = fh.name

    def _run(self, *extra):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = validate.main(["--ground-truth", self.truth_path, *extra])
        return code, out.getvalue()

    def test_partial_detection_exits_nonzero(self):
        code, text = self._run()
        self.assertEqual(code, validate.EXIT_MISSED)
        self.assertIn("1/3", text)

    def test_full_detection_exits_zero(self):
        FakeScanner.detects = {"dotenv": "/.env", "phpinfo": "/phpinfo.php",
                               "directory listing": "/uploads/"}
        self.addCleanup(setattr, FakeScanner, "detects", {"dotenv": "/.env"})
        code, text = self._run()
        self.assertEqual(code, validate.EXIT_OK)
        self.assertIn("3/3", text)

    def test_json_output(self):
        code, text = self._run("--json")
        self.assertEqual(code, validate.EXIT_MISSED)
        data = json.loads(text)
        self.assertEqual(data["expected_count"], 3)
        self.assertEqual(data["target"], "http://127.0.0.1:8080")

    def test_non_loopback_target_is_refused(self):
        code, _ = self._run("--target", "http://example.com")
        self.assertEqual(code, validate.EXIT_USAGE)

    def test_unknown_scanner_is_refused(self):
        code, _ = self._run("--scanner", "nope")
        self.assertEqual(code, validate.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()


TRAPS = [
    {
        "id": "lookup-not-injectable",
        "path": "/lookup",
        "category": "injection",
        "description": "sound endpoint that looks injectable",
        "match_any": ["sqli", "sql injection", "injection"],
    }
]

INJECTABLE = [
    _entry("sqli-error-based-search-q", "/search", ["sqli", "sql injection"],
           category="injection"),
]


class FalsePositiveTest(unittest.TestCase):
    """`must_not_detect` endpoints are documented as sound. Reporting one is
    wrong, and must not be scored as a detection of something else."""

    def test_a_finding_on_a_trap_endpoint_is_a_false_positive(self):
        finding = _finding("SQL injection", finding_id="sql-injection-in-q",
                           matched_at="http://127.0.0.1:8080/lookup?q=x")
        report = validate.score([finding], INJECTABLE, must_not_detect=TRAPS)
        self.assertEqual([f.finding_id for f in report.false_positives],
                         ["sql-injection-in-q"])

    def test_a_trap_finding_is_not_credited_to_a_real_entry(self):
        # The regression this exists for: keyword matching alone credited an
        # injection report at the sound /lookup to the real /search SQLi, so the
        # trap rewarded exactly what it was written to catch.
        finding = _finding("SQL injection", finding_id="sql-injection-in-q",
                           matched_at="http://127.0.0.1:8080/lookup?q=x")
        report = validate.score([finding], INJECTABLE, must_not_detect=TRAPS)
        self.assertEqual([e.id for e in report.entries if e.detected], [])
        self.assertEqual(report.recall, 0.0)

    def test_the_same_keywords_at_the_documented_path_still_count(self):
        finding = _finding("SQL injection", finding_id="sqli-error",
                           matched_at="http://127.0.0.1:8080/search?q=x")
        report = validate.score([finding], INJECTABLE, must_not_detect=TRAPS)
        self.assertEqual(report.false_positives, [])
        self.assertEqual([e.id for e in report.entries if e.detected],
                         ["sqli-error-based-search-q"])

    def test_a_trap_path_finding_with_other_keywords_is_not_a_false_positive(self):
        # Being *at* the endpoint is not the offence; claiming the documented
        # weakness class there is.
        finding = _finding("Missing security header", finding_id="headers",
                           matched_at="http://127.0.0.1:8080/lookup")
        report = validate.score([finding], INJECTABLE, must_not_detect=TRAPS)
        self.assertEqual(report.false_positives, [])
        self.assertEqual(len(report.unexpected), 1)

    def test_false_positives_fail_the_run(self):
        finding = _finding("SQL injection", finding_id="sqli",
                           matched_at="http://127.0.0.1:8080/lookup")
        report = validate.score([finding], INJECTABLE, must_not_detect=TRAPS)
        self.assertTrue(report.false_positives)
        self.assertIn("FALSE POSITIVES", validate.render(report))

    def test_directory_entries_cover_paths_below_them(self):
        traps = [{"id": "uploads-fine", "path": "/uploads/",
                  "match_any": ["listing"]}]
        finding = _finding("directory listing", finding_id="dir",
                           matched_at="http://127.0.0.1:8080/uploads/sub/x")
        report = validate.score([finding], [], must_not_detect=traps)
        self.assertEqual(len(report.false_positives), 1)


AUTHED = [
    dict(_entry("idor-order", "/api/orders/1002", ["idor"], category="idor"),
         as_actor="alice"),
]


class NotAttemptedTest(unittest.TestCase):
    """"안 찾아봄"과 "못 찾음"은 다르다. A weakness that needs a session nobody
    had is a setup gap, not a detection failure."""

    def test_entry_needing_an_actor_without_a_session_is_not_attempted(self):
        report = validate.score([], AUTHED)
        self.assertEqual([e.id for e in report.not_attempted()], ["idor-order"])
        self.assertEqual(report.missed(), [])

    def test_not_attempted_entries_are_excluded_from_recall(self):
        # Folding them in would read as "the agent failed" when the run never
        # gave it a chance.
        entries = AUTHED + [_entry("exposed-dotenv", "/.env", ["dotenv"])]
        found = _finding("dotenv", finding_id="dotenv",
                         matched_at="http://127.0.0.1:8080/.env")
        report = validate.score([found], entries)
        self.assertEqual(len(report.attempted), 1)
        self.assertEqual(report.recall, 1.0)
        self.assertIn("not attempted", validate.render(report))

    def test_a_live_session_makes_it_attempted(self):
        report = validate.score([], AUTHED, actors=frozenset({"alice"}))
        self.assertEqual(report.not_attempted(), [])
        self.assertEqual([e.id for e in report.missed()], ["idor-order"])

    def test_detection_beats_the_actor_bookkeeping(self):
        # If it was found, it was obviously attempted, whatever we think we know
        # about sessions.
        found = _finding("idor", finding_id="idor",
                         matched_at="http://127.0.0.1:8080/api/orders/1002")
        report = validate.score([found], AUTHED)
        self.assertEqual(report.not_attempted(), [])
        self.assertEqual(report.recall, 1.0)


class IngestScoringTest(unittest.TestCase):
    """`--ingest` grades a result a subagent already produced."""

    def setUp(self):
        truth = {"target": "http://127.0.0.1:8080",
                 "expected": INJECTABLE + AUTHED, "must_not_detect": TRAPS}
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(truth, fh)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        self.truth_path = fh.name

    def _result_file(self, findings):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"agent": "idor", "findings": findings,
                   "coverage": {"unit": "object-id", "tested": len(findings)},
                   "completion": {"requests_made": 3}}, fh, ensure_ascii=False)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    @staticmethod
    def _agent_finding(finding_id, name, category, matched_at, actor="alice"):
        exchange = {"method": "GET", "url": matched_at, "status": 200,
                    "actor": actor, "response_excerpt": "x"}
        return {
            "scanner": "agent:idor", "id": finding_id, "name": name,
            "severity": "high", "confidence": "confirmed", "category": category,
            "matched_at": matched_at, "description": "d", "tags": [],
            "evidence": {"baseline_index": 0, "rationale": "r",
                         "exchanges": [exchange]},
            "agent_data": {"idor": {"strategy": "s", "target": "id",
                                    "target_kind": "object-id"}},
        }

    def _run(self, path, *extra):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = validate.main(["--ground-truth", self.truth_path,
                                  "--ingest", path, *extra])
        return code, out.getvalue()

    def test_a_correct_agent_result_scores_a_detection(self):
        path = self._result_file([self._agent_finding(
            "idor-order-object-access", "ownership missing", "idor",
            "http://127.0.0.1:8080/api/orders/1002")])
        code, text = self._run(path)
        self.assertIn("[x] idor-order", text)
        self.assertEqual(code, validate.EXIT_MISSED)   # the /search SQLi is still missed

    def test_evidence_actors_decide_what_was_attempted(self):
        # A saved result has no live session to ask, so the exchanges are the
        # only honest source for "could this even be tried".
        path = self._result_file([self._agent_finding(
            "sqli-error", "sql injection", "injection",
            "http://127.0.0.1:8080/search?q=x", actor="alice")])
        _, text = self._run(path)
        self.assertNotIn("NOT ATTEMPTED", text)

    def test_a_trap_finding_is_scored_as_a_false_positive(self):
        path = self._result_file([self._agent_finding(
            "sql-injection-in-lookup", "sql injection", "injection",
            "http://127.0.0.1:8080/lookup?q=x")])
        code, text = self._run(path)
        self.assertIn("FALSE POSITIVES", text)
        self.assertEqual(code, validate.EXIT_MISSED)

    def test_a_result_failing_the_contract_is_not_scored(self):
        # Grading a malformed finding would report accuracy for something the
        # harness would never have accepted in the first place.
        bad = self._agent_finding("x", "n", "idor",
                                  "http://127.0.0.1:8080/api/orders/1002")
        bad["scanner"] = "idor"            # missing the agent: prefix
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, text = self._run(self._result_file([bad]))
        self.assertEqual(code, validate.EXIT_USAGE)
        self.assertEqual(text, "")
        self.assertIn("agent:", err.getvalue())

    def test_ingest_and_scanner_selection_are_mutually_exclusive(self):
        path = self._result_file([])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, _ = self._run(path, "-s", "fake")
        self.assertEqual(code, validate.EXIT_USAGE)
