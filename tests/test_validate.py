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
             severity=Severity.INFO, matched_at="http://127.0.0.1:8080/"):
    return Finding(scanner=scanner, finding_id=finding_id, name=name,
                   severity=severity, matched_at=matched_at)


class ScoreTest(unittest.TestCase):
    def test_keyword_match_is_case_insensitive(self):
        report = validate.score([_finding("Exposed DOTENV file")], EXPECTED)
        detected = {e.id: e.detected for e in report.entries}
        self.assertTrue(detected["exposed-dotenv"])
        self.assertFalse(detected["phpinfo-disclosure"])

    def test_matches_on_finding_id_too(self):
        report = validate.score(
            [_finding("Config exposure", finding_id="phpinfo-files")], EXPECTED)
        self.assertTrue({e.id: e.detected for e in report.entries}["phpinfo-disclosure"])

    def test_recall_counts_distinct_entries(self):
        report = validate.score([], EXPECTED)
        self.assertEqual(report.detected_count, 0)
        self.assertEqual(report.recall, 0.0)

        findings = [_finding("dotenv exposure"), _finding("phpinfo() page"),
                    _finding("Directory listing enabled")]
        report = validate.score(findings, EXPECTED)
        self.assertEqual(report.detected_count, 3)
        self.assertEqual(report.recall, 1.0)

    def test_duplicate_findings_do_not_inflate_recall(self):
        findings = [_finding("dotenv exposure"), _finding("Exposed .env file")]
        report = validate.score(findings, EXPECTED)
        self.assertEqual(report.detected_count, 1)
        self.assertEqual(len(report.unexpected), 0)

    def test_a_finding_credits_only_its_most_specific_entry(self):
        expected = EXPECTED + [_entry("generic-exposure", "/", ["exposure"])]
        report = validate.score([_finding("dotenv exposure")], expected)
        detected = {e.id: e.detected for e in report.entries}
        self.assertTrue(detected["exposed-dotenv"])   # listed first = more specific
        self.assertFalse(detected["generic-exposure"])

    def test_unmatched_findings_are_reported_as_unexpected(self):
        noise = _finding("robots.txt endpoint prober", scanner="nikto",
                         severity=Severity.MEDIUM,
                         matched_at="http://127.0.0.1:8080/robots.txt")
        report = validate.score([_finding("dotenv exposure"), noise], EXPECTED)
        self.assertEqual(len(report.unexpected), 1)
        self.assertEqual(report.unexpected[0].name, noise.name)
        # Unexpected findings are not auto-labelled false positives; the report
        # only groups them so a human can triage.
        self.assertEqual(report.unexpected_by_severity()["medium"], 1)

    def test_entry_records_which_scanner_detected_it(self):
        report = validate.score(
            [_finding("dotenv exposure", scanner="nuclei"),
             _finding("dotenv file found", scanner="nikto")], EXPECTED)
        entry = {e.id: e for e in report.entries}["exposed-dotenv"]
        self.assertEqual(sorted(entry.scanners), ["nikto", "nuclei"])
        self.assertEqual(len(entry.findings), 2)

    def test_report_serializes_to_json(self):
        report = validate.score([_finding("phpinfo() page")], EXPECTED)
        data = json.loads(json.dumps(report.to_dict()))
        self.assertEqual(data["recall"], round(1 / 3, 4))
        self.assertEqual(data["expected_count"], 3)
        self.assertEqual(len(data["entries"]), 3)

    def test_render_shows_misses_and_recall(self):
        text = validate.render(validate.score([_finding("phpinfo() page")], EXPECTED))
        self.assertIn("phpinfo-disclosure", text)
        self.assertIn("exposed-dotenv", text)
        self.assertIn("1/3", text)


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
    """Reports one finding per ground-truth entry it is told to detect."""

    name = "fake"
    detects = ["dotenv"]

    def is_available(self):
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        for keyword in self.detects:
            on_finding(Finding(self.name, f"{keyword}-tpl", f"{keyword} exposure",
                               Severity.HIGH, target.url + keyword))
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
        FakeScanner.detects = ["dotenv", "phpinfo", "directory listing"]
        self.addCleanup(setattr, FakeScanner, "detects", ["dotenv"])
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
