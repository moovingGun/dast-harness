import json
import os
import tempfile
import unittest

from dast_harness import NiktoScanner, ScanConfig, Severity, Target

# Shape confirmed against Nikto 2.6.1 JSON output.
SAMPLE_OUTPUT = [
    {
        "host": "127.0.0.1",
        "ip": "127.0.0.1",
        "port": 8091,
        "vulnerabilities": [
            {
                "id": "600720",
                "method": "HEAD",
                "msg": "SimpleHTTP/0.6 appears to be outdated.",
                "references": "",
                "url": "/",
            },
            {
                "id": "013587",
                "method": "GET",
                "msg": "Suggested security header missing: x-content-type-options.",
                "references": "https://developer.mozilla.org/",
                "url": "/",
            },
        ],
    }
]


class NiktoScannerTests(unittest.TestCase):
    def test_builds_command(self) -> None:
        command = NiktoScanner()._build_command(
            Target("http://127.0.0.1:8091"), ScanConfig(request_timeout=5), "/tmp/o.json"
        )
        self.assertIn("-h", command)
        self.assertIn("http://127.0.0.1:8091", command)
        self.assertIn("-Format", command)
        self.assertIn("json", command)
        self.assertIn("-output", command)
        self.assertIn("/tmp/o.json", command)
        self.assertIn("5", command)  # request_timeout -> -timeout

    def test_parses_findings_with_unknown_severity(self) -> None:
        scanner = NiktoScanner()
        findings = []
        warnings = []
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nikto.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(SAMPLE_OUTPUT, fh)
            scanner._parse_output(
                path, "http://127.0.0.1:8091", findings.append, warnings.append
            )

        self.assertEqual(len(findings), 2)
        self.assertEqual(warnings, [])
        self.assertEqual(findings[0].scanner, "nikto")
        self.assertEqual(findings[0].finding_id, "600720")
        # Nikto has no severities -> everything is UNKNOWN.
        self.assertTrue(all(f.severity is Severity.UNKNOWN for f in findings))
        self.assertEqual(findings[0].matched_at, "http://127.0.0.1:8091/")

    def test_empty_output_is_not_a_finding_or_warning(self) -> None:
        scanner = NiktoScanner()
        findings, warnings = [], []
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nikto.json")
            open(path, "w").close()  # empty file
            scanner._parse_output(path, "http://127.0.0.1", findings.append, warnings.append)
        self.assertEqual(findings, [])
        self.assertEqual(warnings, [])

    def test_invalid_json_warns_without_crashing(self) -> None:
        scanner = NiktoScanner()
        findings, warnings = [], []
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nikto.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("not json")
            scanner._parse_output(path, "http://127.0.0.1", findings.append, warnings.append)
        self.assertEqual(findings, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn("invalid JSON", warnings[0])

    def test_missing_output_file_warns(self) -> None:
        scanner = NiktoScanner()
        findings, warnings = [], []
        scanner._parse_output(
            "/nonexistent/nikto.json", "http://127.0.0.1", findings.append, warnings.append
        )
        self.assertEqual(findings, [])
        self.assertEqual(len(warnings), 1)


if __name__ == "__main__":
    unittest.main()
