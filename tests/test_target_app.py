"""Contract for the controlled vulnerable target (targets/vulnerable_app).

The app and ground_truth.json must not drift: every documented weakness has to
be observably served, because step 3 scores scanner accuracy against that file.
Runs in-process on an ephemeral port — no Docker needed.
"""

import json
import os
import re
import sys
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "targets"))

from vulnerable_app import app as vulnapp  # noqa: E402

TARGET_DIR = os.path.join(ROOT, "targets", "vulnerable_app")
GROUND_TRUTH = os.path.join(TARGET_DIR, "ground_truth.json")


class QuietHandler(vulnapp.Handler):
    def log_message(self, *args):  # keep the test output readable
        pass


def _fetch(base, path):
    with urllib.request.urlopen(base + path, timeout=5) as resp:
        return resp.status, resp.headers, resp.read().decode("utf-8", "replace")


class VulnerableAppTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]
        with open(GROUND_TRUTH, encoding="utf-8") as fh:
            cls.truth = json.load(fh)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_binds_loopback_by_default(self):
        # The target is deliberately vulnerable: it must not listen on 0.0.0.0
        # unless a container entrypoint asks for it explicitly.
        self.assertEqual(vulnapp.DEFAULT_HOST, "127.0.0.1")

    def test_ground_truth_entries_are_well_formed(self):
        entries = self.truth["expected"]
        self.assertGreaterEqual(len(entries), 5)
        ids = [e["id"] for e in entries]
        self.assertEqual(len(ids), len(set(ids)), "duplicate ground truth ids")
        for entry in entries:
            with self.subTest(id=entry["id"]):
                for key in ("id", "path", "category", "description", "match_any"):
                    self.assertIn(key, entry)
                self.assertTrue(entry["path"].startswith("/"))
                self.assertTrue(entry["match_any"])
                self.assertTrue(all(m == m.lower() for m in entry["match_any"]))

    def test_every_documented_weakness_is_actually_served(self):
        for entry in self.truth["expected"]:
            with self.subTest(id=entry["id"]):
                status, headers, body = _fetch(self.base, entry["path"])
                self.assertEqual(status, 200)
                if entry.get("body_contains"):
                    self.assertIn(entry["body_contains"], body)
                for header in entry.get("absent_headers", []):
                    self.assertIsNone(
                        headers.get(header),
                        f"{header} is present, so {entry['id']} is not observable",
                    )

    def test_directory_listing_is_enabled(self):
        _, _, body = _fetch(self.base, "/uploads/")
        self.assertIn("Index of /uploads", body)

    def test_unknown_path_is_not_a_finding(self):
        # A 404 on random paths keeps false positives attributable to the
        # scanner, not to a catch-all handler that answers everything.
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            _fetch(self.base, "/no-such-page-4c1f")
        self.assertEqual(ctx.exception.code, 404)
        ctx.exception.close()


class ContainerConfigTest(unittest.TestCase):
    """The target is vulnerable on purpose, so its container must stay
    reachable only from loopback on the host."""

    def test_compose_publishes_on_loopback_only(self):
        with open(os.path.join(ROOT, "targets", "compose.yml"), encoding="utf-8") as fh:
            compose = fh.read()
        published = re.findall(r'^\s*-\s*"?([^"\s]+:\d+:\d+)"?\s*$', compose, re.M)
        self.assertTrue(published, "compose.yml publishes no port")
        for mapping in published:
            self.assertTrue(
                mapping.startswith("127.0.0.1:"),
                f"{mapping} would expose the vulnerable target beyond loopback",
            )

    def test_dockerfile_serves_on_all_interfaces_inside_the_container(self):
        with open(os.path.join(TARGET_DIR, "Dockerfile"), encoding="utf-8") as fh:
            dockerfile = fh.read()
        self.assertIn("--host", dockerfile)
        self.assertIn("0.0.0.0", dockerfile)  # container-internal; compose gates it


if __name__ == "__main__":
    unittest.main()
