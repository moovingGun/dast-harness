"""`dast-harness probe` — the one network tool a subagent is given.

The point of this command is that an LLM holding it cannot leave the authorized
scope, no matter what the target's response tells it to do. So most of these
tests are about what does *not* get sent.

Runs the real target in-process on an ephemeral port; no Docker, no fixtures.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "targets"))

from vulnerable_app import app as vulnapp  # noqa: E402

from dast_harness import cli  # noqa: E402
from dast_harness.probe import MAX_BATCH  # noqa: E402

ACTORS_FILE = os.path.join(ROOT, "targets", "vulnerable_app", "actors.json")


class QuietHandler(vulnapp.Handler):
    def log_message(self, *args):
        pass


class ProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def _probe(self, batch, *, auth=None, target=None, allow=None):
        """Run the subcommand the way a subagent's Bash call would."""
        argv = ["probe", "--target", target or self.base]
        if auth:
            argv += ["--auth", auth]
        for host in allow or []:
            argv += ["--allow", host]

        payload = batch if isinstance(batch, str) else json.dumps(batch)
        out, err = io.StringIO(), io.StringIO()
        stdin = sys.stdin
        sys.stdin = io.StringIO(payload)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(argv)
        finally:
            sys.stdin = stdin
        text = out.getvalue()
        return code, (json.loads(text) if text.strip() else None), err.getvalue()

    # ------------------------------------------------------------- happy path
    def test_batch_keeps_order_and_identities(self):
        # The unit a subagent actually works in: baseline / attack / control.
        code, result, _ = self._probe([
            {"url": f"{self.base}/api/orders/1001", "actor": "alice"},
            {"url": f"{self.base}/api/orders/1002", "actor": "alice"},
            {"url": f"{self.base}/api/orders/1002", "actor": "anon"},
        ], auth=ACTORS_FILE)
        self.assertEqual(code, 0)
        got = [(e["actor"], e["status"]) for e in result["exchanges"]]
        self.assertEqual(got, [("alice", 200), ("alice", 200), ("anon", 401)])
        # The anon control is what separates "IDOR" from "no auth at all".
        self.assertIn("alice@example.com", result["exchanges"][0]["response_excerpt"])
        self.assertIn("bob@example.com", result["exchanges"][1]["response_excerpt"])

    def test_a_single_object_does_not_need_wrapping(self):
        code, result, _ = self._probe({"url": f"{self.base}/"})
        self.assertEqual(code, 0)
        self.assertEqual(len(result["exchanges"]), 1)

    def test_sessions_survive_within_one_invocation(self):
        # This is why the command takes a batch: a process per request would
        # lose the cookie jar between them.
        code, result, _ = self._probe([
            {"url": f"{self.base}/api/orders/1001", "actor": "alice"},
            {"url": f"{self.base}/api/orders/1003", "actor": "alice"},
        ], auth=ACTORS_FILE)
        self.assertEqual(code, 0)
        self.assertEqual([e["status"] for e in result["exchanges"]], [200, 200])

    # ------------------------------------------------------- what is refused
    def test_off_target_url_is_blocked_and_stops_the_batch(self):
        # The prompt-injection case: the target's own response tells the agent
        # to fetch somewhere else.
        code, result, _ = self._probe([
            {"url": f"{self.base}/", "note": "fine"},
            {"url": "http://attacker.example/exfil", "note": "injected"},
            {"url": f"{self.base}/admin/", "note": "must not be sent"},
        ])
        self.assertEqual(code, 1)
        # Only the first request left the process.
        self.assertEqual([e["url"] for e in result["exchanges"]], [f"{self.base}/"])
        self.assertEqual(result["blocked"][0][0], "http://attacker.example/exfil")
        self.assertIn("attacker.example", result["error"])

    def test_unknown_actor_is_refused_before_anything_is_sent(self):
        # Silently downgrading a typo'd actor to anon would invert every IDOR
        # verdict that follows.
        code, result, _ = self._probe(
            [{"url": f"{self.base}/api/orders/1002", "actor": "alicee"}],
            auth=ACTORS_FILE)
        self.assertEqual(code, 1)
        self.assertEqual(result["exchanges"], [])
        self.assertIn("alicee", result["error"])

    def test_dead_session_stops_before_the_first_request(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "actors.json")
            with open(path, "w") as fh:
                json.dump({"actors": {"bob": {
                    "cookies": {"session": "expired"},
                    "verify": {"path": "/api/orders/1002",
                               "expect_status": 200}}}}, fh)
            code, result, err = self._probe(
                [{"url": f"{self.base}/api/orders/1002", "actor": "bob"}], auth=path)
        self.assertEqual(code, 1)
        self.assertEqual(result["exchanges"], [])
        self.assertIn("인증 실패", err)

    def test_unauthorized_target_refuses_the_whole_invocation(self):
        code, result, err = self._probe([{"url": "http://8.8.8.8/"}],
                                        target="http://8.8.8.8")
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertIn("not loopback", err)

    def test_batch_size_is_capped(self):
        batch = [{"url": f"{self.base}/"} for _ in range(MAX_BATCH + 1)]
        code, result, err = self._probe(batch)
        self.assertEqual(code, 2)
        self.assertIsNone(result)          # nothing was sent
        self.assertIn(str(MAX_BATCH), err)

    def test_unlisted_method_is_refused(self):
        code, _, err = self._probe([{"url": f"{self.base}/", "method": "TRACE"}])
        self.assertEqual(code, 2)
        self.assertIn("TRACE", err)

    def test_malformed_stdin_is_a_usage_error(self):
        code, _, err = self._probe("not json at all")
        self.assertEqual(code, 2)
        self.assertIn("JSON", err)

    def test_missing_url_is_rejected(self):
        code, _, err = self._probe([{"method": "GET"}])
        self.assertEqual(code, 2)
        self.assertIn("url", err)

    # ----------------------------------------------------------- output shape
    def test_credentials_are_masked_in_the_output(self):
        code, result, _ = self._probe(
            [{"url": f"{self.base}/", "headers": {"Authorization": "Bearer SECRET"}}])
        self.assertEqual(code, 0)
        blob = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("SECRET", blob)
        self.assertEqual(
            result["exchanges"][0]["request_headers"]["Authorization"], "***")

    def test_exchanges_are_shaped_for_evidence(self):
        # The output is meant to drop straight into Evidence(exchanges=[...]).
        code, result, _ = self._probe([{"url": f"{self.base}/", "note": "기준선"}])
        self.assertEqual(code, 0)
        exchange = result["exchanges"][0]
        for field in ("method", "url", "status", "actor", "request_headers",
                      "response_headers", "response_excerpt", "note"):
            self.assertIn(field, exchange)
        self.assertEqual(exchange["note"], "기준선")

    def test_auth_result_is_reported_alongside(self):
        code, result, _ = self._probe([{"url": f"{self.base}/"}], auth=ACTORS_FILE)
        self.assertEqual(code, 0)
        self.assertTrue(result["auth"]["alice"]["ok"])
        self.assertTrue(result["auth"]["bob"]["ok"])


if __name__ == "__main__":
    unittest.main()
