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
import urllib.error
import urllib.parse
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


def _cookie_for(actor):
    """The session cookie the app would hand `actor` after a successful login."""
    return next(f"session={token}"
                for token, user in vulnapp.SESSIONS.items() if user == actor)


def _fetch(base, path, *, actor=None, data=None):
    req = urllib.request.Request(base + path, data=data)
    if actor:
        req.add_header("Cookie", _cookie_for(actor))
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, resp.headers, resp.read().decode("utf-8", "replace")


def _post(base, path, fields):
    body = urllib.parse.urlencode(fields).encode()
    try:
        return _fetch(base, path, data=body)
    except urllib.error.HTTPError as exc:
        # Login failures are 401s, which urllib raises; they are the response.
        with exc:
            return exc.code, exc.headers, exc.read().decode("utf-8", "replace")


class ServedAppCase(unittest.TestCase):
    """Runs the target in-process on an ephemeral port. Holds no tests itself."""

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


class VulnerableAppTest(ServedAppCase):
    def test_binds_loopback_by_default(self):
        # The target is deliberately vulnerable: it must not listen on 0.0.0.0
        # unless a container entrypoint asks for it explicitly.
        self.assertEqual(vulnapp.DEFAULT_HOST, "127.0.0.1")

    def test_ground_truth_entries_are_well_formed(self):
        entries = self.truth["expected"] + self.truth["must_not_detect"]
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
        # must_not_detect entries are held to the same bar: a negative control
        # only controls for something if it is actually reachable.
        for entry in self.truth["expected"] + self.truth["must_not_detect"]:
            with self.subTest(id=entry["id"]):
                status, headers, body = _fetch(self.base, entry["path"],
                                               actor=entry.get("as_actor"))
                self.assertEqual(status, 200)
                if entry.get("body_contains"):
                    self.assertIn(entry["body_contains"], body)
                for header in entry.get("absent_headers", []):
                    self.assertIsNone(
                        headers.get(header),
                        f"{header} is present, so {entry['id']} is not observable",
                    )

    def test_agent_surfaces_are_reachable_from_the_index(self):
        # The recon agent finds endpoints by crawling, so an unlinked surface is
        # invisible to it no matter how vulnerable it is.
        _, _, index = _fetch(self.base, "/")
        for path in ("/login", "/search?q=invoice", "/lookup?q=alice"):
            with self.subTest(path=path):
                self.assertIn(f'href="{path}"', index)
        _, _, login = _fetch(self.base, "/login")
        self.assertIn('href="/api/orders/1001"', login)

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


class AgentSurfaceTest(ServedAppCase):
    """The three weaknesses the recon / injection / IDOR agents are built against.

    Each is asserted as a *contrast*, because that is the shape the agents have
    to produce as evidence: a baseline plus the request that differs from it.
    """

    def test_login_failure_messages_differ_by_cause(self):
        # The whole user-enumeration weakness is this difference. If both
        # branches ever return the same text, the weakness is gone and the
        # ground-truth entry is stale.
        known, _, known_body = _post(self.base, "/login",
                                     {"username": "alice", "password": "wrong"})
        unknown, _, unknown_body = _post(self.base, "/login",
                                         {"username": "zzzz_nope", "password": "wrong"})
        self.assertEqual((known, unknown), (401, 401))
        self.assertNotEqual(known_body, unknown_body)
        self.assertIn("비밀번호가 올바르지 않습니다", known_body)
        self.assertIn("존재하지 않는 사용자입니다", unknown_body)

    def test_successful_login_sets_a_session_cookie(self):
        status, headers, _ = _post(self.base, "/login",
                                   {"username": "alice", "password": "alice123"})
        self.assertEqual(status, 200)
        self.assertIn("session=alice-session", headers.get("Set-Cookie", ""))

    def test_order_api_requires_a_session(self):
        # The contrast that separates IDOR from a missing-auth API: anonymous
        # access is refused, so authentication exists and only authorization
        # is absent.
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            _fetch(self.base, "/api/orders/1002")
        self.assertEqual(ctx.exception.code, 401)
        ctx.exception.close()

    def test_signed_in_user_reads_another_users_order(self):
        _, _, own = _fetch(self.base, "/api/orders/1001", actor="alice")
        _, _, other = _fetch(self.base, "/api/orders/1002", actor="alice")
        self.assertIn("alice@example.com", own)          # baseline
        self.assertIn("bob@example.com", other)          # the IDOR

    def test_unknown_order_is_404_for_a_signed_in_user(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            _fetch(self.base, "/api/orders/9999", actor="alice")
        self.assertEqual(ctx.exception.code, 404)
        ctx.exception.close()

    def test_search_breaks_on_an_unbalanced_quote(self):
        _, _, baseline = _fetch(self.base, "/search?q=invoice")
        self.assertIn("3 results for invoice", baseline)

        with self.assertRaises(urllib.error.HTTPError) as ctx:
            _fetch(self.base, "/search?q=invoice%27")
        self.assertEqual(ctx.exception.code, 500)
        self.assertIn("SQL syntax", ctx.exception.read().decode())
        ctx.exception.close()

    def test_comment_repairs_the_broken_query(self):
        # Baseline restored by a comment is the proof that the input is parsed
        # as SQL rather than merely echoed into an error page.
        status, _, body = _fetch(self.base, "/search?q=invoice%27--%20")
        self.assertEqual(status, 200)
        self.assertIn("3 results for invoice", body)

    def test_lookup_is_a_negative_control(self):
        # Same query-parameter shape as /search, but sound. An injection
        # finding here is a false positive, so it must never look injectable.
        status, _, body = _fetch(self.base, "/lookup?q=alice%27")
        self.assertEqual(status, 200)
        self.assertNotIn("SQL", body)

    def test_lookup_500_carries_no_sql_error(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            _fetch(self.base, "/lookup?q=" + "a" * 101)
        self.assertEqual(ctx.exception.code, 500)
        body = ctx.exception.read().decode()
        ctx.exception.close()
        # A 500 alone is not evidence of injection; the SQL error string is.
        for marker in ("SQL", "syntax", "MySQL"):
            self.assertNotIn(marker, body)

    def test_post_is_rejected_outside_login(self):
        # Keeps the added surface tight: /login is the only POST endpoint.
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            _fetch(self.base, "/admin/", data=b"username=admin&password=admin")
        self.assertEqual(ctx.exception.code, 405)
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
