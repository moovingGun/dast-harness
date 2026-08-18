"""Behaviour of the auth scenario: getting a session, and proving it is alive.

Config parsing runs on plain dicts. Everything else runs the real
`AgentHttpClient` against the real target app, in-process on an ephemeral port
— a fake client would happily "authenticate" without a cookie jar ever being
exercised, which is exactly the bug this file exists to catch.
"""

import os
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "targets"))

from vulnerable_app import app as vulnapp  # noqa: E402

from dast_harness.agent_kit.auth import (AuthConfigError, establish,  # noqa: E402
                                         load_actors, parse_actors)
from dast_harness.agent_kit.http import AgentHttpClient  # noqa: E402

ACTORS_FILE = os.path.join(ROOT, "targets", "vulnerable_app", "actors.json")


class QuietHandler(vulnapp.Handler):
    def log_message(self, *args):
        pass


class ConfigTests(unittest.TestCase):
    def test_verify_is_mandatory(self):
        # The whole point: without it a dead session scans logged out and
        # reports "nothing found".
        with self.assertRaises(AuthConfigError) as ctx:
            parse_actors({"actors": {"alice": {"cookies": {"session": "x"}}}})
        self.assertIn("verify", str(ctx.exception))

    def test_actor_needs_a_way_to_get_a_session(self):
        with self.assertRaises(AuthConfigError):
            parse_actors({"actors": {"alice": {"verify": {"path": "/"}}}})

    def test_anon_cannot_be_redefined(self):
        # anon is the logged-out control every agent compares against.
        with self.assertRaises(AuthConfigError):
            parse_actors({"actors": {"anon": {"cookies": {"s": "x"},
                                              "verify": {"path": "/"}}}})

    def test_rejects_unlisted_login_method(self):
        with self.assertRaises(AuthConfigError):
            parse_actors({"actors": {"a": {
                "login": [{"method": "DELETE", "path": "/x"}],
                "verify": {"path": "/"}}}})

    def test_rejects_missing_actors_block(self):
        with self.assertRaises(AuthConfigError):
            parse_actors({"nope": {}})

    def test_rejects_empty_actors(self):
        with self.assertRaises(AuthConfigError):
            parse_actors({"actors": {}})

    def test_rejects_non_scalar_body_value(self):
        with self.assertRaises(AuthConfigError):
            parse_actors({"actors": {"a": {
                "login": [{"path": "/x", "body": {"u": ["list"]}}],
                "verify": {"path": "/"}}}})

    def test_missing_file_is_a_config_error(self):
        with self.assertRaises(AuthConfigError):
            load_actors(os.path.join(ROOT, "no-such-file.json"))

    def test_shipped_scenario_parses(self):
        # targets/vulnerable_app/actors.json is what the IDOR team starts from.
        actors = load_actors(ACTORS_FILE)
        self.assertEqual(sorted(actors), ["alice", "bob"])
        self.assertTrue(actors["alice"].login)      # replays a login sequence
        self.assertTrue(actors["bob"].cookies)      # takes a supplied session


class CredentialScopeTests(unittest.TestCase):
    """A supplied token must not follow the actor to another allowed host.

    The allowlist says "you may scan these hosts". It does not say "these hosts
    may have each other's credentials". Cookies are already host-scoped by the
    cookie jar; headers were not, so a Bearer token for one staging host rode
    along to every other allowlisted one.

    No server needed: the request headers are built before the socket is opened,
    so a failed connection still records what would have been sent.
    """

    def _client(self):
        client = AgentHttpClient(allowlist={"a.internal", "b.internal"})
        client.set_actor_headers("alice", {"Authorization": "Bearer TOKEN-A"},
                                 "http://a.internal/")
        return client

    def _sent(self, client, url):
        return "Authorization" in client.request("GET", url, actor="alice").request_headers

    def test_token_goes_to_the_host_it_was_scoped_to(self):
        self.assertTrue(self._sent(self._client(), "http://a.internal/x"))

    def test_token_does_not_follow_to_another_allowed_host(self):
        self.assertFalse(self._sent(self._client(), "http://b.internal/x"))

    def test_port_does_not_split_the_scope(self):
        # Same rule as cookies, and the same host on another port is the same
        # app in practice. Being stricter would drop auth silently instead.
        self.assertTrue(self._sent(self._client(), "http://a.internal:8443/x"))

    def test_rebinding_an_actor_to_a_second_host_is_refused(self):
        client = self._client()
        with self.assertRaises(ValueError):
            client.set_actor_headers("alice", {"Authorization": "Bearer TOKEN-B"},
                                     "http://b.internal/")

    def test_other_actors_are_unaffected(self):
        client = self._client()
        exchange = client.request("GET", "http://a.internal/x", actor="anon")
        self.assertNotIn("Authorization", exchange.request_headers)


class EstablishTests(unittest.TestCase):
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

    def _run(self, spec):
        client = AgentHttpClient()
        results = establish(client, parse_actors(spec), self.base)
        return client, results

    def test_login_sequence_produces_a_working_session(self):
        client, results = self._run({"actors": {"alice": {
            "login": [{"method": "POST", "path": "/login",
                       "body": {"username": "alice", "password": "alice123"}}],
            "verify": {"path": "/api/orders/1001", "expect_status": 200,
                       "body_contains": "alice@example.com"}}}})
        self.assertTrue(results["alice"].ok, results["alice"].reason)
        self.assertEqual(client.actors, ["alice"])
        self.assertEqual(client.cookies("alice"), ["session"])

    def test_supplied_cookie_produces_a_working_session(self):
        # The path that matters in real engagements: a human logged in through
        # MFA/SSO and handed over the session.
        client, results = self._run({"actors": {"bob": {
            "cookies": {"session": "bob-session"},
            "verify": {"path": "/api/orders/1002", "expect_status": 200}}}})
        self.assertTrue(results["bob"].ok, results["bob"].reason)
        self.assertEqual(client.actors, ["bob"])

    def test_supplied_cookie_works_for_a_dotless_hostname(self):
        # Regression: cookiejar treats a dotless host as "<host>.local", so a
        # cookie stored under the bare hostname is silently never sent — the
        # session is fine but verify fails 401. safety.py allows `localhost`
        # by name, so this is a first-class target, not an edge case.
        port = self.server.server_address[1]
        client = AgentHttpClient()
        results = establish(client, parse_actors({"actors": {"bob": {
            "cookies": {"session": "bob-session"},
            "verify": {"path": "/api/orders/1002", "expect_status": 200,
                       "body_contains": "bob@example.com"}}}}),
            "http://localhost:%d" % port)
        self.assertTrue(results["bob"].ok, results["bob"].reason)
        self.assertEqual(client.actors, ["bob"])

    def test_dead_session_fails_loudly(self):
        client, results = self._run({"actors": {"bob": {
            "cookies": {"session": "expired"},
            "verify": {"path": "/api/orders/1002", "expect_status": 200}}}})
        self.assertFalse(results["bob"].ok)
        self.assertIn("401", results["bob"].reason)
        # Never claimed as usable: an agent reading client.actors sees nothing.
        self.assertEqual(client.actors, [])

    def test_wrong_password_fails_at_the_login_step(self):
        client, results = self._run({"actors": {"alice": {
            "login": [{"method": "POST", "path": "/login",
                       "body": {"username": "alice", "password": "WRONG"}}],
            "verify": {"path": "/api/orders/1001"}}}})
        self.assertFalse(results["alice"].ok)
        self.assertIn("login[0]", results["alice"].reason)
        self.assertEqual(client.actors, [])

    def test_body_contains_catches_a_session_that_returns_200(self):
        # Status alone is not proof: many apps serve the login page with 200.
        client, results = self._run({"actors": {"bob": {
            "cookies": {"session": "bob-session"},
            "verify": {"path": "/api/orders/1002", "expect_status": 200,
                       "body_contains": "alice@example.com"}}}})
        self.assertFalse(results["bob"].ok)
        self.assertIn("alice@example.com", results["bob"].reason)

    def test_actors_do_not_share_sessions(self):
        client, results = self._run({"actors": {
            "alice": {"cookies": {"session": "alice-session"},
                      "verify": {"path": "/api/orders/1001"}},
            "bob": {"cookies": {"session": "bob-session"},
                    "verify": {"path": "/api/orders/1002"}}}})
        self.assertTrue(all(r.ok for r in results.values()))
        # alice must not be able to read her order through bob's jar, or every
        # IDOR verdict downstream is meaningless.
        self.assertEqual(client.cookies("anon"), [])
        alice_view = client.get(f"{self.base}/api/orders/1001", actor="bob")
        self.assertEqual(alice_view.status, 200)   # 200 is the IDOR itself
        logged_out = client.get(f"{self.base}/api/orders/1001", actor="anon")
        self.assertEqual(logged_out.status, 401)   # anon stays logged out

    def test_supplied_header_rides_every_request(self):
        client, _ = self._run({"actors": {"api": {
            "headers": {"X-Api-Key": "secret-key", "X-Tenant": "acme"},
            "verify": {"path": "/", "expect_status": 200}}}})
        exchange = client.get(f"{self.base}/", actor="api")
        # Present on a request nobody passed it to...
        self.assertIn("X-Api-Key", exchange.request_headers)
        # ...but masked, so a Bearer token cannot ride out in the report.
        self.assertEqual(exchange.request_headers["X-Api-Key"], "***")
        self.assertEqual(exchange.request_headers["X-Tenant"], "acme")
        # Another actor does not inherit it.
        other = client.get(f"{self.base}/", actor="anon")
        self.assertNotIn("X-Api-Key", other.request_headers)
        # A per-request header still wins over the actor default.
        override = client.get(f"{self.base}/", actor="api",
                              headers={"X-Tenant": "explicit"})
        self.assertEqual(override.request_headers["X-Tenant"], "explicit")

    def test_credentials_never_reach_the_report(self):
        client, _ = self._run({"actors": {"alice": {
            "login": [{"method": "POST", "path": "/login",
                       "body": {"username": "alice", "password": "alice123"}}],
            "verify": {"path": "/api/orders/1001"}}}})
        # establish() hands back no exchanges at all, so the login body cannot
        # be attached as evidence by an agent that never sees it.
        self.assertEqual(client.blocked, [])
        self.assertEqual(client.actors, ["alice"])

    def test_one_actor_failing_does_not_block_the_others(self):
        _, results = self._run({"actors": {
            "alice": {"cookies": {"session": "alice-session"},
                      "verify": {"path": "/api/orders/1001"}},
            "ghost": {"cookies": {"session": "nope"},
                      "verify": {"path": "/api/orders/1002"}}}})
        self.assertTrue(results["alice"].ok)
        self.assertFalse(results["ghost"].ok)

    def test_requests_are_counted_per_actor(self):
        _, results = self._run({"actors": {
            "alice": {"login": [{"method": "POST", "path": "/login",
                                 "body": {"username": "alice",
                                          "password": "alice123"}}],
                      "verify": {"path": "/api/orders/1001"}},
            "bob": {"cookies": {"session": "bob-session"},
                    "verify": {"path": "/api/orders/1002"}}}})
        self.assertEqual(results["alice"].requests_made, 2)   # login + verify
        self.assertEqual(results["bob"].requests_made, 1)     # verify only


if __name__ == "__main__":
    unittest.main()
