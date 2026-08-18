"""Behaviour of the recon agent. **Copy this file when you add an agent.**

The pattern: drive the agent with a `FakeClient` (no server, no sockets), then
assert on the `AgentResult` it returns. `tests/test_agent_contract.py` already
checks that the result obeys the contract, so here we only check what *this*
agent is supposed to find.

`recon.py` is the skeleton the other agents get copied from, so a drift here
lands in both copies.
"""

import unittest

from dast_harness.agent_kit import ReconResult, validate_result
from dast_harness.agent_kit import recon
from dast_harness.agent_kit.recon import ReconAgent

from tests.agent_fakes import ORIGIN, FakeClient

PAGES = {
    f"{ORIGIN}/robots.txt": (
        200, "text/plain", "User-agent: *\nDisallow: /admin/\n"),
    f"{ORIGIN}/": (
        200, "text/html",
        '<a href="/admin/">admin</a>'
        '<a href="/search?q=invoice">search</a>'
        '<a href="/api/orders/1001">order</a>'),
    f"{ORIGIN}/admin/": (
        200, "text/html",
        '<h1>Administrator Login</h1>'
        '<form method="post" action="/login">'
        '  <input type="text" name="username" value="admin">'
        '  <input type="password" name="password">'
        '  <input type="number" name="pin">'
        '  <input type="submit" value="Sign in">'
        '</form>'),
    f"{ORIGIN}/search": (200, "text/html", "<h1>0 results</h1>"),
    f"{ORIGIN}/api/orders/1001": (401, "application/json", "{}"),
}


class ReconCrawlTest(unittest.TestCase):
    def setUp(self):
        self.result = ReconAgent(FakeClient(PAGES)).run(ORIGIN)

    def _seed(self, method, template):
        return next(s for s in self.result.request_seeds
                    if (s.method, s.template) == (method, template))

    def test_returns_a_valid_recon_result(self):
        self.assertIsInstance(self.result, ReconResult)
        self.assertEqual(validate_result(self.result), [])

    def test_reports_the_endpoints_it_crawled(self):
        templates = {s.template for s in self.result.request_seeds}
        self.assertLessEqual({"/", "/admin/", "/robots.txt", "/search",
                              "/api/orders/{id}"}, templates)

    def test_reports_the_robots_finding(self):
        self.assertEqual([f.finding_id for f in self.result.findings],
                         ["robots-discloses-reachable-paths"])

    def test_query_parameter_keeps_its_value(self):
        self.assertEqual(
            [(p.name, p.location, p.value) for p in self._seed("GET", "/search").params],
            [("q", "query", "invoice")])

    def test_path_parameter_is_typed_and_valued(self):
        seed = self._seed("GET", "/api/orders/{id}")
        self.assertEqual([(p.name, p.location, p.value, p.type) for p in seed.params],
                         [("id", "path", "1001", "int")])
        self.assertIs(seed.auth_required, True)        # 401 observed

    def test_coverage_counts_what_it_fetched(self):
        self.assertEqual(self.result.coverage.unit, "endpoint")
        self.assertGreater(self.result.coverage.tested, 0)
        self.assertEqual(self.result.coverage.findings, len(self.result.findings))


class ReconFormParsingTest(unittest.TestCase):
    """Forms are how the injection agent learns about POST parameters."""

    def setUp(self):
        self.agent = ReconAgent(FakeClient(PAGES))
        self.result = self.agent.run(ORIGIN)

    def _seed(self, method, template):
        return next(s for s in self.result.request_seeds
                    if (s.method, s.template) == (method, template))

    def test_body_parameters_are_captured(self):
        self.assertEqual(
            {(p.name, p.location) for p in self._seed("POST", "/login").params},
            {("username", "body"), ("password", "body"), ("pin", "body")})

    def test_declared_field_types_and_values_survive(self):
        params = {p.name: p for p in self._seed("POST", "/login").params}
        self.assertEqual(params["username"].value, "admin")
        self.assertEqual(params["pin"].type, "int")     # <input type="number">
        self.assertEqual(params["password"].type, "string")

    def test_submit_control_is_not_a_parameter(self):
        names = {p.name for p in self._seed("POST", "/login").params}
        self.assertNotIn("Sign in", names)

    def test_post_form_records_its_body_encoding(self):
        self.assertEqual(self._seed("POST", "/login").body_content_type,
                         "application/x-www-form-urlencoded")

    def test_post_seed_is_not_actually_sent(self):
        # Recon must not press state-changing buttons; it reports the shape only.
        self.assertIsNone(self._seed("POST", "/login").observed_status)

    def test_quoted_attribute_value_keeps_its_spaces(self):
        self.assertEqual(recon._attrs('name="title" value="hello world"'),
                         {"name": "title", "value": "hello world"})

    def test_key_value_text_inside_an_attribute_is_not_an_attribute(self):
        # 'placeholder="e.g. name=foo"' renamed the parameter to foo, and
        # 'placeholder="hint: type=submit"' made a password field look like a
        # submit control and dropped it from the seed entirely.
        self.assertEqual(recon._attrs('name="q" placeholder="e.g. name=foo"'),
                         {"name": "q", "placeholder": "e.g. name=foo"})
        self.assertEqual(
            recon._attrs('name="password" type="password" '
                         'placeholder="hint: type=submit"')["type"],
            "password")

    def test_entities_in_attribute_values_are_decoded(self):
        self.assertEqual(recon._attrs('action="/s?a=1&amp;b=2"')["action"],
                         "/s?a=1&b=2")

    def test_form_tag_survives_a_gt_inside_an_attribute(self):
        # The attr chunk used to be cut at the '>' in onsubmit, so method and
        # action were never read: the POST endpoint vanished and the current
        # page got a phantom query parameter instead.
        agent = ReconAgent(FakeClient({}))
        agent._record_forms(
            f"{ORIGIN}/checkout",
            '<form onsubmit="return a>b" method="post" action="/pay">'
            '<input name="amount" value="10"></form>')
        self.assertEqual(list(agent._collected), [("POST", "/pay")])
        self.assertEqual(
            [(p.name, p.location)
             for p in agent._collected[("POST", "/pay")].params],
            [("amount", "body")])


class ReconLargePageTest(unittest.TestCase):
    """Parsing must use the full body, not the evidence excerpt.

    `HttpExchange.response_excerpt` is truncated to `MAX_EXCERPT` so that reports
    stay small. Parsing HTML out of it silently loses everything past the cutoff,
    and because a form needs its closing tag, a half-visible form contributes
    nothing at all — no error, no skip reason.
    """

    def _page_with_form_after(self, filler_len):
        return ("<html><body>" + ("x" * filler_len) +
                '<form method="post" action="/login">'
                '<input name="username"><input name="password">'
                '</form></body></html>')

    def _seeds(self, filler_len):
        html = self._page_with_form_after(filler_len)
        agent = ReconAgent(FakeClient({
            f"{ORIGIN}/robots.txt": (404, "text/plain", ""),
            f"{ORIGIN}/": (200, "text/html", html),
        }))
        return {(s.method, s.template) for s in agent.run(ORIGIN).request_seeds}

    def test_form_near_the_top_is_found(self):
        self.assertIn(("POST", "/login"), self._seeds(50))

    def test_form_past_the_excerpt_cutoff_is_still_found(self):
        # 2048 is MAX_EXCERPT; the form starts well beyond it.
        self.assertIn(("POST", "/login"), self._seeds(4000))

    def test_link_past_the_excerpt_cutoff_is_still_crawled(self):
        html = ("<html><body>" + ("x" * 4000) +
                '<a href="/deep">deep</a></body></html>')
        agent = ReconAgent(FakeClient({
            f"{ORIGIN}/robots.txt": (404, "text/plain", ""),
            f"{ORIGIN}/": (200, "text/html", html),
            f"{ORIGIN}/deep": (200, "text/html", "<h1>deep</h1>"),
        }))
        templates = {s.template for s in agent.run(ORIGIN).request_seeds}
        self.assertIn("/deep", templates)

    def test_evidence_excerpt_stays_bounded(self):
        # The fix must not widen what lands in the report.
        agent = ReconAgent(FakeClient({
            f"{ORIGIN}/robots.txt": (404, "text/plain", ""),
            f"{ORIGIN}/": (200, "text/html", self._page_with_form_after(4000)),
        }))
        agent.run(ORIGIN)
        excerpt = agent.exchanges[f"{ORIGIN}/"].response_excerpt
        self.assertLessEqual(len(excerpt), 2048 + 16)
        self.assertGreater(len(agent.bodies[f"{ORIGIN}/"]), len(excerpt))


class ReconEntityTest(unittest.TestCase):
    """`&amp;` in a link must be decoded before the URL is used."""

    def test_ampersand_entity_does_not_leak_into_a_parameter_name(self):
        agent = ReconAgent(FakeClient({
            f"{ORIGIN}/robots.txt": (404, "text/plain", ""),
            f"{ORIGIN}/": (200, "text/html",
                           '<a href="/s?a=1&amp;b=2">search</a>'),
            f"{ORIGIN}/s": (200, "text/html", "<h1>ok</h1>"),
        }))
        seed = next(s for s in agent.run(ORIGIN).request_seeds
                    if s.template == "/s")
        # Before the fix this was [('a', '1'), ('amp;b', '2')].
        self.assertEqual([(p.name, p.value) for p in seed.params],
                         [("a", "1"), ("b", "2")])


class ReconSeedMergeTest(unittest.TestCase):
    """Two URLs of the same shape collapse into one seed."""

    def test_merged_seed_keeps_url_and_path_params_together(self):
        # Merging took the newer path value but kept the older url, inventing a
        # request that was never sent (url .../1001 carrying id=7).
        from dast_harness.agent_kit import RequestParameter, RequestSeed
        agent = ReconAgent(FakeClient({}))
        for value in ("1001", "7"):
            agent._add(RequestSeed(
                method="GET", url=f"{ORIGIN}/api/orders/{value}",
                params=(RequestParameter(name="id", location="path",
                                         value=value, type="int"),),
                observed_status=200))
        self.assertEqual(len(agent._collected), 1)
        seed = next(iter(agent._collected.values()))
        path_value = next(p.value for p in seed.params if p.location == "path")
        self.assertIn(path_value, seed.url)
        # ...and the seed still matches the key it is stored under.
        self.assertEqual(("GET", seed.template), next(iter(agent._collected)))


LOGIN_FORM = (
    '<form method="post" action="/login">'
    '  <input type="text" name="username">'
    '  <input type="password" name="password">'
    '</form>'
)


def _enum_pages(real_body, absent_body, absent_body2=None):
    """로그인 폼 하나 + POST 응답을 흉내내는 FakeClient용 페이지들."""
    return {f"{ORIGIN}/": (200, "text/html", LOGIN_FORM)}


class _LoginClient(FakeClient):
    """POST 본문의 username에 따라 다른 응답을 준다."""

    def __init__(self, real_user, real_body, absent_body, absent_body2=None, **kw):
        super().__init__({f"{ORIGIN}/": (200, "text/html", LOGIN_FORM)}, **kw)
        self.real_user = real_user
        self.real_body = real_body
        self.absent_body = absent_body
        self.absent_body2 = absent_body2 or absent_body
        self._absent_seen = 0

    def post(self, url, **kw):
        body = kw.get("body") or ""
        if f"username={self.real_user}" in body:
            text = self.real_body
        else:
            self._absent_seen += 1
            text = self.absent_body if self._absent_seen == 1 else self.absent_body2
        self.post_pages[url] = (401, "text/plain", text)
        return super().post(url, **kw)


class ReconUserEnumerationTest(unittest.TestCase):
    """실재 계정과 없는 계정의 로그인 실패 응답이 다른가.

    없는 계정을 **두 번** 보내는 것이 요점이다. 응답에 타임스탬프나 토큰이 섞여
    매번 달라지는 대상에서, 한 번만 비교하면 전부 취약하다고 보고하게 된다.
    """

    def _run(self, client):
        agent = ReconAgent(client)
        return agent.run(ORIGIN)

    def test_different_messages_are_reported(self):
        client = _LoginClient("alice", "비밀번호가 올바르지 않습니다",
                              "존재하지 않는 사용자입니다", actors=["alice"])
        result = self._run(client)
        ids = [f.finding_id for f in result.findings]
        self.assertIn("user-enumeration-login", ids)
        finding = next(f for f in result.findings
                       if f.finding_id == "user-enumeration-login")
        self.assertEqual(finding.category, "information-disclosure")
        self.assertEqual(len(finding.evidence.exchanges), 3)
        self.assertEqual(finding.evidence.baseline_index, 0)

    def test_identical_messages_are_not_reported(self):
        client = _LoginClient("alice", "로그인 실패", "로그인 실패", actors=["alice"])
        result = self._run(client)
        self.assertNotIn("user-enumeration-login",
                         [f.finding_id for f in result.findings])

    def test_an_unstable_response_is_skipped_not_reported(self):
        # 없는 계정 둘의 응답이 서로 다르면 차이의 원인을 계정 존재로 좁힐 수 없다.
        # 여기서 보고하면 토큰·타임스탬프가 섞인 대상은 전부 취약해진다.
        client = _LoginClient("alice", "비밀번호 오류",
                              "실패 nonce=aaa", "실패 nonce=bbb", actors=["alice"])
        result = self._run(client)
        self.assertNotIn("user-enumeration-login",
                         [f.finding_id for f in result.findings])
        self.assertIn("login-response-unstable", result.coverage.skip_reasons)

    def test_without_a_known_account_it_skips(self):
        # 실재한다고 믿을 만한 계정이 없으면 기준선을 못 잡는다. 아무 이름이나
        # 넣고 "실재 계정"이라 가정하면 판정이 무의미해진다.
        client = _LoginClient("alice", "A", "B")      # actors 비어 있음
        result = self._run(client)
        self.assertNotIn("user-enumeration-login",
                         [f.finding_id for f in result.findings])
        self.assertIn("no-known-account", result.coverage.skip_reasons)

    def test_no_login_form_is_recorded_as_a_skip(self):
        client = FakeClient({f"{ORIGIN}/": (200, "text/html", "<p>no forms</p>")})
        result = self._run(client)
        self.assertIn("no-login-form", result.coverage.skip_reasons)

    def test_it_does_not_brute_force(self):
        client = _LoginClient("alice", "비밀번호가 올바르지 않습니다",
                              "존재하지 않는 사용자입니다", actors=["alice"])
        result = self._run(client)
        finding = next(f for f in result.findings
                       if f.finding_id == "user-enumeration-login")
        probe = finding.agent_data["recon"]
        self.assertEqual(probe.attempts, 3)           # 계정 잠금을 유발하지 않는다
        self.assertIn("credential-bruteforce", probe.withheld)


if __name__ == "__main__":
    unittest.main()
