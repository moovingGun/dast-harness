"""Contract for agent findings (dast_harness/agent_kit/contract.py).

The five-plus-one rules in finding-v0-proposal.md §4 are only real if they are
enforced, so this file is the enforcement: every rule has a positive case (the
proposal's own §6 examples) and a negative case that must be rejected.

Written promises rot over a weekend; asserts do not.
"""

import json
import unittest
from dataclasses import asdict

from dast_harness import Finding, Severity
from dast_harness.agent_kit import Agent
from dast_harness.agent_kit.contract import (MASKED, MAX_EXCERPT,
                                             AgentCompletion, AgentFinding,
                                             AgentResult, Confidence, Coverage,
                                             Evidence, HttpExchange, Probe,
                                             ReconResult, RequestParameter,
                                             RequestSeed, finding_to_dict,
                                             validate_finding, validate_result)
from dast_harness.agent_kit.recon import ReconAgent

from tests.agent_fakes import ORIGIN, FakeClient


def _probe(**kw):
    """A minimally valid Probe; override any field per test."""
    base = dict(strategy="sequential-id", target="id", target_kind="object-id")
    return Probe(**{**base, **kw})


def _evidence(**kw):
    base = dict(
        baseline_index=0,
        rationale="alice로 bob의 주문이 200으로 반환됐다.",
        exchanges=[
            HttpExchange(method="GET", url="http://127.0.0.1:8080/api/orders/1001",
                         actor="alice", status=200, note="기준선"),
            HttpExchange(method="GET", url="http://127.0.0.1:8080/api/orders/1002",
                         actor="alice", status=200, note="공격"),
        ],
    )
    return Evidence(**{**base, **kw})


def _agent_finding(**kw):
    """A finding that passes every rule; override to build violations."""
    base = dict(
        scanner="agent:idor",
        finding_id="idor-order-object-access",
        name="주문 조회 API에 객체 소유권 검사 없음",
        severity=Severity.HIGH,
        matched_at="http://127.0.0.1:8080/api/orders/1002",
        confidence=Confidence.CONFIRMED,
        category="idor",
        evidence=_evidence(),
        agent_data={"idor": _probe()},
    )
    return AgentFinding(**{**base, **kw})


class ProposalExamplesTest(unittest.TestCase):
    """finding-v0-proposal.md §6 examples must stay valid, verbatim.

    Teammates copy these examples. If the linter and the document disagree, one
    of them is lying to whoever copies next.
    """

    def test_idor_example_passes(self):
        f = _agent_finding(
            evidence=Evidence(
                baseline_index=0,
                rationale=("alice 세션으로 bob의 주문(1002)이 200으로 반환됐고 본문에 "
                           "bob@example.com이 들어 있다. 3번 요청이 401이므로 인증은 "
                           "걸려 있고 객체 소유권 검사만 없다 — IDOR이다."),
                exchanges=[
                    HttpExchange(
                        method="GET", url="http://127.0.0.1:8080/api/orders/1001",
                        actor="alice", status=200,
                        response_excerpt='{"id":1001,"owner":"alice@example.com"}',
                        note="기준선: alice가 자기 주문을 조회 (정상)"),
                    HttpExchange(
                        method="GET", url="http://127.0.0.1:8080/api/orders/1002",
                        actor="alice", status=200,
                        response_excerpt='{"id":1002,"owner":"bob@example.com"}',
                        note="공격: id만 1002로 바꿈"),
                    HttpExchange(
                        method="GET", url="http://127.0.0.1:8080/api/orders/1002",
                        actor="anon", status=401,
                        response_excerpt='{"error":"authentication required"}',
                        note="대조: 비로그인은 차단됨 → 인가만 없음"),
                ],
            ),
            agent_data={"idor": Probe(
                strategy="sequential-id", target="id", target_kind="object-id",
                attempts=4, hits=["1002"], actors=["alice", "anon"],
                extra={"probed_ids": [1000, 1001, 1002, 1003]})},
        )
        self.assertEqual(validate_finding(f), [])

    def test_injection_example_passes(self):
        f = AgentFinding(
            scanner="agent:injection",
            finding_id="sqli-error-based-search-q",
            name="검색 파라미터 q에 SQL 구문 주입 가능",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            category="injection",
            matched_at="http://127.0.0.1:8080/search?q=",
            tags=["sqli", "injection", "error-based"],
            evidence=Evidence(
                baseline_index=0,
                rationale=("따옴표 하나로 500 + 구문 오류, 주석(--)을 붙이면 200으로 "
                           "복구된다. 결정적 증거다. 데이터 추출은 미시도이며 "
                           "withheld에 남긴다 — 자제는 confidence를 낮추지 않는다."),
                exchanges=[
                    HttpExchange(method="GET", url="http://127.0.0.1:8080/search?q=invoice",
                                 actor="anon", status=200, note="기준선: 정상 입력"),
                    HttpExchange(method="GET", url="http://127.0.0.1:8080/search?q=invoice%27",
                                 actor="anon", status=500, note="따옴표 1개 → 구문 깨짐"),
                    HttpExchange(method="GET", url="http://127.0.0.1:8080/search?q=invoice%27--%20",
                                 actor="anon", status=200, note="주석으로 복구"),
                ],
            ),
            agent_data={"injection": Probe(
                strategy="error-based-sqli", target="q", target_kind="parameter",
                attempts=7, hits=["invoice'"], actors=["anon"],
                withheld=["union-select-extraction", "time-based-blind"],
                extra={"location": "query", "dbms_guess": "mysql"})},
        )
        self.assertEqual(validate_finding(f), [])

    def test_recon_example_passes(self):
        f = AgentFinding(
            scanner="agent:recon",
            finding_id="user-enumeration-login",
            name="로그인 응답으로 계정 존재 여부 구분 가능",
            severity=Severity.LOW,
            confidence=Confidence.FIRM,
            category="information-disclosure",
            matched_at="http://127.0.0.1:8080/login",
            evidence=Evidence(
                baseline_index=0,
                rationale=("같은 실패인데 메시지가 다르다. CONFIRMED가 아닌 이유: "
                           "메시지 차이의 원인을 다른 가능성과 배제하지 않았다."),
                exchanges=[
                    HttpExchange(method="POST", url="http://127.0.0.1:8080/login",
                                 actor="anon", status=401,
                                 request_body="username=alice&password=wrong",
                                 note="기준선: 실재 계정 + 틀린 비밀번호"),
                    HttpExchange(method="POST", url="http://127.0.0.1:8080/login",
                                 actor="anon", status=401,
                                 request_body="username=zzzz_nope&password=wrong",
                                 note="없는 계정 → 메시지가 다름"),
                ],
            ),
            agent_data={"recon": Probe(
                strategy="login-error-differential", target="/login",
                target_kind="endpoint", attempts=2,
                hits=["alice", "bob", "admin"], actors=["anon"])},
        )
        self.assertEqual(validate_finding(f), [])


class RuleEnforcementTest(unittest.TestCase):
    """Each §4 rule must reject its violation. A rule nobody enforces is a wish."""

    def assertRejects(self, finding, needle):
        errs = validate_finding(finding)
        self.assertTrue(
            any(needle in e for e in errs),
            f"expected an error containing {needle!r}, got {errs}",
        )

    # --- rule 2: evidence is always required for agent findings
    def test_missing_evidence_is_rejected_even_when_confirmed(self):
        f = _agent_finding(evidence=None, confidence=Confidence.CONFIRMED)
        self.assertRejects(f, "evidence가 없음")

    def test_non_confirmed_without_evidence_names_rule_2(self):
        f = _agent_finding(evidence=None, confidence=Confidence.TENTATIVE)
        self.assertRejects(f, "규칙2")

    def test_empty_exchanges_is_rejected(self):
        f = _agent_finding(evidence=_evidence(exchanges=[]))
        self.assertRejects(f, "exchanges가 비어 있음")

    def test_blank_rationale_is_rejected(self):
        f = _agent_finding(evidence=_evidence(rationale="   "))
        self.assertRejects(f, "rationale이 비어 있음")

    def test_baseline_index_out_of_range_is_rejected(self):
        f = _agent_finding(evidence=_evidence(baseline_index=7))
        self.assertRejects(f, "baseline_index")

    def test_baseline_index_may_be_omitted(self):
        # Not every finding is proved by contrast (e.g. a bare /.env exposure),
        # so None stays legal. See proposal §9-3.
        f = _agent_finding(evidence=_evidence(baseline_index=None))
        self.assertEqual(validate_finding(f), [])

    # --- rule 3: agent: prefix
    def test_bare_agent_prefix_is_rejected(self):
        f = _agent_finding(scanner="agent:")
        self.assertRejects(f, "규칙3")

    # --- rule 4: agent_data namespacing, raw untouched
    def test_foreign_namespace_in_agent_data_is_rejected(self):
        f = _agent_finding(agent_data={"injection": _probe(target_kind="parameter")})
        self.assertRejects(f, "규칙4")

    def test_agent_using_raw_is_rejected(self):
        f = _agent_finding(raw={"template-id": "x"})
        self.assertRejects(f, "raw")

    # --- rule 6: agent_data[<name>] must be Probe-shaped
    def test_free_form_agent_data_is_rejected(self):
        # This is what the proposal's first draft told teammates to write.
        f = _agent_finding(agent_data={"idor": {"id_strategy": "sequential-numeric"}})
        self.assertRejects(f, "규칙6")

    def test_probe_missing_required_field_is_rejected(self):
        f = _agent_finding(agent_data={"idor": _probe(strategy="")})
        self.assertRejects(f, "strategy")

    def test_target_kind_outside_vocabulary_is_rejected(self):
        f = _agent_finding(agent_data={"idor": _probe(target_kind="objectid")})
        self.assertRejects(f, "target_kind")

    def test_probe_as_plain_dict_is_accepted(self):
        # asdict()-ed Probes survive a JSON round trip and must still validate.
        f = _agent_finding(agent_data={"idor": asdict(_probe())})
        self.assertEqual(validate_finding(f), [])

    def test_missing_probe_is_rejected(self):
        f = _agent_finding(agent_data={})
        self.assertRejects(f, "규칙6")

    # --- category vocabulary (§3)
    def test_category_outside_vocabulary_is_rejected(self):
        f = _agent_finding(category="sqli")
        self.assertRejects(f, "category가 어휘 밖")

    def test_ground_truth_categories_are_accepted(self):
        for category in ("exposure", "information-disclosure", "misconfiguration"):
            with self.subTest(category=category):
                self.assertEqual(validate_finding(_agent_finding(category=category)), [])


class ScannerFindingTest(unittest.TestCase):
    """The linter runs over mixed lists, so plain Findings must pass through."""

    def test_plain_finding_does_not_crash_the_linter(self):
        # Regression: validate_finding() read f.category directly, which a
        # scanner Finding does not have -> AttributeError on any mixed list.
        f = Finding("nuclei", "tpl-id", "n", Severity.LOW, "http://127.0.0.1:8080/")
        self.assertEqual(validate_finding(f), [])

    def test_scanner_finding_needs_no_evidence(self):
        f = Finding("nikto", "tpl-id", "n", Severity.INFO, "http://127.0.0.1:8080/")
        self.assertEqual(validate_finding(f), [])

    def test_scanner_raw_is_allowed(self):
        f = Finding("nuclei", "tpl-id", "n", Severity.LOW, "http://127.0.0.1:8080/",
                    raw={"template-id": "x"})
        self.assertEqual(validate_finding(f), [])

    def test_agent_finding_is_a_finding(self):
        # Reporters and the orchestrator are typed on Finding; inheritance is
        # what lets agent findings flow through them unchanged.
        self.assertIsInstance(_agent_finding(), Finding)

    def test_scanner_finding_defaults_to_confirmed(self):
        f = Finding("nuclei", "tpl-id", "n", Severity.LOW, "http://127.0.0.1:8080/")
        self.assertIs(getattr(f, "confidence", Confidence.CONFIRMED),
                      Confidence.CONFIRMED)


class MaskingTest(unittest.TestCase):
    """Rule 5 is enforced in __post_init__, so hand-built exchanges obey it too."""

    def test_credential_request_headers_are_masked(self):
        ex = HttpExchange(method="GET", url="http://127.0.0.1:8080/", status=200,
                          request_headers={"Cookie": "session=secret",
                                           "Authorization": "Bearer tok",
                                           "X-Api-Key": "k",
                                           "Accept": "text/html"})
        self.assertEqual(ex.request_headers,
                         {"Cookie": MASKED, "Authorization": MASKED,
                          "X-Api-Key": MASKED, "Accept": "text/html"})

    def test_set_cookie_in_response_is_masked(self):
        ex = HttpExchange(method="GET", url="http://127.0.0.1:8080/", status=200,
                          response_headers={"Set-Cookie": "session=secret",
                                            "Content-Type": "text/html"})
        self.assertEqual(ex.response_headers,
                         {"Set-Cookie": MASKED, "Content-Type": "text/html"})

    def test_masking_is_case_insensitive(self):
        ex = HttpExchange(method="GET", url="http://127.0.0.1:8080/", status=200,
                          request_headers={"cookie": "session=secret"})
        self.assertEqual(ex.request_headers, {"cookie": MASKED})

    def test_long_excerpt_is_truncated(self):
        ex = HttpExchange(method="GET", url="http://127.0.0.1:8080/", status=200,
                          response_excerpt="A" * 5000)
        self.assertLess(len(ex.response_excerpt), 5000)
        self.assertTrue(ex.response_excerpt.endswith("[truncated]"))

    def test_unmasked_header_in_evidence_is_rejected(self):
        # A hand-built dict cannot get past __post_init__, so this simulates a
        # finding assembled by some future code path that bypasses it.
        ex = HttpExchange(method="GET", url="http://127.0.0.1:8080/", status=200)
        object.__setattr__(ex, "request_headers", {"Cookie": "session=secret"})
        f = _agent_finding(evidence=_evidence(exchanges=[ex], baseline_index=0))
        errs = validate_finding(f)
        self.assertTrue(any("미마스킹" in e for e in errs), errs)

    def test_oversized_excerpt_in_evidence_is_rejected(self):
        ex = HttpExchange(method="GET", url="http://127.0.0.1:8080/", status=200)
        object.__setattr__(ex, "response_excerpt", "A" * (MAX_EXCERPT + 100))
        f = _agent_finding(evidence=_evidence(exchanges=[ex], baseline_index=0))
        errs = validate_finding(f)
        self.assertTrue(any("초과" in e for e in errs), errs)


class SerializationTest(unittest.TestCase):
    """Findings that cannot be serialized cannot be reported."""

    def test_finding_with_probe_is_json_serializable(self):
        # Regression: rule 6 mandates a Probe (a dataclass) in agent_data and
        # recon.py stores one, but finding_to_dict passed it through untouched
        # -> TypeError: Object of type Probe is not JSON serializable.
        payload = json.dumps(finding_to_dict(_agent_finding()), ensure_ascii=False)
        self.assertIn("sequential-id", payload)

    def test_probe_is_flattened_to_a_dict(self):
        out = finding_to_dict(_agent_finding())
        self.assertEqual(out["agent_data"]["idor"]["target_kind"], "object-id")

    def test_v0_fields_survive_serialization(self):
        out = finding_to_dict(_agent_finding(confidence=Confidence.FIRM))
        self.assertEqual(out["confidence"], "firm")
        self.assertEqual(out["category"], "idor")
        self.assertEqual(out["evidence"]["baseline_index"], 0)

    def test_evidence_can_be_left_out(self):
        out = finding_to_dict(_agent_finding(), include_evidence=False)
        self.assertNotIn("evidence", out)

    def test_scanner_finding_serializes_without_v0_fields(self):
        f = Finding("nuclei", "tpl-id", "n", Severity.LOW, "http://127.0.0.1:8080/")
        out = finding_to_dict(f)
        self.assertEqual(out["confidence"], "confirmed")
        self.assertNotIn("agent_data", out)

    def test_coverage_is_serializable(self):
        out = json.loads(json.dumps(asdict(Coverage(
            unit="object-id", tested=4, skipped=1,
            skip_reasons={"no-auth-session": 1}, findings=1))))
        self.assertEqual(out["skip_reasons"], {"no-auth-session": 1})


class AgentResultTest(unittest.TestCase):
    """The per-agent return value, not just the per-finding shape.

    Getting Finding right is not enough to merge three agents: if one returns
    a dict of endpoints and another a list of tuples, the orchestrator cannot
    treat them alike. This used to be a bare dict with nothing checking it.
    """

    def _result(self, **kw):
        base = dict(
            agent="idor",
            findings=[_agent_finding()],
            coverage=Coverage(unit="object-id", tested=4, findings=1),
            completion=AgentCompletion(requests_made=9),
        )
        return AgentResult(**{**base, **kw})

    def test_well_formed_result_passes(self):
        self.assertEqual(validate_result(self._result()), [])

    def test_missing_agent_name_is_rejected(self):
        errs = validate_result(self._result(agent=""))
        self.assertTrue(any("agent가 비어" in e for e in errs), errs)

    def test_missing_coverage_is_rejected(self):
        # 0 findings with no coverage cannot be told apart from "never looked".
        errs = validate_result(AgentResult(agent="idor", coverage=None,
                                           completion=AgentCompletion()))
        self.assertTrue(any("coverage가 없음" in e for e in errs), errs)

    def test_empty_result_with_coverage_passes(self):
        # Finding nothing is a legitimate outcome and must not be an error.
        empty = AgentResult(agent="idor",
                            coverage=Coverage(unit="object-id", tested=9, findings=0),
                            completion=AgentCompletion(requests_made=9))
        self.assertEqual(validate_result(empty), [])

    def test_coverage_unit_outside_vocabulary_is_rejected(self):
        errs = validate_result(self._result(
            coverage=Coverage(unit="objects", tested=4, findings=1)))
        self.assertTrue(any("coverage.unit" in e for e in errs), errs)

    def test_stale_coverage_count_is_rejected(self):
        errs = validate_result(self._result(
            coverage=Coverage(unit="object-id", tested=4, findings=7)))
        self.assertTrue(any("coverage.findings" in e for e in errs), errs)

    def test_finding_from_another_agent_is_rejected(self):
        # Copying someone else's agent and forgetting to change `name` lands here.
        errs = validate_result(self._result(agent="injection"))
        self.assertTrue(any("scanner가" in e for e in errs), errs)

    def test_finding_level_rules_are_checked_too(self):
        bad = _agent_finding(evidence=None)
        errs = validate_result(self._result(findings=[bad]))
        self.assertTrue(any("evidence가 없음" in e for e in errs), errs)

    def test_result_is_json_serializable(self):
        payload = json.dumps(self._result(completion=AgentCompletion(
            requests_made=9,
            blocked=[("http://attacker.example/exfil", "허가되지 않은 대상")],
        )).to_dict(), ensure_ascii=False)
        out = json.loads(payload)
        self.assertEqual(out["agent"], "idor")
        self.assertEqual(out["coverage"]["unit"], "object-id")
        self.assertEqual(out["completion"]["blocked"][0][1], "허가되지 않은 대상")


class AgentBaseTest(unittest.TestCase):
    """`Agent.finish()` is what stops three agents from drifting apart."""

    class Stub(Agent):
        name = "idor"
        unit = "object-id"

        def run(self, base):
            return self.finish([], tested=3)

    def _stub(self):
        return self.Stub(FakeClient({}))

    def test_finish_fills_coverage_and_counters(self):
        agent = self._stub()
        agent.client.request_count = 11
        result = agent.run("http://t.invalid")
        self.assertEqual(result.agent, "idor")
        self.assertEqual(result.coverage.unit, "object-id")
        self.assertEqual(result.coverage.tested, 3)
        self.assertEqual(result.completion.requests_made, 11)

    def test_finish_counts_findings_itself(self):
        # Hand-counted coverage drifts; derived coverage cannot.
        agent = self._stub()
        result = agent.finish([_agent_finding()], tested=1)
        self.assertEqual(result.coverage.findings, 1)

    def test_finish_carries_blocked_requests(self):
        # Prompt-injection attempts show up here, so they must not be dropped.
        agent = self._stub()
        agent.client.blocked = [("http://attacker.example/exfil", "허가되지 않은 대상")]
        self.assertEqual(agent.run("http://t.invalid").completion.blocked,
                         [("http://attacker.example/exfil", "허가되지 않은 대상")])

    def test_finish_raises_on_a_contract_violation(self):
        agent = self._stub()
        stray = _agent_finding(scanner="agent:recon")   # wrong agent
        with self.assertRaises(AssertionError):
            agent.finish([stray], tested=1)

    def test_skip_reasons_are_recorded(self):
        result = self._stub().finish([], tested=0, skipped=3,
                                     skip_reasons={"no-auth-session": 3})
        self.assertEqual(result.coverage.skipped, 3)
        self.assertEqual(result.coverage.skip_reasons, {"no-auth-session": 3})


class RequestSeedTest(unittest.TestCase):
    """Seeds are replayed verbatim by the other two agents.

    A seed that loses the parameter's location, value or type forces the
    receiving agent to re-observe everything recon already saw.
    """

    def _seed(self, **kw):
        base = dict(
            method="GET",
            url="http://127.0.0.1:8080/api/orders/1001",
            params=(RequestParameter(name="id", location="path",
                                     value="1001", type="int"),),
        )
        return RequestSeed(**{**base, **kw})

    def test_template_collapses_path_values(self):
        # Without this, every id becomes its own seed and the list drowns in values.
        self.assertEqual(self._seed().template, "/api/orders/{id}")

    def test_template_of_a_plain_path_is_the_path(self):
        seed = RequestSeed(method="GET", url="http://127.0.0.1:8080/login")
        self.assertEqual(seed.template, "/login")

    def test_seed_keeps_the_observed_value(self):
        # injection needs the baseline value; IDOR needs the id it can pivot from.
        self.assertEqual(self._seed().params[0].value, "1001")

    def test_valid_seed_passes_validation(self):
        result = ReconResult(agent="recon",
                             coverage=Coverage(unit="endpoint", tested=1, findings=0),
                             completion=AgentCompletion(),
                             request_seeds=[self._seed()])
        self.assertEqual(validate_result(result), [])

    def _seed_errors(self, seed):
        return validate_result(ReconResult(
            agent="recon", coverage=Coverage(unit="endpoint", tested=1, findings=0),
            completion=AgentCompletion(), request_seeds=[seed]))

    def test_relative_url_is_rejected(self):
        # A seed is meant to be sendable as-is; a bare path is not.
        errs = self._seed_errors(self._seed(url="/api/orders/1001"))
        self.assertTrue(any("http(s)" in e for e in errs), errs)

    def test_location_outside_vocabulary_is_rejected(self):
        errs = self._seed_errors(self._seed(
            params=(RequestParameter(name="id", location="urlpath"),)))
        self.assertTrue(any("location" in e for e in errs), errs)

    def test_type_outside_vocabulary_is_rejected(self):
        errs = self._seed_errors(self._seed(
            params=(RequestParameter(name="id", location="path", type="number"),)))
        self.assertTrue(any("type" in e for e in errs), errs)

    def test_json_path_outside_body_is_rejected(self):
        errs = self._seed_errors(self._seed(
            params=(RequestParameter(name="id", location="query",
                                     json_path="$.user.id"),)))
        self.assertTrue(any("json_path" in e for e in errs), errs)

    def test_json_body_parameter_is_accepted(self):
        errs = self._seed_errors(self._seed(
            method="POST", body_content_type="application/json",
            params=(RequestParameter(name="id", location="body", value="1001",
                                     type="int", json_path="$.order.id"),)))
        self.assertEqual(errs, [])

    def test_unnamed_parameter_is_rejected(self):
        errs = self._seed_errors(self._seed(
            params=(RequestParameter(name="", location="query"),)))
        self.assertTrue(any("이름 없는" in e for e in errs), errs)


class SeedTemplateTest(unittest.TestCase):
    """`template` groups seeds. Blind str.replace corrupted it, and it is the
    key the whole inventory is keyed by."""

    def _template(self, path, path_params):
        return RequestSeed(
            method="GET", url="http://127.0.0.1:8080" + path,
            params=tuple(RequestParameter(name=n, location="path", value=v,
                                          type="int")
                         for n, v in path_params),
        ).template

    def test_value_inside_another_segment_is_not_substituted(self):
        # str.replace turned this into "/api/v{id}/users/{id}": the API version
        # became a placeholder, so two ids produced two different templates and
        # the seed list drowned in values — the exact thing template prevents.
        self.assertEqual(self._template("/api/v2/users/2", [("id", "2")]),
                         "/api/v2/users/{id}")

    def test_shorter_id_is_not_substituted_inside_a_longer_one(self):
        self.assertEqual(self._template("/api/1/items/11",
                                        [("id1", "1"), ("id2", "11")]),
                         "/api/{id1}/items/{id2}")

    def test_repeated_value_consumes_one_placeholder_each(self):
        self.assertEqual(self._template("/files/1/1", [("id1", "1"), ("id2", "1")]),
                         "/files/{id1}/{id2}")
        self.assertEqual(self._template("/orders/2/items/2",
                                        [("id1", "2"), ("id2", "2")]),
                         "/orders/{id1}/items/{id2}")


class SeedValidationTest(unittest.TestCase):
    """`validate_result` let several unsendable seeds through."""

    def _errors(self, **kw):
        seed = RequestSeed(**{**dict(method="GET",
                                     url="http://127.0.0.1:8080/x"), **kw})
        return validate_result(ReconResult(
            agent="recon",
            coverage=Coverage(unit="endpoint", tested=1, findings=0),
            completion=AgentCompletion(), request_seeds=[seed]))

    def test_non_http_scheme_is_rejected(self):
        # Only `.scheme` was checked, so javascript: URLs passed.
        errs = self._errors(url="javascript:alert(1)")
        self.assertTrue(any("http(s)" in e for e in errs), errs)

    def test_url_without_a_host_is_rejected(self):
        errs = self._errors(url="http:///no-host")
        self.assertTrue(any("http(s)" in e for e in errs), errs)

    def test_empty_method_is_rejected(self):
        errs = self._errors(method="")
        self.assertTrue(any("method" in e for e in errs), errs)

    def test_path_param_absent_from_the_url_is_rejected(self):
        errs = self._errors(
            url="http://127.0.0.1:8080/api/orders/1001",
            params=(RequestParameter(name="id", location="path", value="7"),))
        self.assertTrue(any("url 경로에 없음" in e for e in errs), errs)

    def test_non_string_value_is_rejected(self):
        # An int value made `.template` raise TypeError downstream.
        errs = self._errors(
            params=(RequestParameter(name="id", location="query", value=7),))
        self.assertTrue(any("문자열이 아님" in e for e in errs), errs)

    def test_duplicate_parameter_is_rejected(self):
        errs = self._errors(params=(
            RequestParameter(name="q", location="query", value="a"),
            RequestParameter(name="q", location="query", value="b")))
        self.assertTrue(any("중복" in e for e in errs), errs)

    def test_none_request_seeds_does_not_crash(self):
        result = ReconResult(
            agent="recon", coverage=Coverage(unit="endpoint", tested=0, findings=0),
            completion=AgentCompletion(), request_seeds=None)
        self.assertEqual(validate_result(result), [])   # raised TypeError before


class ConfidenceTypeTest(unittest.TestCase):
    """`Confidence` is a str Enum, so a bare string compares equal to it."""

    def test_bare_string_confidence_is_rejected(self):
        # It passed validation and then crashed to_dict() on `.value`.
        f = _agent_finding(confidence="firm")
        errs = validate_finding(f)
        self.assertTrue(any("Confidence enum" in e for e in errs), errs)

    def test_enum_confidence_is_accepted(self):
        self.assertEqual(validate_finding(_agent_finding(
            confidence=Confidence.FIRM)), [])

    def test_rejected_confidence_never_reaches_serialization(self):
        # The contract check has to fire before to_dict() is ever called.
        result = AgentResult(
            agent="idor", findings=[_agent_finding(confidence="firm")],
            coverage=Coverage(unit="object-id", tested=1, findings=1),
            completion=AgentCompletion())
        self.assertTrue(validate_result(result))


if __name__ == "__main__":
    unittest.main()
