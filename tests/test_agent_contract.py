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
from dast_harness.agent_kit.contract import (MASKED, MAX_EXCERPT, AgentFinding,
                                             Confidence, Coverage, Endpoint,
                                             Evidence, HttpExchange, Probe,
                                             finding_to_dict, validate_finding)


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
            confidence=Confidence.FIRM,
            category="injection",
            matched_at="http://127.0.0.1:8080/search?q=",
            tags=["sqli", "injection", "error-based"],
            evidence=Evidence(
                baseline_index=0,
                rationale=("따옴표 하나로 500 + 구문 오류, 주석(--)을 붙이면 200으로 "
                           "복구된다. CONFIRMED가 아닌 이유: 데이터 추출 미시도."),
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

    def test_run_result_shape_is_json_serializable(self):
        # The proposal §5 contract: what every agent's run() hands back.
        result = {
            "endpoints": [asdict(Endpoint(
                method="GET", url_template="/api/orders/{id}", params=("id",),
                auth_required=True, observed_status=200,
                content_type="application/json", source="link"))],
            "findings": [finding_to_dict(_agent_finding())],
            "coverage": asdict(Coverage(
                unit="object-id", tested=4, skipped=1,
                skip_reasons={"no-auth-session": 1}, requests=9, findings=1)),
            "requests_made": 9,
            "blocked": [["http://attacker.example/exfil", "허가되지 않은 대상"]],
        }
        round_tripped = json.loads(json.dumps(result, ensure_ascii=False))
        self.assertEqual(round_tripped["endpoints"][0]["url_template"],
                         "/api/orders/{id}")
        self.assertEqual(round_tripped["coverage"]["skip_reasons"],
                         {"no-auth-session": 1})


if __name__ == "__main__":
    unittest.main()
