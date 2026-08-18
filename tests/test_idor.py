"""IDOR 에이전트 — 자기 것 / 남의 것 / 비로그인 3단으로 판정한다.

200이 떴다고 다 IDOR이 아니다. 응답이 기준선과 같으면 남의 걸 본 게 아니고,
비로그인도 통과하면 "인가 없음"이 아니라 "인증 없음"이다. 그 둘을 가르는 게
이 파일 테스트의 대부분이다.
"""

import unittest

from dast_harness.agent_kit import (Confidence, RequestParameter, RequestSeed,
                                    validate_result)
from dast_harness.agent_kit.idor import IdorAgent, candidates_for

from tests.agent_fakes import ORIGIN, FakeClient

ALICE = '{"id": 1001, "owner": "alice@example.com", "item": "desk"}'
BOB = '{"id": 1002, "owner": "bob@example.com", "item": "dock"}'
DENIED = '{"error": "authentication required"}'


def _seed(path="/api/orders/1001", value="1001"):
    return RequestSeed(
        method="GET", url=f"{ORIGIN}{path}",
        params=(RequestParameter(name="id", location="path", value=value,
                                 type="int"),),
        auth_required=True, observed_status=200, source="link",
    )


def _run(pages, seeds=None, actors=("alice",)):
    client = FakeClient(pages, actors=actors)
    agent = IdorAgent(client)
    agent.seeds = seeds if seeds is not None else [_seed()]
    return agent.run(ORIGIN), client


class VulnerableTests(unittest.TestCase):
    PAGES = {
        f"{ORIGIN}/api/orders/1001": (200, "application/json", ALICE),
        f"{ORIGIN}/api/orders/1002": (200, "application/json", BOB),
    }

    def _pages_with_control(self):
        # FakeClient는 actor별 응답을 구분하지 않으므로, 비로그인 대조는
        # 아래 ControlTests에서 별도로 검증한다.
        return dict(self.PAGES)

    def test_reports_when_a_neighbour_object_leaks(self):
        result, _ = _run(self._pages_with_control())
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.category, "idor")
        self.assertEqual(finding.scanner, "agent:idor")
        self.assertTrue(finding.matched_at.endswith("/1002"))

    def test_evidence_is_baseline_attack_control(self):
        result, _ = _run(self._pages_with_control())
        evidence = result.findings[0].evidence
        self.assertEqual(len(evidence.exchanges), 3)
        self.assertEqual(evidence.baseline_index, 0)
        self.assertEqual([e.actor for e in evidence.exchanges],
                         ["alice", "alice", "anon"])

    def test_result_obeys_the_contract(self):
        result, _ = _run(self._pages_with_control())
        self.assertEqual(validate_result(result), [])

    def test_withheld_write_methods_are_recorded(self):
        result, _ = _run(self._pages_with_control())
        probe = result.findings[0].agent_data["idor"]
        self.assertIn("write-methods", probe.withheld)
        self.assertEqual(probe.target_kind, "object-id")


class _ActorAwareClient(FakeClient):
    """`anon`에게는 401을 준다. 인가 없음과 인증 없음을 가르는 축이 actor다."""

    def _exchange(self, method, url, table, kw):
        if kw.get("actor", "anon") == "anon":
            table = {u: (401, "application/json", DENIED) for u in table}
        return super()._exchange(method, url, table, kw)


class ControlLegTests(unittest.TestCase):
    """세 번째 요청이 '인가 없음'과 '인증 없음'을 가른다."""

    PAGES = {
        f"{ORIGIN}/api/orders/1001": (200, "application/json", ALICE),
        f"{ORIGIN}/api/orders/1002": (200, "application/json", BOB),
    }

    def test_blocked_anon_makes_it_confirmed(self):
        client = _ActorAwareClient(self.PAGES, actors=("alice",))
        agent = IdorAgent(client); agent.seeds = [_seed()]
        result = agent.run(ORIGIN)
        finding = result.findings[0]
        self.assertEqual(finding.confidence, Confidence.CONFIRMED)
        self.assertEqual(finding.evidence.exchanges[2].status, 401)
        self.assertIn("IDOR이다", finding.evidence.rationale)
        self.assertTrue(finding.agent_data["idor"].extra["auth_enforced"])

    def test_anon_that_also_gets_in_is_only_firm(self):
        # 비로그인도 통과하면 인증 자체가 없는 API일 수 있다. 조치 방법이
        # 달라지므로 확정하지 않는다.
        client = FakeClient(self.PAGES, actors=("alice",))
        agent = IdorAgent(client); agent.seeds = [_seed()]
        result = agent.run(ORIGIN)
        finding = result.findings[0]
        self.assertEqual(finding.confidence, Confidence.FIRM)
        self.assertIn("사람 확인", finding.evidence.rationale)
        self.assertFalse(finding.agent_data["idor"].extra["auth_enforced"])


class NotVulnerableTests(unittest.TestCase):
    """200만 보고 보고하면 여기서 오탐이 난다."""

    def test_identical_response_is_not_a_leak(self):
        # 같은 본문이면 남의 걸 본 게 아니다 — id를 무시하는 핸들러이거나
        # 공용 리소스다.
        pages = {
            f"{ORIGIN}/api/orders/1001": (200, "application/json", ALICE),
            f"{ORIGIN}/api/orders/1002": (200, "application/json", ALICE),
            f"{ORIGIN}/api/orders/1000": (200, "application/json", ALICE),
            f"{ORIGIN}/api/orders/1": (200, "application/json", ALICE),
        }
        result, _ = _run(pages)
        self.assertEqual(result.findings, [])
        self.assertIn("same-response-as-baseline", result.coverage.skip_reasons)

    def test_a_denied_neighbour_is_not_reported(self):
        pages = {
            f"{ORIGIN}/api/orders/1001": (200, "application/json", ALICE),
            f"{ORIGIN}/api/orders/1002": (403, "application/json", DENIED),
            f"{ORIGIN}/api/orders/1000": (403, "application/json", DENIED),
            f"{ORIGIN}/api/orders/1": (403, "application/json", DENIED),
        }
        result, _ = _run(pages)
        self.assertEqual(result.findings, [])

    def test_a_baseline_we_cannot_read_is_skipped(self):
        pages = {f"{ORIGIN}/api/orders/1001": (401, "application/json", DENIED)}
        result, _ = _run(pages)
        self.assertEqual(result.findings, [])
        self.assertIn("baseline-not-200", result.coverage.skip_reasons)


class SessionTests(unittest.TestCase):
    def test_without_a_session_it_skips_instead_of_scanning_logged_out(self):
        # 비로그인으로 대신하면 "인가 없음"이 아니라 "인증 없음"을 보게 되고,
        # 0건이 "취약하지 않음"으로 읽힌다. 못 찾은 게 아니라 안 찾아본 것이다.
        result, client = _run({}, actors=())
        self.assertEqual(result.findings, [])
        self.assertEqual(result.coverage.tested, 0)
        self.assertEqual(result.coverage.skip_reasons, {"no-auth-session": 1})
        self.assertEqual(client.request_count, 0)      # 아무것도 안 보냈다

    def test_the_first_live_actor_is_the_owner(self):
        result, _ = _run({
            f"{ORIGIN}/api/orders/1001": (200, "application/json", ALICE),
            f"{ORIGIN}/api/orders/1002": (200, "application/json", BOB),
        }, actors=("bob", "alice"))
        self.assertEqual(result.findings[0].agent_data["idor"].actors[0], "bob")


class ScopeTests(unittest.TestCase):
    def test_query_parameters_are_left_to_the_injection_agent(self):
        seed = RequestSeed(
            method="GET", url=f"{ORIGIN}/search?q=invoice",
            params=(RequestParameter(name="q", location="query", value="invoice",
                                     type="string"),),
            observed_status=200, source="link")
        result, client = _run({}, [seed])
        self.assertEqual(result.coverage.tested, 0)
        self.assertEqual(client.request_count, 0)

    def test_wants_seeds_is_declared(self):
        self.assertTrue(IdorAgent.wants_seeds)


class StrategyTests(unittest.TestCase):
    def test_sequential_neighbours_come_first(self):
        values = [c.value for c in candidates_for("1001")]
        self.assertEqual(values[:2], ["1002", "1000"])

    def test_the_original_value_is_never_retried(self):
        self.assertNotIn("1001", [c.value for c in candidates_for("1001")])

    def test_non_numeric_identifiers_yield_nothing_yet(self):
        # UUID 같은 건 아직 전략이 없다. 지어내지 않고 빈 목록을 준다 —
        # 새 전략은 strategies.py에 추가한다.
        self.assertEqual(candidates_for("6f1e-a2b3"), [])

    def test_boundary_id_is_offered_for_higher_values(self):
        self.assertIn("1", [c.value for c in candidates_for("500")])


if __name__ == "__main__":
    unittest.main()
