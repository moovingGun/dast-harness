"""injection 에이전트 — 구문을 깨고 주석으로 복구되는지로 판정한다.

가장 중요한 테스트는 "찾는다"가 아니라 **"멀쩡한 걸 안 건드린다"** 쪽이다.
정답지에 `/lookup`이 오탐 함정으로 들어 있고, 500만 보고 보고하는 에이전트는
거기 걸린다.
"""

import unittest

from dast_harness.agent_kit import (Confidence, RequestParameter, RequestSeed,
                                    validate_result)
from dast_harness.agent_kit.injection import InjectionAgent

from tests.agent_fakes import ORIGIN, FakeClient

SQL_ERROR_BODY = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    'to your MySQL server version for the right syntax to use near "\'%x%\'"'
)


def _seed(path, name, value, location="query", method="GET"):
    url = f"{ORIGIN}{path}?{name}={value}" if location == "query" else f"{ORIGIN}{path}"
    return RequestSeed(
        method=method, url=url,
        params=(RequestParameter(name=name, location=location, value=value,
                                 type="string"),),
        observed_status=200, source="link",
    )


def _run(pages, seeds, post_pages=None):
    client = FakeClient(pages, post_pages=post_pages)
    agent = InjectionAgent(client)
    agent.seeds = seeds
    return agent.run(ORIGIN), client


class InjectableTests(unittest.TestCase):
    """정상 → 깨짐 → 복구가 다 맞을 때만 보고한다."""

    PAGES = {
        f"{ORIGIN}/search?q=invoice": (200, "text/html", "<h1>3 results</h1>"),
        f"{ORIGIN}/search?q=invoice%27": (500, "text/plain", SQL_ERROR_BODY),
        f"{ORIGIN}/search?q=invoice%27--": (200, "text/html", "<h1>3 results</h1>"),
    }

    def test_reports_when_syntax_breaks_and_a_comment_repairs_it(self):
        result, _ = _run(self.PAGES, [_seed("/search", "q", "invoice")])
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.category, "injection")
        self.assertEqual(finding.confidence, Confidence.CONFIRMED)
        self.assertEqual(finding.scanner, "agent:injection")

    def test_evidence_is_baseline_attack_repair(self):
        result, _ = _run(self.PAGES, [_seed("/search", "q", "invoice")])
        evidence = result.findings[0].evidence
        self.assertEqual(len(evidence.exchanges), 3)
        self.assertEqual(evidence.baseline_index, 0)
        self.assertEqual([e.status for e in evidence.exchanges], [200, 500, 200])

    def test_withheld_payloads_do_not_lower_confidence(self):
        result, _ = _run(self.PAGES, [_seed("/search", "q", "invoice")])
        probe = result.findings[0].agent_data["injection"]
        self.assertIn("union-select-extraction", probe.withheld)
        self.assertEqual(result.findings[0].confidence, Confidence.CONFIRMED)

    def test_result_obeys_the_contract(self):
        result, _ = _run(self.PAGES, [_seed("/search", "q", "invoice")])
        self.assertEqual(validate_result(result), [])

    def test_stops_probing_a_parameter_once_it_is_decided(self):
        _, client = _run(self.PAGES, [_seed("/search", "q", "invoice")])
        # baseline + break + repair = 3. Further payloads would be noise.
        self.assertEqual(client.request_count, 3)


class FalsePositiveTests(unittest.TestCase):
    """`/lookup`은 잘 깨지지만 주입되지는 않는다. 여기서 보고하면 감점이다."""

    def test_a_500_without_a_sql_signature_is_not_reported(self):
        pages = {
            f"{ORIGIN}/lookup?q=alice": (200, "text/html", "<h1>1 people matching</h1>"),
            # 따옴표는 정상 처리 — 500도 아니다
            f"{ORIGIN}/lookup?q=alice%27": (200, "text/html", "<h1>0 people matching</h1>"),
        }
        result, _ = _run(pages, [_seed("/lookup", "q", "alice")])
        self.assertEqual(result.findings, [])

    def test_a_generic_server_error_is_recorded_as_a_skip_not_a_finding(self):
        pages = {
            f"{ORIGIN}/lookup?q=alice": (200, "text/html", "ok"),
            f"{ORIGIN}/lookup?q=alice%27": (500, "text/plain",
                                            "Internal Server Error: lookup failed"),
            f"{ORIGIN}/lookup?q=alice%22": (500, "text/plain",
                                            "Internal Server Error: lookup failed"),
            f"{ORIGIN}/lookup?q=alice%27)": (500, "text/plain",
                                             "Internal Server Error: lookup failed"),
        }
        result, _ = _run(pages, [_seed("/lookup", "q", "alice")])
        self.assertEqual(result.findings, [])
        # "안 찾은 것"이 아니라 "봤는데 근거가 없었다"로 남는다.
        self.assertIn("errors-without-sql-signature", result.coverage.skip_reasons)

    def test_a_baseline_that_already_errors_is_skipped(self):
        pages = {f"{ORIGIN}/broken?q=x": (500, "text/plain", "boom")}
        result, _ = _run(pages, [_seed("/broken", "q", "x")])
        self.assertEqual(result.findings, [])
        self.assertIn("baseline-already-erroring", result.coverage.skip_reasons)

    def test_no_repair_lowers_confidence_instead_of_claiming_certainty(self):
        pages = {
            f"{ORIGIN}/search?q=invoice": (200, "text/html", "ok"),
            f"{ORIGIN}/search?q=invoice%27": (500, "text/plain", SQL_ERROR_BODY),
            # 주석으로도 복구되지 않는다 — 오류의 원인이 구문이라 단정 못 한다
            f"{ORIGIN}/search?q=invoice%27--": (500, "text/plain", SQL_ERROR_BODY),
        }
        result, _ = _run(pages, [_seed("/search", "q", "invoice")])
        self.assertEqual(result.findings[0].confidence, Confidence.FIRM)
        self.assertIn("사람 확인", result.findings[0].evidence.rationale)


class ScopeTests(unittest.TestCase):
    def test_path_parameters_are_left_to_the_idor_agent(self):
        seed = RequestSeed(
            method="GET", url=f"{ORIGIN}/api/orders/1001",
            params=(RequestParameter(name="id", location="path", value="1001",
                                     type="int"),),
            observed_status=200, source="link")
        result, client = _run({}, [seed])
        self.assertEqual(result.coverage.tested, 0)
        self.assertEqual(client.request_count, 0)

    def test_body_parameters_are_probed_one_at_a_time(self):
        seed = RequestSeed(
            method="POST", url=f"{ORIGIN}/login",
            params=(RequestParameter(name="username", location="body", value="alice",
                                     type="string"),
                    RequestParameter(name="password", location="body", value="pw",
                                     type="string")),
            observed_status=200, source="form")
        _, client = _run({}, [seed], post_pages={
            f"{ORIGIN}/login": (200, "text/html", "ok")})
        bodies = [body for _, _, _, body in client.sent if body]
        # 한 번에 한 파라미터만 바뀌고 나머지는 관측값을 유지한다.
        self.assertTrue(all("password=pw" in b for b in bodies if "username=alice" in b))

    def test_wants_seeds_is_declared(self):
        # 러너가 씨앗 없이 돌리면 실패로 세우게 하는 스위치.
        self.assertTrue(InjectionAgent.wants_seeds)


if __name__ == "__main__":
    unittest.main()
