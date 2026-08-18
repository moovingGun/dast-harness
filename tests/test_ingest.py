"""`dast-harness ingest` — the gate a subagent's JSON passes through.

A gate is defined by what it turns away, so most of this file is rejections.
The error strings matter as much as the exit codes: they are the retry
instruction handed back to whatever wrote the JSON.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest

from dast_harness import cli
from dast_harness.agent_kit import AgentHttpClient, Confidence
from dast_harness.agent_kit.recon import ReconAgent
from dast_harness.ingest import IngestError, load_result
from dast_harness.models import Severity

from tests.agent_fakes import ORIGIN, FakeClient

TARGET = "http://127.0.0.1:8080"


def _exchange(**kw):
    base = {"method": "GET", "url": f"{TARGET}/api/orders/1002", "status": 200,
            "actor": "alice", "response_headers": {"Content-Type": "text/html"},
            "response_excerpt": "hi", "note": ""}
    base.update(kw)
    return base


def _finding(**kw):
    base = {
        "scanner": "agent:idor",
        "id": "idor-order-object-access",
        "name": "주문 조회 API에 객체 소유권 검사 없음",
        "severity": "high",
        "confidence": "confirmed",
        "category": "idor",
        "matched_at": f"{TARGET}/api/orders/1002",
        "description": "id만 바꿔 타인의 주문을 조회할 수 있다.",
        "tags": ["idor"],
        "evidence": {
            "baseline_index": 0,
            "rationale": "alice 세션으로 남의 주문이 200, 비로그인은 401.",
            "exchanges": [_exchange(), _exchange(actor="anon", status=401)],
        },
        "agent_data": {"idor": {"strategy": "sequential-id", "target": "id",
                                "target_kind": "object-id"}},
    }
    base.update(kw)
    return base


def _result(**kw):
    base = {
        "agent": "idor",
        "findings": [_finding()],
        "coverage": {"unit": "object-id", "tested": 1, "skipped": 0,
                     "skip_reasons": {}},
        "completion": {"requests_made": 3, "blocked": []},
    }
    base.update(kw)
    return base


class LoadTests(unittest.TestCase):
    def test_a_well_formed_result_loads(self):
        result = load_result(_result())
        self.assertEqual(result.agent, "idor")
        self.assertEqual(result.findings[0].severity, Severity.HIGH)
        self.assertEqual(result.findings[0].confidence, Confidence.CONFIRMED)
        self.assertEqual(result.coverage.tested, 1)

    def test_our_own_agent_output_round_trips(self):
        # The ingest format is AgentResult.to_dict() on purpose: a Python agent
        # and a subagent have to produce the same shape or they never merge.
        recon = ReconAgent(FakeClient({
            f"{ORIGIN}/robots.txt": (200, "text/plain",
                                     "User-agent: *\nDisallow: /admin/\n"),
            f"{ORIGIN}/admin/": (200, "text/html", "<h1>admin</h1>"),
            f"{ORIGIN}/": (200, "text/html", '<a href="/admin/">a</a>'),
        })).run(ORIGIN)
        reloaded = load_result(json.loads(json.dumps(recon.to_dict())))
        self.assertEqual(reloaded.agent, "recon")
        self.assertEqual(len(reloaded.findings), len(recon.findings))
        self.assertEqual(len(reloaded.request_seeds), len(recon.request_seeds))

    def test_credentials_pasted_into_evidence_are_masked_on_load(self):
        # Rebuilding HttpExchange re-runs __post_init__, so rule 5 is enforced
        # again here — a subagent that pasted a raw token cannot leak it through.
        payload = _result(findings=[_finding(evidence={
            "baseline_index": 0,
            "rationale": "x",
            "exchanges": [_exchange(
                request_headers={"Authorization": "Bearer REAL-TOKEN"})],
        })])
        result = load_result(payload)
        headers = result.findings[0].evidence.exchanges[0].request_headers
        self.assertEqual(headers["Authorization"], "***")

    def test_overlong_excerpt_is_truncated_on_load(self):
        payload = _result(findings=[_finding(evidence={
            "baseline_index": 0, "rationale": "x",
            "exchanges": [_exchange(response_excerpt="A" * 9000)],
        })])
        result = load_result(payload)
        excerpt = result.findings[0].evidence.exchanges[0].response_excerpt
        self.assertLess(len(excerpt), 9000)
        self.assertTrue(excerpt.endswith("…[truncated]"))

    # ------------------------------------------------------------- rejections
    def _rejects(self, payload, *fragments):
        with self.assertRaises(IngestError) as ctx:
            load_result(payload)
        message = str(ctx.exception)
        for fragment in fragments:
            self.assertIn(fragment, message)
        return message

    def test_missing_evidence_is_rejected(self):
        # Rule 2: evidence is always required on an agent finding.
        self._rejects(_result(findings=[_finding(evidence=None)]), "evidence")

    def test_evidence_with_no_exchanges_is_rejected(self):
        self._rejects(
            _result(findings=[_finding(evidence={"exchanges": [],
                                                 "rationale": "x"})]),
            "exchanges")

    def test_category_outside_the_vocabulary_is_rejected(self):
        message = self._rejects(
            _result(findings=[_finding(category="access-control")]),
            "access-control")
        # The message has to list what is allowed, or the writer cannot fix it.
        self.assertIn("idor", message)

    def test_unknown_confidence_is_rejected(self):
        self._rejects(_result(findings=[_finding(confidence="아마도")]),
                      "confidence")

    def test_missing_agent_prefix_is_rejected(self):
        # Rule 3: an agent's scanner value must be f"agent:{name}".
        self._rejects(_result(findings=[_finding(scanner="idor")]), "agent:")

    def test_agent_data_under_the_wrong_key_is_rejected(self):
        # Rule 4: agent_data lives under the agent's own name only.
        self._rejects(_result(findings=[_finding(agent_data={"recon": {
            "strategy": "s", "target": "t", "target_kind": "object-id"}})]))

    def test_probe_missing_required_fields_is_rejected(self):
        # Rule 6: agent_data[<name>] is a Probe with strategy/target/target_kind.
        self._rejects(
            _result(findings=[_finding(agent_data={"idor": {"strategy": "s"}})]),
            "target")

    def test_missing_coverage_is_rejected(self):
        message = self._rejects(_result(coverage=None), "coverage")
        # "0건 찾음"과 "0건 봄"을 구분할 수 없게 되는 것이 이유다.
        self.assertIn("0건", message)

    def test_missing_agent_name_is_rejected(self):
        self._rejects(_result(agent=None), "agent")

    def test_non_object_payload_is_rejected(self):
        self._rejects(["not", "a", "result"])


class CliTests(unittest.TestCase):
    def _run(self, payloads, extra=()):
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for i, payload in enumerate(payloads):
                path = os.path.join(d, f"r{i}.json")
                with open(path, "w", encoding="utf-8") as fh:
                    if isinstance(payload, str):
                        fh.write(payload)
                    else:
                        json.dump(payload, fh, ensure_ascii=False)
                paths.append(path)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(["ingest", *paths, *extra])
            return code, out.getvalue(), err.getvalue()

    def test_valid_result_renders_a_report(self):
        code, out, _ = self._run([_result()])
        self.assertEqual(code, 0)
        self.assertIn("agent:idor", out)
        self.assertIn("idor-order-object-access", out)

    def test_several_agents_merge_into_one_report(self):
        recon = {"agent": "recon", "findings": [],
                 "coverage": {"unit": "endpoint", "tested": 4},
                 "completion": {"requests_made": 4}}
        code, out, _ = self._run([recon, _result()])
        self.assertEqual(code, 0)
        self.assertIn("agent:recon", out)
        self.assertIn("agent:idor", out)

    def test_json_output_carries_the_agent_block(self):
        code, out, _ = self._run([_result()], extra=["--format", "json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["findings_count"], 1)
        self.assertEqual(payload["agents"]["idor"]["result"]["coverage"]["tested"], 1)
        # Findings travel once, in "findings" — not duplicated inside the agent.
        self.assertNotIn("findings", payload["agents"]["idor"]["result"])

    def test_contract_violation_exits_2_and_says_why(self):
        code, out, err = self._run([_result(findings=[_finding(scanner="idor")])])
        self.assertEqual(code, 2)
        self.assertIn("agent:", err)
        self.assertEqual(out, "")          # no half-report on a rejected input

    def test_malformed_json_exits_2(self):
        code, _, err = self._run(["{not json"])
        self.assertEqual(code, 2)
        self.assertIn("JSON", err)

    def test_same_agent_twice_is_refused(self):
        code, _, err = self._run([_result(), _result()])
        self.assertEqual(code, 2)
        self.assertIn("idor", err)

    def test_target_is_derived_from_the_findings(self):
        code, out, _ = self._run([_result()])
        self.assertIn(TARGET, out)

    def test_explicit_target_wins(self):
        code, out, _ = self._run([_result()], extra=["--target", "http://x.test"])
        self.assertIn("http://x.test", out)


if __name__ == "__main__":
    unittest.main()
