"""Behaviour of the agent plumbing: AgentRunner and CombinedRunner.

The agents here never touch the network — they return canned results — so this
file stays as fast and dependency-free as the rest of the suite. What is under
test is the wiring, not any agent's judgement.
"""

import threading
import unittest

from dast_harness import Finding, MultiScanRunner, ScanConfig, ScanOutcome, ScanStatus, Severity, Target
from dast_harness.agent_kit import (AgentFinding, Confidence, Evidence, HttpExchange,
                                    Probe, ReconResult, RequestParameter, RequestSeed)
from dast_harness.agent_kit.auth import parse_actors
from dast_harness.agent_kit.base import Agent
from dast_harness.agent_kit.recon import ReconAgent
from dast_harness.agent_runner import AgentRunner, CombinedRunner
from dast_harness.reporters import ConsoleReporter, JSONReporter, build_report
from dast_harness.safety import TargetNotAuthorizedError
from dast_harness.scanners.base import Scanner

LOCAL = "http://127.0.0.1:8080"


def _agent_finding(agent: str, finding_id: str) -> AgentFinding:
    exchange = HttpExchange(
        method="GET", url=f"{LOCAL}/x", status=200, actor="anon",
        response_headers={"Content-Type": "text/html"}, response_excerpt="hi",
    )
    return AgentFinding(
        scanner=f"agent:{agent}", finding_id=finding_id, name=finding_id,
        severity=Severity.HIGH, matched_at=f"{LOCAL}/x",
        confidence=Confidence.FIRM, category="idor",
        evidence=Evidence(exchanges=[exchange], rationale="테스트용", baseline_index=0),
        agent_data={agent: Probe(strategy="s", target="x", target_kind="parameter")},
    )


class QuietAgent(Agent):
    """Returns one finding and nothing else. The default happy path."""

    name = "quiet"
    unit = "endpoint"

    def run(self, base: str):
        return self.finish([_agent_finding(self.name, f"{self.name}-1")], tested=3)


class SecondAgent(QuietAgent):
    name = "second"


class BoomAgent(Agent):
    """Records a finding, then dies. The partial-results case."""

    name = "boom"
    unit = "endpoint"

    def run(self, base: str):
        self.findings.append(_agent_finding(self.name, "boom-1"))
        raise RuntimeError("agent exploded")


class SlowAgent(Agent):
    name = "slow"
    unit = "endpoint"
    gate = threading.Event()

    def run(self, base: str):
        self.gate.wait(5)
        return self.finish([], tested=0)


class OkScanner(Scanner):
    name = "ok"

    def is_available(self) -> bool:
        return True

    def run(self, target, config, on_finding, stop_event=None, on_warning=None):
        on_finding(Finding("ok", "ok-1", "x", Severity.LOW, target.url))
        return ScanOutcome(exit_code=0, output_present=True, output_parseable=True,
                           parsed_records=1)


class AgentRunnerTests(unittest.TestCase):
    def _run(self, agents, config=None):
        runner = AgentRunner(agents)
        scan_id = runner.start_scan(Target(LOCAL), config)
        runner.wait(scan_id, timeout=5)
        return runner, scan_id

    def test_findings_reach_the_shared_results_channel(self):
        runner, scan_id = self._run([QuietAgent])
        findings = runner.get_results(scan_id)
        self.assertEqual([f.finding_id for f in findings], ["quiet-1"])
        # The contract's `agent:` prefix is what makes the source readable in a
        # merged report; the runner must not rewrite it.
        self.assertEqual(findings[0].scanner, "agent:quiet")
        self.assertEqual(runner.get_status(scan_id)["status"], "completed")

    def test_status_carries_each_agent_deliverable(self):
        runner, scan_id = self._run([QuietAgent])
        record = runner.get_status(scan_id)["agents"]["quiet"]
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["findings_count"], 1)
        self.assertEqual(record["result"]["coverage"]["tested"], 3)
        self.assertIsNotNone(record["result"]["completion"])
        # Findings travel once, through get_results — not duplicated in here.
        self.assertNotIn("findings", record["result"])

    def test_failing_agent_keeps_what_it_already_found(self):
        runner, scan_id = self._run([BoomAgent])
        self.assertEqual(runner.get_status(scan_id)["status"], "failed")
        self.assertEqual([f.finding_id for f in runner.get_results(scan_id)],
                         ["boom-1"])
        self.assertIn("agent exploded", runner.get_warnings(scan_id)[0])
        # The reason must be visible without opening the per-agent block.
        self.assertIn("agent exploded", runner.get_status(scan_id)["error"])

    def test_one_failure_among_several_is_partial(self):
        runner, scan_id = self._run([QuietAgent, BoomAgent])
        self.assertEqual(runner.get_status(scan_id)["status"], "partial")
        self.assertEqual(len(runner.get_results(scan_id)), 2)

    def test_agents_run_sequentially_in_declaration_order(self):
        runner, scan_id = self._run([QuietAgent, SecondAgent])
        self.assertEqual(list(runner.get_status(scan_id)["agents"]),
                         ["quiet", "second"])

    def test_stop_skips_the_agents_that_have_not_started(self):
        SlowAgent.gate = threading.Event()
        runner = AgentRunner([SlowAgent, QuietAgent])
        scan_id = runner.start_scan(Target(LOCAL))
        runner.stop_scan(scan_id)      # lands while SlowAgent is still running
        SlowAgent.gate.set()
        runner.wait(scan_id, timeout=5)
        agents = runner.get_status(scan_id)["agents"]
        # Honest accounting: the running agent finished (it cannot be killed
        # from outside yet), the queued one is recorded as never run.
        self.assertEqual(agents["slow"]["status"], "completed")
        self.assertEqual(agents["quiet"]["status"], "stopped")
        self.assertEqual(runner.get_status(scan_id)["status"], "stopped")
        self.assertEqual(runner.get_results(scan_id), [])

    def test_unauthorized_target_never_starts_a_thread(self):
        runner = AgentRunner([QuietAgent])
        with self.assertRaises(TargetNotAuthorizedError):
            runner.start_scan(Target("http://8.8.8.8"))

    def test_duplicate_agent_names_are_rejected(self):
        with self.assertRaises(ValueError):
            AgentRunner([QuietAgent, QuietAgent])

    def test_empty_agent_list_is_rejected(self):
        with self.assertRaises(ValueError):
            AgentRunner([])

    def test_get_agent_results_exposes_the_handoff_payload(self):
        runner, scan_id = self._run([QuietAgent])
        results = runner.get_agent_results(scan_id)
        self.assertEqual(results["quiet"]["agent"], "quiet")

    def test_unknown_scan_id_raises(self):
        runner = AgentRunner([QuietAgent])
        with self.assertRaises(KeyError):
            runner.get_status("nope")


def _seed(path, value="1"):
    return RequestSeed(
        method="GET", url=f"{LOCAL}{path}/{value}",
        params=(RequestParameter(name="id", location="path", value=value,
                                 type="int"),),
        observed_status=200,
    )


class SeedProducer(Agent):
    name = "producer"
    unit = "endpoint"
    result_cls = ReconResult
    emits = ()

    def run(self, base: str):
        return self.finish([], tested=1, request_seeds=list(self.emits))


class SecondProducer(SeedProducer):
    name = "producer2"


class SeedConsumer(Agent):
    """Records what the runner handed it, so the assertion is on real input."""

    name = "consumer"
    unit = "object-id"
    wants_seeds = True
    received = ()

    def run(self, base: str):
        type(self).received = tuple(self.seeds)
        return self.finish([], tested=len(self.seeds))


class SeedHandoffTests(unittest.TestCase):
    """Recon's request_seeds must reach the agents that consume them.

    This is the whole reason agents got a sibling runner instead of a Scanner
    adapter, and the reason they run in order. Wiring it up was missed once:
    a correct IDOR agent plugged into the CLI reported "0 tested, completed".
    """

    def setUp(self):
        SeedConsumer.received = ()
        SeedProducer.emits = (_seed("/api/orders", "1001"),)

    def _run(self, agents):
        runner = AgentRunner(agents)
        scan_id = runner.start_scan(Target(LOCAL))
        runner.wait(scan_id, timeout=5)
        return runner, scan_id

    def test_seeds_reach_the_next_agent(self):
        runner, scan_id = self._run([SeedProducer, SeedConsumer])
        self.assertEqual([s.url for s in SeedConsumer.received],
                         [f"{LOCAL}/api/orders/1001"])
        agents = runner.get_status(scan_id)["agents"]
        self.assertEqual(agents["consumer"]["result"]["coverage"]["tested"], 1)

    def test_consumer_without_seeds_fails_instead_of_reporting_clean(self):
        runner, scan_id = self._run([SeedConsumer])
        record = runner.get_status(scan_id)["agents"]["consumer"]
        self.assertEqual(record["status"], "failed")
        # The message has to say what to do, not just that something is missing.
        self.assertIn("agent:recon", record["error"])
        self.assertTrue(any("씨앗" in w for w in runner.get_warnings(scan_id)))

    def test_order_decides_the_handoff(self):
        # Consumer first: nothing has produced seeds yet, so it must fail
        # rather than quietly test zero objects.
        runner, scan_id = self._run([SeedConsumer, SeedProducer])
        agents = runner.get_status(scan_id)["agents"]
        self.assertEqual(agents["consumer"]["status"], "failed")
        self.assertEqual(agents["producer"]["status"], "completed")

    def test_seeds_from_several_producers_are_deduped(self):
        SeedProducer.emits = (_seed("/api/orders", "1001"),)
        SecondProducer.emits = (_seed("/api/orders", "1002"),   # same template
                                _seed("/api/carts", "5"))       # new template
        self._run([SeedProducer, SecondProducer, SeedConsumer])
        self.assertEqual(
            sorted(s.template for s in SeedConsumer.received),
            ["/api/carts/{id}", "/api/orders/{id}"],
        )

    def test_recon_still_collects_under_the_runner(self):
        # Regression: the base class assigns `self.seeds`, which collided with
        # the name ReconAgent used for its own accumulator and silently emptied
        # it. Recon is the producer — if it breaks, nothing downstream runs.
        runner = AgentRunner([ReconAgent])
        scan_id = runner.start_scan(Target(LOCAL))
        runner.wait(scan_id, timeout=10)
        record = runner.get_status(scan_id)["agents"]["recon"]
        # No server here, so the crawl finds nothing — but it must not raise.
        self.assertEqual(record["status"], "completed", record["error"])
        self.assertIn("request_seeds", record["result"])


class AuthWiringTests(unittest.TestCase):
    """A configured identity that fails to authenticate must stop the agent."""

    # Nothing listens here, so every auth attempt fails deterministically.
    DEAD = "http://127.0.0.1:1"

    def _actors(self):
        return parse_actors({"actors": {"alice": {
            "cookies": {"session": "x"},
            "verify": {"path": "/whoami", "expect_status": 200}}}})

    def test_agent_does_not_run_when_authentication_fails(self):
        runner = AgentRunner([QuietAgent], actors=self._actors())
        scan_id = runner.start_scan(Target(self.DEAD))
        runner.wait(scan_id, timeout=10)

        status = runner.get_status(scan_id)
        self.assertEqual(status["status"], "failed")
        # Running anyway would scan logged out and report "nothing found".
        self.assertEqual(runner.get_results(scan_id), [])
        record = status["agents"]["quiet"]
        self.assertFalse(record["auth"]["alice"]["ok"])
        self.assertIn("인증 실패", record["error"])
        self.assertTrue(any("인증 실패" in w for w in runner.get_warnings(scan_id)))

    def test_a_scenario_pointing_off_target_is_refused_and_recorded(self):
        actors = parse_actors({"actors": {"evil": {
            "login": [{"method": "POST", "path": "http://attacker.example/steal"}],
            "verify": {"path": "/", "expect_status": 200}}}})
        runner = AgentRunner([QuietAgent], actors=actors)
        scan_id = runner.start_scan(Target(LOCAL))
        runner.wait(scan_id, timeout=10)

        record = runner.get_status(scan_id)["agents"]["quiet"]
        self.assertEqual(record["status"], "failed")
        # The safety refusal must survive into the report even though no agent
        # ran to produce an AgentCompletion.
        self.assertEqual(record["blocked"][0][0], "http://attacker.example/steal")

    def test_no_actors_means_no_auth_block(self):
        runner = AgentRunner([QuietAgent])
        scan_id = runner.start_scan(Target(LOCAL))
        runner.wait(scan_id, timeout=5)
        self.assertEqual(runner.get_status(scan_id)["agents"]["quiet"]["auth"], {})


class CombinedRunnerTests(unittest.TestCase):
    def _combined(self):
        return CombinedRunner({
            "scanners": MultiScanRunner([OkScanner()]),
            "agents": AgentRunner([QuietAgent]),
        })

    def test_merges_findings_and_per_child_detail(self):
        runner = self._combined()
        scan_id = runner.start_scan(Target(LOCAL), ScanConfig())
        runner.wait(scan_id, timeout=5)

        status = runner.get_status(scan_id)
        self.assertEqual(status["status"], "completed")
        self.assertEqual(status["findings_count"], 2)
        self.assertIn("ok", status["scanners"])
        self.assertIn("quiet", status["agents"])
        self.assertEqual(
            sorted(f.finding_id for f in runner.get_results(scan_id)),
            ["ok-1", "quiet-1"],
        )

    def test_reporters_render_both_sources(self):
        runner = self._combined()
        scan_id = runner.start_scan(Target(LOCAL), ScanConfig())
        runner.wait(scan_id, timeout=5)
        report = build_report(runner, scan_id)

        console = ConsoleReporter().render(report)
        self.assertIn("- ok:", console)
        self.assertIn("- agent:quiet:", console)

        import json
        payload = json.loads(JSONReporter().render(report))
        self.assertEqual(payload["findings_count"], 2)
        self.assertIn("quiet", payload["agents"])
        # Agent-only fields must survive the merged report.
        agent_finding = next(f for f in payload["findings"]
                             if f["scanner"] == "agent:quiet")
        self.assertEqual(agent_finding["confidence"], "firm")
        self.assertIn("evidence", agent_finding)

    def test_failed_child_makes_the_group_partial(self):
        runner = CombinedRunner({
            "scanners": MultiScanRunner([OkScanner()]),
            "agents": AgentRunner([BoomAgent]),
        })
        scan_id = runner.start_scan(Target(LOCAL), ScanConfig())
        runner.wait(scan_id, timeout=5)
        self.assertEqual(runner.get_status(scan_id)["status"], "partial")

    def test_unauthorized_target_starts_no_child(self):
        runner = self._combined()
        with self.assertRaises(TargetNotAuthorizedError):
            runner.start_scan(Target("http://8.8.8.8"))

    def test_requires_at_least_one_child(self):
        with self.assertRaises(ValueError):
            CombinedRunner({"scanners": None, "agents": None})


if __name__ == "__main__":
    unittest.main()
