"""에이전트 실행 — `ScanRunner`의 **형제**이지 하위 타입이 아니다.

에이전트를 `Scanner` 어댑터로 감싸지 않은 이유는 하나다. `Scanner.run()`은 결과를
`on_finding(Finding)` 콜백으로만 흘리는데, 정찰의 주 산출물인 `request_seeds`
(injection/IDOR 에이전트의 입력)를 보낼 채널이 거기에 없다. 어댑터로 감싸면 그
산출물을 out-of-band로 빼야 하고, 그 순간 세 에이전트를 똑같이 다룬다는 계약이
깨진다. 그래서 같은 메서드 이름(`start_scan`/`wait`/`get_status`/`get_results`/
`get_warnings`/`stop_scan`)만 맞춘 별도 러너를 둔다 — 리포터는 안 고쳐도 된다.

**에이전트는 순차로 돈다.** 스캐너를 병렬로 돌리는 이유는 각자 서브프로세스로
수 분씩 걸리기 때문이지만, 에이전트는 인프로세스이고 정찰 → injection/IDOR로
씨앗을 넘기는 순서가 어차피 필요하다.

중단에 대해 정직하게: 에이전트는 인프로세스 루프라 밖에서 죽일 수 없다. 여기서
`stop_scan()`은 **에이전트와 에이전트 사이**에서만 듣는다. 실행 중인 에이전트를
요청 단위로 끊으려면 `AgentHttpClient`에 stop_event가 들어가야 하고, 그건 아직
없다. 그래서 실제로 건너뛴 에이전트가 있을 때만 STOPPED로 적는다 — 안 멈췄는데
멈췄다고 보고하지 않는다.
"""

from __future__ import annotations

import threading
import time
import uuid

from .agent_kit.auth import Actor, establish
from .agent_kit.base import Agent
from .agent_kit.http import AgentHttpClient
from .models import Finding, ScanConfig, ScanState, ScanStatus, Target
from .orchestrator import rollup_status
from .safety import authorize_target

# 에이전트 하나에 허용하는 요청 수. 에이전트마다 클라이언트를 따로 주므로
# 이 상한도 에이전트마다 따로 적용된다 (아래 _run_one 주석 참고).
DEFAULT_MAX_REQUESTS = 500

_DEFAULT_TIMEOUT = 10.0


class AgentRunner:
    """에이전트들을 한 타겟에 순차로 돌리고, 스캐너와 같은 상태 뷰를 낸다."""

    def __init__(
        self,
        agents: list[type[Agent]],
        allowlist: set[str] | None = None,
        *,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        actors: dict[str, Actor] | None = None,
    ) -> None:
        if not agents:
            raise ValueError("at least one agent is required")
        names = [a.name for a in agents]
        if not all(names):
            raise ValueError("every agent must set a non-empty name")
        if len(names) != len(set(names)):
            raise ValueError(f"agent names must be unique, got {names}")
        self.agents = list(agents)
        self.allowlist = allowlist or set()
        self.max_requests = max_requests
        self.actors = dict(actors or {})
        self._scans: dict[str, ScanState] = {}
        self._records: dict[str, dict[str, dict]] = {}  # scan_id -> name -> record
        self._stop_events: dict[str, threading.Event] = {}
        self._timed_out: dict[str, bool] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 시작
    def start_scan(self, target: Target, config: ScanConfig | None = None) -> str:
        """타겟을 인증하고 백그라운드에서 에이전트들을 돌린다.

        `AgentHttpClient`가 매 요청마다 다시 인증하지만, 여기서 먼저 막아야
        인가되지 않은 타겟에 스레드조차 뜨지 않는다.
        """
        config = config or ScanConfig()
        auth = authorize_target(target.url, self.allowlist)  # may raise

        scan_id = uuid.uuid4().hex[:12]
        state = ScanState(
            scan_id=scan_id, target=target, authorization_reason=auth.reason
        )
        stop_event = threading.Event()
        with self._lock:
            self._scans[scan_id] = state
            self._stop_events[scan_id] = stop_event
            self._records[scan_id] = {}

        thread = threading.Thread(
            target=self._run, args=(scan_id, state, config, stop_event), daemon=True
        )
        thread.start()
        return scan_id

    # ------------------------------------------------------------------ 실행
    def _run(
        self,
        scan_id: str,
        state: ScanState,
        config: ScanConfig,
        stop_event: threading.Event,
    ) -> None:
        try:
            self._execute(scan_id, state, config, stop_event)
        except Exception as exc:  # noqa: BLE001 - wait()가 매달리면 안 된다
            if state.is_active():
                state.mark_finished(
                    ScanStatus.FAILED, time.time(), exit_code=None,
                    error=f"agent run post-processing failed: {exc!r}",
                )
        finally:
            # 마지막 안전망: 어떤 경로로도 종료 상태에 못 닿았으면 FAILED로 못박고
            # 항상 done을 푼다 (wait()가 여기에 매달려 있다).
            if state.is_active():
                try:
                    state.mark_finished(
                        ScanStatus.FAILED, time.time(), exit_code=None,
                        error="agent run ended without a terminal status",
                    )
                except Exception:  # noqa: BLE001 - 최후 수단, done을 막으면 안 된다
                    pass
            state.done.set()

    def _execute(
        self,
        scan_id: str,
        state: ScanState,
        config: ScanConfig,
        stop_event: threading.Event,
    ) -> None:
        state.mark_running(time.time())
        for agent_cls in self.agents:
            if stop_event.is_set():
                # 중단은 에이전트 경계에서만 듣는다. 안 돈 에이전트는 안 돌았다고
                # 적는다 — 완료로 세면 커버리지가 거짓말이 된다.
                record = _record(
                    ScanStatus.STOPPED, started_at=None, finished_at=None,
                    error="중단 요청으로 실행되지 않음",
                )
            else:
                record = self._run_one(agent_cls, state, config)
            with self._lock:
                self._records[scan_id][agent_cls.name] = record

        records = self._agent_records(scan_id)
        status = ScanStatus(rollup_status([r["status"] for r in records.values()]))
        # 실패한 에이전트의 사유를 그룹 상태로 올린다. 여기서 안 올리면 리포트에
        # "failed"만 뜨고 왜 실패했는지는 per-agent 블록을 열어야만 보인다.
        errors = [
            f"{name}: {r['error']}" for name, r in records.items()
            if r["status"] == ScanStatus.FAILED.value and r.get("error")
        ]
        state.mark_finished(
            status, time.time(), exit_code=None,
            error="; ".join(errors) if errors else None,
        )

    def _run_one(
        self, agent_cls: type[Agent], state: ScanState, config: ScanConfig
    ) -> dict:
        """에이전트 하나를 돌리고 그 결과를 상태에 흘린다.

        클라이언트는 **에이전트마다 새로 만든다.** 하나를 공유하면
        `AgentCompletion.requests_made`와 `blocked`가 앞 에이전트 것까지 합산돼
        "이 에이전트가 몇 번 요청했나"라는 계약이 조용히 거짓이 된다.

        따라서 인증도 에이전트마다 다시 세운다. 로그인 요청이 에이전트 수만큼
        늘지만(보통 1~2회), 그 대가로 한 에이전트의 세션 만료가 다음 에이전트를
        오염시키지 않는다. 세션을 공유해서 아끼기에는 "만료된 세션으로 조용히
        비로그인 스캔"이 너무 비싼 실패다.
        """
        client = AgentHttpClient(
            allowlist=self.allowlist,
            max_requests=self.max_requests,
            timeout=config.request_timeout or _DEFAULT_TIMEOUT,
        )
        started_at = time.time()

        auth = establish(client, self.actors, state.target.url) if self.actors else {}
        failed = [r for r in auth.values() if not r.ok]
        if failed:
            # 인증에 실패한 채로 계속 돌면 에이전트가 비로그인으로 훑고 "취약점
            # 없음"을 보고한다. 깨끗한 성적표로 보이는 미탐이라 여기서 세운다.
            reason = "; ".join(f"{r.actor}: {r.reason}" for r in failed)
            state.add_warning(f"[agent:{agent_cls.name}] 인증 실패 — {reason}")
            return _record(
                ScanStatus.FAILED, started_at=started_at, finished_at=time.time(),
                error=f"인증 실패로 실행하지 않음 ({reason})", auth=auth,
                # 에이전트가 안 돌면 AgentCompletion이 없어서 blocked가 통째로
                # 사라진다. 시나리오가 허가 범위 밖을 가리켰다는 증거를 여기서
                # 버리면 안 된다.
                blocked=client.blocked,
            )

        agent = agent_cls(client)
        try:
            result = agent.run(state.target.url)
        except Exception as exc:  # noqa: BLE001 - 계약 위반도 네트워크 실패도 여기로
            # 도중에 죽어도 이미 찾은 findings는 살린다. 에이전트가 self.findings에
            # 계속 append하도록 만들어진 이유가 이거다.
            for finding in agent.findings:
                state.add_finding(finding)
            state.add_warning(f"[agent:{agent_cls.name}] {exc}")
            return _record(
                ScanStatus.FAILED, started_at=started_at, finished_at=time.time(),
                error=str(exc), findings_count=len(agent.findings), auth=auth,
            )

        for finding in result.findings:
            state.add_finding(finding)

        # findings는 이미 공용 채널로 흘렸으므로 여기서는 개수만 남긴다. 같은
        # finding을 리포트 두 곳에 싣지 않는다.
        payload = result.to_dict()
        findings_count = len(payload.pop("findings", []))
        return _record(
            ScanStatus.COMPLETED, started_at=started_at, finished_at=time.time(),
            findings_count=findings_count, result=payload, auth=auth,
        )

    # ------------------------------------------------------------------ 조회
    def _get(self, scan_id: str) -> ScanState:
        with self._lock:
            if scan_id not in self._scans:
                raise KeyError(f"unknown scan_id {scan_id!r}")
            return self._scans[scan_id]

    def _agent_records(self, scan_id: str) -> dict[str, dict]:
        with self._lock:
            return dict(self._records.get(scan_id, {}))

    def get_status(self, scan_id: str) -> dict:
        state = self._get(scan_id)
        snapshot = state.snapshot()
        records = self._agent_records(scan_id)
        clean = {
            ScanStatus.COMPLETED.value,
            ScanStatus.COMPLETED_WITH_WARNINGS.value,
        }
        snapshot["results_partial"] = snapshot["status"] not in clean
        # 에이전트별 산출물(coverage/completion/request_seeds)이 리포트로 나가는
        # 통로. 어댑터로 감쌌다면 이 자리가 없었다.
        snapshot["agents"] = records
        return snapshot

    def get_results(self, scan_id: str) -> list[Finding]:
        return self._get(scan_id).findings()

    def get_warnings(self, scan_id: str) -> list[str]:
        return self._get(scan_id).warnings()

    def get_agent_results(self, scan_id: str) -> dict[str, dict]:
        """에이전트 이름 → 산출물(dict). 정찰의 `request_seeds`가 여기 있다."""
        self._get(scan_id)  # KeyError if unknown
        return {
            name: record["result"]
            for name, record in self._agent_records(scan_id).items()
            if record.get("result") is not None
        }

    # ------------------------------------------------------------------ 제어
    def stop_scan(self, scan_id: str) -> None:
        """중단을 요청한다. **에이전트 경계에서만** 듣는다 (모듈 docstring 참고)."""
        state = self._get(scan_id)
        with self._lock:
            event = self._stop_events.get(scan_id)
        if event is not None and state.is_active():
            state.mark_stop_requested()
            event.set()

    def wait(self, scan_id: str, timeout: float | None = None) -> dict:
        state = self._get(scan_id)
        state.done.wait(timeout)
        if timeout is not None and state.is_active():
            # 마감이 지났는데 아직 돈다. 스캐너와 달리 프로세스를 죽일 수 없으므로
            # 중단을 요청만 하고, 실제로 안 멈추면 RUNNING으로 남는다 (정직하게).
            with self._lock:
                self._timed_out[scan_id] = True
            self.stop_scan(scan_id)
        return self.get_status(scan_id)

    def timed_out(self, scan_id: str) -> bool:
        self._get(scan_id)  # KeyError if unknown
        with self._lock:
            return self._timed_out.get(scan_id, False)

    def list_scans(self) -> list[dict]:
        with self._lock:
            ids = list(self._scans)
        return [self.get_status(scan_id) for scan_id in ids]


def _record(
    status: ScanStatus,
    *,
    started_at: float | None,
    finished_at: float | None,
    error: str | None = None,
    findings_count: int = 0,
    result: dict | None = None,
    auth: dict | None = None,
    blocked: list | None = None,
) -> dict:
    record = {
        "status": status.value,
        "started_at": started_at,
        "finished_at": finished_at,
        "error": error,
        "findings_count": findings_count,
        "result": result,
        # 어느 신원으로 돌았는지. 인증 없이 돈 결과와 alice로 돈 결과는 다른
        # 물건이라, 리포트만 보고 구별할 수 있어야 한다.
        "auth": {name: r.to_dict() for name, r in (auth or {}).items()},
    }
    if blocked:
        record["blocked"] = [list(b) for b in blocked]
    return record


class CombinedRunner:
    """스캐너 러너와 에이전트 러너를 하나의 스캔으로 묶는다.

    `build_report`가 쓰는 다섯 메서드만 맞추므로 리포터는 이 클래스를 몰라도 된다.
    자식이 하나뿐이어도(에이전트만, 또는 스캐너만) 그대로 동작한다.
    """

    def __init__(self, children: dict[str, object], allowlist: set[str] | None = None) -> None:
        children = {k: v for k, v in children.items() if v is not None}
        if not children:
            raise ValueError("at least one child runner is required")
        self._children = children
        self.allowlist = allowlist or set()
        self._groups: dict[str, dict[str, str]] = {}
        self._lock = threading.Lock()

    def start_scan(self, target: Target, config: ScanConfig | None = None) -> str:
        # 자식들도 각자 인증하지만, 먼저 여기서 막아야 절반만 시작되는 일이 없다.
        authorize_target(target.url, self.allowlist)  # may raise

        group_id = uuid.uuid4().hex[:12]
        started: dict[str, str] = {}
        try:
            for key, runner in self._children.items():
                started[key] = runner.start_scan(target, config)
        except Exception:
            # 뒤늦게 실패하면 이미 시작한 자식을 고아로 남기지 않는다.
            for key, child_id in started.items():
                self._children[key].stop_scan(child_id)
                self._children[key].wait(child_id, 2.0)
            raise
        with self._lock:
            self._groups[group_id] = started
        return group_id

    def _mapping(self, group_id: str) -> dict[str, str]:
        with self._lock:
            if group_id not in self._groups:
                raise KeyError(f"unknown scan_id {group_id!r}")
            return self._groups[group_id]

    def _parts(self, group_id: str) -> dict[str, dict]:
        return {
            key: self._children[key].get_status(child_id)
            for key, child_id in self._mapping(group_id).items()
        }

    def get_status(self, group_id: str) -> dict:
        parts = self._parts(group_id)
        clean = {
            ScanStatus.COMPLETED.value,
            ScanStatus.COMPLETED_WITH_WARNINGS.value,
        }
        merged = {
            "scan_id": group_id,
            "target": next(iter(parts.values()))["target"],
            "status": rollup_status([p["status"] for p in parts.values()]),
            "results_partial": any(
                p.get("results_partial", p["status"] not in clean)
                for p in parts.values()
            ),
            "exit_code": None,  # 프로세스가 여럿이라 의미가 없다
            "findings_count": sum(p.get("findings_count", 0) for p in parts.values()),
            "warnings_count": sum(p.get("warnings_count", 0) for p in parts.values()),
        }
        # 자식별 상세는 각자의 키 아래 그대로 옮긴다 (scanners / agents).
        for key, part in parts.items():
            detail = part.get(key)
            if detail:
                merged[key] = detail
        errors = [p["error"] for p in parts.values() if p.get("error")]
        if errors:
            merged["error"] = "; ".join(errors)
        return merged

    def get_results(self, group_id: str) -> list[Finding]:
        results: list[Finding] = []
        for key, child_id in self._mapping(group_id).items():
            results.extend(self._children[key].get_results(child_id))
        return results

    def get_warnings(self, group_id: str) -> list[str]:
        warnings: list[str] = []
        for key, child_id in self._mapping(group_id).items():
            warnings.extend(self._children[key].get_warnings(child_id))
        return warnings

    def stop_scan(self, group_id: str) -> None:
        for key, child_id in self._mapping(group_id).items():
            self._children[key].stop_scan(child_id)

    def wait(self, group_id: str, timeout: float | None = None) -> dict:
        """그룹 전체에 하나의 마감을 준다 (자식마다 따로가 아니라)."""
        mapping = self._mapping(group_id)
        deadline = None if timeout is None else time.monotonic() + timeout
        for key, child_id in mapping.items():
            remaining = (
                None if deadline is None else max(0.0, deadline - time.monotonic())
            )
            self._children[key].wait(child_id, remaining)
        return self.get_status(group_id)

    def timed_out(self, group_id: str) -> bool:
        return any(
            self._children[key].timed_out(child_id)
            for key, child_id in self._mapping(group_id).items()
        )


__all__ = ["AgentRunner", "CombinedRunner", "DEFAULT_MAX_REQUESTS"]
