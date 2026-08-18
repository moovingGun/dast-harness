"""`dast-harness ingest` — 서브에이전트가 쓴 JSON을 계약에 통과시켜 받는다.

`probe`가 **요청 방향** 통로라면 이쪽은 **결과 방향** 게이트다. LLM 서브에이전트는
Python 객체를 돌려줄 수 없으니 JSON을 쓴다. 그걸 그대로 믿고 리포트에 싣는 대신,
`AgentFinding`으로 복원해서 `validate_result()`를 통과시킨다.

    dast-harness probe  ...  →  서브에이전트가 판단  →  findings.json
                                                          ↓
                                              dast-harness ingest findings.json
                                                          ↓
                                        validate_result() 통과 → 리포트

**입력 형식은 `AgentResult.to_dict()`와 같다.** 새 형식을 만들지 않은 이유는,
Python 에이전트가 내는 것과 서브에이전트가 내는 것이 같은 모양이어야 한 리포트로
합쳐지기 때문이다. 그래서 이 명령은 우리 에이전트의 출력도 그대로 먹는다.

복원이 검사를 겸한다:

- `HttpExchange`를 다시 만들면 `__post_init__`이 **자격증명을 다시 마스킹하고**
  excerpt를 자른다. 서브에이전트가 날 토큰을 붙여넣었어도 여기서 가려진다.
- `severity`/`confidence`/`category`가 어휘 밖이면 여기서 걸린다.
- `evidence` 누락, `agent_data` 모양, `agent:` 접두사는 `validate_result()`가 본다.

에러 메시지는 사람이 아니라 **LLM에게 돌려주는 수정 지시**다. "형식 위반"이 아니라
어느 finding의 어느 필드가 왜 틀렸는지 적는다 — 그래야 서브에이전트가 고쳐서
다시 낼 수 있다.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse, urlunparse

from .agent_kit.contract import (AgentCompletion, AgentFinding, AgentResult,
                                 Confidence, Coverage, Evidence, HttpExchange,
                                 Probe, ReconResult, RequestParameter,
                                 RequestSeed, validate_result)
from .models import Severity
from .reporters import ConsoleReporter, JSONReporter, ScanReport


class IngestError(Exception):
    """JSON이 계약을 못 지켰다. 메시지가 곧 수정 지시다."""


def _require(raw, key, where, types, *, default=None):
    if key not in raw or raw[key] is None:
        if default is not None:
            return default
        raise IngestError(f"{where}: {key!r}가 필요하다")
    value = raw[key]
    if not isinstance(value, types):
        names = types if isinstance(types, type) else types
        raise IngestError(f"{where}.{key}: 타입이 맞지 않는다 ({names}를 기대)")
    return value


def _enum(cls, value, where, key):
    try:
        return cls(str(value).strip().lower())
    except ValueError:
        allowed = ", ".join(m.value for m in cls)
        raise IngestError(
            f"{where}.{key}: {value!r}는 허용되지 않는다 (허용: {allowed})"
        ) from None


def load_exchange(raw, where: str) -> HttpExchange:
    if not isinstance(raw, dict):
        raise IngestError(f"{where}: 객체여야 한다")
    status = raw.get("status")
    if status is not None and not isinstance(status, int):
        raise IngestError(f"{where}.status: 정수이거나 null이어야 한다")
    # 여기서 다시 만드는 것이 요점이다 — __post_init__이 마스킹과 길이 제한을
    # 다시 강제하므로, 서브에이전트가 뭘 붙여넣었든 규칙 5가 지켜진다.
    return HttpExchange(
        method=str(_require(raw, "method", where, str)).upper(),
        url=_require(raw, "url", where, str),
        status=status,
        actor=raw.get("actor") or "",
        request_headers=dict(raw.get("request_headers") or {}),
        request_body=raw.get("request_body"),
        response_headers=dict(raw.get("response_headers") or {}),
        response_excerpt=raw.get("response_excerpt") or "",
        note=raw.get("note") or "",
        elapsed_ms=raw.get("elapsed_ms"),
    )


def load_evidence(raw, where: str) -> Evidence:
    if not isinstance(raw, dict):
        raise IngestError(
            f"{where}: 'evidence'는 객체여야 한다. 에이전트 finding에 evidence는 "
            f"항상 필수다 (규칙 2)"
        )
    exchanges = raw.get("exchanges")
    if not isinstance(exchanges, list) or not exchanges:
        raise IngestError(f"{where}.exchanges: 비어 있지 않은 배열이어야 한다")
    return Evidence(
        exchanges=[load_exchange(e, f"{where}.exchanges[{i}]")
                   for i, e in enumerate(exchanges)],
        rationale=_require(raw, "rationale", where, str),
        baseline_index=raw.get("baseline_index"),
    )


def load_probe(raw, where: str) -> Probe:
    if not isinstance(raw, dict):
        raise IngestError(f"{where}: 객체여야 한다 (Probe)")
    return Probe(
        strategy=_require(raw, "strategy", where, str),
        target=_require(raw, "target", where, str),
        target_kind=_require(raw, "target_kind", where, str),
        attempts=raw.get("attempts") or 0,
        hits=list(raw.get("hits") or []),
        actors=list(raw.get("actors") or []),
        withheld=list(raw.get("withheld") or []),
        extra=dict(raw.get("extra") or {}),
    )


def load_finding(raw, where: str) -> AgentFinding:
    if not isinstance(raw, dict):
        raise IngestError(f"{where}: 객체여야 한다")
    # 직렬화할 때 finding_id가 "id"로 나가므로 양쪽 다 받는다.
    finding_id = raw.get("id") or raw.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id:
        raise IngestError(f"{where}: 'id'가 필요하다")

    agent_data_raw = raw.get("agent_data") or {}
    if not isinstance(agent_data_raw, dict):
        raise IngestError(f"{where}.agent_data: 객체여야 한다")
    agent_data = {
        # 값이 Probe 모양이면 복원한다. 규칙 6은 validate_finding이 본다.
        key: load_probe(value, f"{where}.agent_data.{key}")
        if isinstance(value, dict) and "strategy" in value else value
        for key, value in agent_data_raw.items()
    }

    return AgentFinding(
        scanner=_require(raw, "scanner", where, str),
        finding_id=finding_id,
        name=_require(raw, "name", where, str),
        severity=_enum(Severity, raw.get("severity"), where, "severity"),
        matched_at=_require(raw, "matched_at", where, str),
        description=raw.get("description") or "",
        tags=list(raw.get("tags") or []),
        confidence=_enum(Confidence, raw.get("confidence", "confirmed"),
                         where, "confidence"),
        category=raw.get("category") or "",
        evidence=load_evidence(raw.get("evidence"), f"{where}.evidence"),
        agent_data=agent_data,
    )


def load_seed(raw, where: str) -> RequestSeed:
    if not isinstance(raw, dict):
        raise IngestError(f"{where}: 객체여야 한다")
    params = raw.get("params") or []
    if not isinstance(params, list):
        raise IngestError(f"{where}.params: 배열이어야 한다")
    return RequestSeed(
        method=str(_require(raw, "method", where, str)).upper(),
        url=_require(raw, "url", where, str),
        params=tuple(
            RequestParameter(
                name=_require(p, "name", f"{where}.params[{i}]", str),
                location=_require(p, "location", f"{where}.params[{i}]", str),
                value=p.get("value") or "",
                type=p.get("type") or "string",
                json_path=p.get("json_path") or "",
            )
            for i, p in enumerate(params)
        ),
        body_content_type=raw.get("body_content_type") or "",
        auth_required=raw.get("auth_required"),
        observed_status=raw.get("observed_status"),
        observed_content_type=raw.get("observed_content_type") or "",
        source=raw.get("source") or "",
    )


def load_result(payload) -> AgentResult:
    """JSON(dict) → `AgentResult`. 계약 위반이면 `IngestError`.

    복원에 성공해도 `validate_result()`를 한 번 더 돌린다 — 복원은 모양을 보고,
    계약 검사는 의미(자기 이름 키, `agent:` 접두사, 증거 유무)를 본다.
    """
    if not isinstance(payload, dict):
        raise IngestError("최상위는 객체여야 한다")
    agent = _require(payload, "agent", "result", str)

    findings_raw = payload.get("findings") or []
    if not isinstance(findings_raw, list):
        raise IngestError("result.findings: 배열이어야 한다")
    findings = [load_finding(f, f"findings[{i}]")
                for i, f in enumerate(findings_raw)]

    coverage_raw = payload.get("coverage")
    if not isinstance(coverage_raw, dict):
        raise IngestError(
            "result.coverage: 객체여야 한다. 0건을 찾았어도 '무엇을 몇 개 봤는지'가 "
            "없으면 그 결과가 무슨 뜻인지 알 수 없다"
        )
    coverage = Coverage(
        unit=_require(coverage_raw, "unit", "result.coverage", str),
        tested=coverage_raw.get("tested") or 0,
        skipped=coverage_raw.get("skipped") or 0,
        skip_reasons=dict(coverage_raw.get("skip_reasons") or {}),
        findings=len(findings),
    )

    completion_raw = payload.get("completion") or {}
    completion = AgentCompletion(
        requests_made=completion_raw.get("requests_made") or 0,
        blocked=[tuple(b) for b in (completion_raw.get("blocked") or [])],
    )

    seeds_raw = payload.get("request_seeds")
    if seeds_raw is not None:
        if not isinstance(seeds_raw, list):
            raise IngestError("result.request_seeds: 배열이어야 한다")
        result = ReconResult(
            agent=agent, findings=findings, coverage=coverage,
            completion=completion,
            request_seeds=[load_seed(s, f"request_seeds[{i}]")
                           for i, s in enumerate(seeds_raw)],
        )
    else:
        result = AgentResult(agent=agent, findings=findings, coverage=coverage,
                             completion=completion)

    problems = validate_result(result)
    if problems:
        raise IngestError("계약 위반:\n  - " + "\n  - ".join(problems))
    return result


# ----------------------------------------------------------------------- CLI
def add_arguments(sub) -> None:
    ingest = sub.add_parser(
        "ingest",
        help="validate agent findings written as JSON and render them as a report",
        description=(
            "Load one or more agent results (the shape AgentResult.to_dict() "
            "produces), reconstruct them as AgentFindings, run the contract "
            "validator, and render a report. This is the gate a Claude subagent's "
            "output passes through before it counts as a finding."
        ),
    )
    ingest.add_argument("files", nargs="+", help="agent result JSON file(s)")
    ingest.add_argument("--target", help="target URL for the report header")
    ingest.add_argument("-f", "--format", choices=("console", "json"),
                        default="console")
    ingest.add_argument("-o", "--output", help="write the report to a file")


def run(args) -> int:
    results: dict[str, AgentResult] = {}
    for path in args.files:
        try:
            with open(path, encoding="utf-8") as fh:
                payload = json.load(fh)
        except OSError as exc:
            print(f"error: {path}: 읽을 수 없다 ({exc})", file=_stderr())
            return 2
        except json.JSONDecodeError as exc:
            print(f"error: {path}: 올바른 JSON이 아니다 ({exc})", file=_stderr())
            return 2
        try:
            result = load_result(payload)
        except IngestError as exc:
            print(f"error: {path}: {exc}", file=_stderr())
            return 2
        if result.agent in results:
            print(f"error: {path}: 에이전트 {result.agent!r} 결과가 두 번 들어왔다",
                  file=_stderr())
            return 2
        results[result.agent] = result

    findings = [f for r in results.values() for f in r.findings]
    status = _status(results, findings, args.target)
    report = ScanReport(status=status, findings=findings, warnings=[])
    text = (JSONReporter().render(report) if args.format == "json"
            else ConsoleReporter().render(report))

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            print(f"error: cannot write output file {args.output!r}: {exc}",
                  file=_stderr())
            return 2
        print(f"wrote {args.output}")
    else:
        print(text)
    return 0


def _status(results, findings, target) -> dict:
    agents = {}
    for name, result in results.items():
        payload = result.to_dict()
        payload.pop("findings", None)
        agents[name] = {
            "status": "completed",
            "started_at": None, "finished_at": None, "error": None,
            "findings_count": len(result.findings),
            "result": payload,
            "auth": {},
        }
    return {
        "scan_id": "ingest",
        "target": target or _origin(findings),
        "status": "completed",
        "results_partial": False,
        "exit_code": None,
        "findings_count": len(findings),
        "warnings_count": 0,
        "agents": agents,
    }


def _origin(findings) -> str:
    """리포트 헤더용 대상. `--target`을 안 줬으면 finding에서 되짚는다."""
    for finding in findings:
        parsed = urlparse(finding.matched_at)
        if parsed.scheme and parsed.netloc:
            return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    return "unknown"


def _stderr():
    import sys
    return sys.stderr


__all__ = ["IngestError", "add_arguments", "load_finding", "load_result", "run"]
