"""에이전트 결과 계약 (Finding v0).

`finding-v0-proposal.md`의 코드판. 기존 `models.py`를 **건드리지 않는다** —
`AgentFinding`이 기존 `Finding`을 상속하므로 리포터·테스트가 그대로 먹는다.

v0가 팀에서 승인되면 이 파일의 필드를 `models.py`의 `Finding`으로 옮기고
`AgentFinding = Finding` 별칭만 남기면 된다. 그때 에이전트 코드는 안 고쳐도 된다.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from urllib.parse import urlparse

from ..models import Finding, Severity

MAX_EXCERPT = 2048
MASKED = "***"
SENSITIVE_HEADERS = ("authorization", "cookie", "set-cookie", "x-api-key")

# ground_truth.json이 이미 쓰는 어휘 + 에이전트용 2개.
TARGET_KINDS = ("object-id", "parameter", "endpoint", "header", "path")

CATEGORIES = (
    "exposure",
    "information-disclosure",
    "misconfiguration",
    "idor",
    "injection",
)


class Confidence(str, Enum):
    """severity와 **별개 축**. severity=진짜면 얼마나 심각한가,
    confidence=진짜일 확신이 얼마인가. 절대 하나로 합치지 않는다.

    LLM이 뱉는 0.6/0.7은 보정된 값이 아니고 세 에이전트 간 비교도 안 된다.
    판정 기준을 글로 적은 3단계가 실제로 더 정확하고 비교 가능하다.
    """

    CONFIRMED = "confirmed"   # 첨부한 요청/응답만 보면 누구나 같은 결론
    FIRM = "firm"             # 증거는 명확하나 판단이 한 단계 들어감
    TENTATIVE = "tentative"   # 정황뿐. 사람 확인 필요


def _mask(headers: dict[str, str] | None) -> dict[str, str]:
    """자격증명 헤더 값을 마스킹. 세션 토큰이 리포트에 남으면 안 된다."""
    return {
        k: (MASKED if k.lower() in SENSITIVE_HEADERS else v)
        for k, v in (headers or {}).items()
    }


@dataclass(frozen=True)
class HttpExchange:
    """재현 가능한 요청/응답 한 쌍. 산문이 아니라 구조체여야 남이 재생할 수 있다.

    `actor`가 핵심이다 — IDOR은 "누구의 신원으로 보냈는가"가 취약점의 정의다.
    보통 손으로 만들지 않고 `AgentHttpClient.request()`가 채워서 돌려준다.
    """

    method: str
    url: str
    status: int | None
    actor: str = ""                  # "alice", "bob", "anon"
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_excerpt: str = ""       # 판단 근거가 된 부분 (MAX_EXCERPT 이내)
    note: str = ""                   # 이 요청이 왜 있는지 한 줄
    elapsed_ms: int | None = None

    def __post_init__(self) -> None:
        # frozen이라 object.__setattr__로 정규화한다. 손으로 만들어도 규칙 5가 지켜진다.
        object.__setattr__(self, "request_headers", _mask(self.request_headers))
        object.__setattr__(self, "response_headers", _mask(self.response_headers))
        if len(self.response_excerpt) > MAX_EXCERPT:
            object.__setattr__(
                self, "response_excerpt", self.response_excerpt[:MAX_EXCERPT] + "…[truncated]"
            )


@dataclass
class Evidence:
    """교환 묶음 + 왜 취약한지.

    `baseline_index`: 에이전트 취약점은 거의 다 **대조**로 증명된다.
    기준선이 몇 번째인지 명시하지 않으면 읽는 사람이 추측해야 한다.
    """

    exchanges: list[HttpExchange]
    rationale: str
    baseline_index: int | None = None


@dataclass
class Probe:
    """이 finding을 만들기까지 에이전트가 뭘 했는지. **세 에이전트 공통 모양.**

    취약점 자체는 name/severity/evidence가 설명한다. Probe는 그 옆에서
    "무엇을 겨눠 몇 번 시도했고 뭐가 걸렸나"를 남긴다. 스캐너의
    CompletionEvidence에 해당하는 에이전트판.
    """

    strategy: str                    # "sequential-id" / "error-based-sqli" / "login-differential"
    target: str                      # 겨냥한 대상: "id", "q", "/login"
    target_kind: str                 # "object-id" | "parameter" | "endpoint" | "header"
    attempts: int = 0                # 시도 횟수
    hits: list[str] = field(default_factory=list)      # 걸린 것 (id/페이로드/계정)
    actors: list[str] = field(default_factory=list)    # 사용한 신원
    withheld: list[str] = field(default_factory=list)  # 안전상 안 한 것
    extra: dict = field(default_factory=dict)          # 에이전트 고유. **여기만 자유**


@dataclass
class Coverage:
    """실행 전체 요약. finding이 0건이어도 남는다.

    "못 찾은 것"과 "안 찾아본 것"을 구분하기 위한 필드다. 이게 없으면
    탐지율 숫자가 무슨 뜻인지 알 수 없다. Finding이 아니라 run() 반환값에 담는다.
    """

    unit: str                        # "parameter" | "object-id" | "endpoint"
    tested: int = 0
    skipped: int = 0
    skip_reasons: dict = field(default_factory=dict)   # {"no-auth-session": 3}
    findings: int = 0
    # 요청 수는 여기 없다 — AgentCompletion.requests_made가 유일한 출처다.
    # 같은 값을 두 곳에 두면 한쪽만 갱신됐을 때 리포트가 자기모순을 일으킨다.


@dataclass
class AgentFinding(Finding):
    """기존 Finding + v0 추가 필드. 전부 기본값이 있어 상속이 안전하다."""

    confidence: Confidence = Confidence.CONFIRMED
    category: str = ""
    evidence: Evidence | None = None
    agent_data: dict = field(default_factory=dict)   # 자기 이름 키 아래에만


PARAM_LOCATIONS = ("query", "body", "path", "header", "cookie")
PARAM_TYPES = ("string", "int", "float", "bool", "json")


@dataclass(frozen=True)
class RequestParameter:
    """검사 대상 파라미터 하나. **위치·값·타입·JSON 경로를 보존한다.**

    이름만 넘기면 받는 쪽이 전부 다시 관측해야 한다. 네 조각이 다 필요하다:

    - `location`: injection은 query와 body를 다르게 넣고, IDOR은 `path`를 노린다
    - `value`: 관측된 값이 **주입의 기준선**이다. 정상 응답을 알아야 대조가 된다
    - `type`: 숫자 파라미터에 문자열 페이로드를 넣으면 타입 오류가 SQL 오류로 오인된다
    - `json_path`: JSON 본문은 이름만으론 위치를 못 짚는다 (`$.user.id`)
    """

    name: str
    location: str                    # PARAM_LOCATIONS
    value: str = ""                  # 관측된 값 = 주입의 기준선
    type: str = "string"             # PARAM_TYPES
    json_path: str = ""              # JSON 본문일 때만: "$.user.id"


@dataclass(frozen=True)
class RequestSeed:
    """**실제로 보낼 수 있는 검사 요청** 하나. 정찰의 주 산출물이다.

    이전 `Endpoint`는 "모양"이었다 — `/api/orders/{id}`. 씨앗은 실제 요청이라
    받는 쪽이 그대로 재생하고 **한 부분만 바꾼다.** 뭘 바꿀 수 있는지는 `params`가
    말한다: `location="path"`면 경로 세그먼트(IDOR), `"query"`/`"body"`면 값(injection).

    취약점이 아니라 목록이므로 `Finding`에 넣지 말 것 — 발견한 요청 40개가
    findings 40건이 되면 리포트가 망가진다.
    """

    method: str
    url: str                         # 절대 URL. 그대로 보낼 수 있다
    params: tuple[RequestParameter, ...] = ()
    body_content_type: str = ""      # 요청 본문 인코딩 (POST 폼이면 urlencoded)
    auth_required: bool | None = None    # None = 미확인
    observed_status: int | None = None
    observed_content_type: str = ""  # 응답 Content-Type
    source: str = ""                 # "seed"|"link"|"form"|"robots.txt"|"guess"

    @property
    def template(self) -> str:
        """`/api/orders/{id}` — 경로 파라미터를 자리표시자로 되돌린 모양.

        같은 엔드포인트의 씨앗을 하나로 묶는 키다. 이게 없으면 id마다 씨앗이
        하나씩 생겨서 목록이 값으로 뒤덮인다.
        """
        path = urlparse(self.url).path or "/"
        for p in self.params:
            if p.location == "path" and p.value:
                path = path.replace(p.value, "{%s}" % p.name)
        return path


@dataclass
class AgentCompletion:
    """실행이 **어떻게 끝났는가.** 스캐너의 `CompletionEvidence`에 대응하는 에이전트판.

    `coverage`가 "무엇을 얼마나 봤나"라면 이쪽은 "끝까지 갔나"다. 둘을 섞으면
    "0건 발견"이 완주한 결과인지 중간에 끊긴 결과인지 구별할 수 없다.

    `blocked`에는 안전장치가 거부한 요청이 남는다 — 타겟 페이지에 심어진 프롬프트
    인젝션의 흔적이 여기 쌓이므로 버리면 안 된다.

    중단/실패 여부(`stopped`/`error`)는 아직 없다. 그걸 채울 러너가 없어서 항상
    같은 값이 들어갈 뿐이었다. 배관을 붙일 때 같이 넣는다.
    """

    requests_made: int = 0
    blocked: list[tuple[str, str]] = field(default_factory=list)   # (url, 거부 사유)


@dataclass
class AgentResult:
    """에이전트 `run()`의 반환값. **세 에이전트가 같은 모양을 낸다.**

    `Finding` 하나의 모양만 맞춰도 합칠 수 없다 — 에이전트 단위 산출물도 같아야
    오케스트레이터가 셋을 똑같이 다룰 수 있다. 전에는 그냥 dict였고 키 이름을
    지켜주는 게 아무것도 없었다.

    여기에는 **세 에이전트가 공통으로 내는 것만** 둔다. 정찰의 요청 씨앗처럼
    한 에이전트에만 있는 산출물은 `ReconResult`처럼 하위 타입으로 내린다.

    보통 손으로 만들지 않고 `Agent.finish()`가 채워서 돌려준다.
    """

    agent: str                                   # "recon" (scanner는 f"agent:{agent}")
    findings: list[Finding] = field(default_factory=list)
    coverage: Coverage | None = None
    completion: AgentCompletion | None = None

    def to_dict(self) -> dict:
        return {
            "agent": self.agent,
            "findings": [finding_to_dict(f) for f in self.findings],
            "coverage": asdict(self.coverage) if self.coverage is not None else None,
            "completion": (
                _completion_dict(self.completion) if self.completion is not None else None
            ),
        }


def _completion_dict(c: AgentCompletion) -> dict:
    out = asdict(c)
    out["blocked"] = [list(b) for b in c.blocked]   # 튜플은 JSON에서 배열이 된다
    return out


@dataclass
class ReconResult(AgentResult):
    """정찰 전용 반환값. 주 산출물은 취약점이 아니라 **검사 요청 씨앗 목록**이다.

    이게 A→B,C 인터페이스다. injection/IDOR 에이전트는 `request_seeds`를 입력으로
    받아 각자 한 부분씩 바꿔본다.
    """

    request_seeds: list[RequestSeed] = field(default_factory=list)

    def to_dict(self) -> dict:
        out = super().to_dict()
        out["request_seeds"] = [asdict(s) for s in self.request_seeds]
        return out


def _seed_errors(seeds) -> list[str]:
    """요청 씨앗 검사. 씨앗은 B/C가 **그대로 재생**하는 물건이라 모양이 어긋나면
    받는 쪽에서 조용히 잘못된 요청을 보낸다."""
    errs: list[str] = []
    for i, s in enumerate(seeds):
        if not urlparse(s.url).scheme:
            errs.append(f"request_seeds[{i}]: url이 절대 URL이 아님 ({s.url!r})")
        for p in s.params:
            where = f"request_seeds[{i}] 파라미터 {p.name!r}"
            if p.location not in PARAM_LOCATIONS:
                errs.append(
                    f"{where}: location이 어휘 밖: {p.location!r} "
                    f"(허용: {', '.join(PARAM_LOCATIONS)})"
                )
            if p.type not in PARAM_TYPES:
                errs.append(
                    f"{where}: type이 어휘 밖: {p.type!r} "
                    f"(허용: {', '.join(PARAM_TYPES)})"
                )
            if p.json_path and p.location != "body":
                errs.append(f"{where}: json_path는 location='body'에서만 쓴다")
            if not p.name:
                errs.append(f"request_seeds[{i}]: 이름 없는 파라미터")
    return errs


def validate_result(r: AgentResult) -> list[str]:
    """`AgentResult` 하나를 검사. 빈 리스트면 통과. `Agent.finish()`가 돌린다.

    findings 각각의 규칙(§4)까지 여기서 같이 본다 — 에이전트가 낸 결과 전체를
    한 번에 검사할 수 있어야 CI에 걸 수 있다.
    """
    errs: list[str] = []

    if not r.agent:
        errs.append("AgentResult.agent가 비어 있음 (에이전트 이름)")

    if r.coverage is None:
        # 0건일 때 "못 찾았다"와 "안 찾아봤다"를 구별하려면 반드시 있어야 한다.
        errs.append("coverage가 없음 (findings가 0건이어도 남긴다)")
    else:
        if r.coverage.unit not in TARGET_KINDS:
            errs.append(
                f"coverage.unit이 어휘 밖: {r.coverage.unit!r} "
                f"(허용: {', '.join(TARGET_KINDS)})"
            )
        if r.coverage.findings != len(r.findings):
            errs.append(
                f"coverage.findings({r.coverage.findings})가 실제 findings "
                f"{len(r.findings)}건과 다름"
            )

    if r.completion is None:
        # coverage가 "얼마나 봤나"라면 completion은 "끝까지 갔나"다.
        errs.append("completion이 없음 (완주인지 중단인지 구별할 수 없다)")

    errs.extend(_seed_errors(getattr(r, "request_seeds", ())))

    expected_scanner = f"agent:{r.agent}"
    for f in r.findings:
        if r.agent and f.scanner != expected_scanner:
            # 남의 에이전트를 베껴 쓰면서 name만 안 바꾼 경우가 여기서 걸린다.
            errs.append(
                f"{f.finding_id}: scanner가 {f.scanner!r} (기대: {expected_scanner!r})"
            )
        errs.extend(f"{f.finding_id}: {e}" for e in validate_finding(f))

    return errs


def validate_finding(f: Finding) -> list[str]:
    """CLAUDE.md의 계약 5개를 검사. 빈 리스트면 통과.

    문서로만 둔 약속은 주말 이틀이면 무너지지만 assert는 안 무너진다.
    커밋 전에, 그리고 CI에서 돌린다.
    """
    errs: list[str] = []

    # 스캐너 Finding에는 category 필드가 없다. 스캐너/에이전트 findings를 한 리스트에
    # 담아 검사하는 게 정상 사용법이므로 getattr로 읽는다.
    category = getattr(f, "category", "")
    if category and category not in CATEGORIES:
        errs.append(f"category가 어휘 밖: {category!r} (허용: {', '.join(CATEGORIES)})")

    if not f.scanner.startswith("agent:"):
        return errs  # 스캐너 finding은 여기까지만

    # --- 규칙 3
    agent_name = f.scanner.split(":", 1)[1]
    if not agent_name:
        errs.append("규칙3: 'agent:' 뒤에 에이전트 이름이 없음")

    conf = getattr(f, "confidence", Confidence.CONFIRMED)
    ev = getattr(f, "evidence", None)

    # --- 규칙 2
    if conf is not Confidence.CONFIRMED and ev is None:
        errs.append("규칙2: confidence가 CONFIRMED가 아니면 evidence는 필수")
    if ev is None:
        errs.append("에이전트 finding에 evidence가 없음 (재현 불가)")
    else:
        if not ev.exchanges:
            errs.append("evidence.exchanges가 비어 있음")
        if not ev.rationale.strip():
            errs.append("evidence.rationale이 비어 있음 (왜 취약한지 설명 필요)")
        bi = ev.baseline_index
        if bi is not None and not (0 <= bi < len(ev.exchanges)):
            errs.append(f"baseline_index({bi})가 exchanges 범위 밖")
        for i, e in enumerate(ev.exchanges):
            for k, v in e.request_headers.items():
                if k.lower() in SENSITIVE_HEADERS and v != MASKED:
                    errs.append(f"규칙5: exchanges[{i}] {k} 미마스킹")
            if len(e.response_excerpt) > MAX_EXCERPT + 16:
                errs.append(f"규칙5: exchanges[{i}] excerpt가 {MAX_EXCERPT}자 초과")

    # --- 규칙 4
    data = getattr(f, "agent_data", {})
    strays = [k for k in data if k != agent_name]
    if strays:
        errs.append(f"규칙4: agent_data에 남의 이름공간 침범 {strays} (허용: {agent_name!r})")

    # --- 규칙 6: agent_data[<이름>]은 Probe 모양이어야 한다
    probe = data.get(agent_name)
    if probe is None:
        errs.append(f"규칙6: agent_data[{agent_name!r}]에 Probe가 없음")
    else:
        d = probe if isinstance(probe, dict) else getattr(probe, "__dict__", {})
        missing = [k for k in ("strategy", "target", "target_kind") if not d.get(k)]
        if missing:
            errs.append(f"규칙6: Probe에 {missing} 누락")
        if d.get("target_kind") not in TARGET_KINDS:
            errs.append(f"규칙6: target_kind가 어휘 밖: {d.get('target_kind')!r}")

    # --- 규칙 1 보조: raw는 스캐너 원본 전용
    if f.raw:
        errs.append("에이전트는 raw를 쓰지 않는다 (agent_data를 쓸 것)")

    return errs


def finding_to_dict(f: Finding, *, include_evidence: bool = True) -> dict:
    """리포터용 직렬화. 기존 JSONReporter는 필드를 화이트리스트로 고르기 때문에
    v0 필드가 **조용히 사라진다** — 리포터를 고칠 때까지 이걸 쓴다."""
    from dataclasses import asdict, is_dataclass

    out = {
        "scanner": f.scanner,
        "id": f.finding_id,
        "name": f.name,
        "severity": f.severity.value,
        "confidence": getattr(f, "confidence", Confidence.CONFIRMED).value,
        "category": getattr(f, "category", ""),
        "matched_at": f.matched_at,
        "description": f.description,
        "tags": list(f.tags),
    }
    ev = getattr(f, "evidence", None)
    if include_evidence and ev is not None:
        out["evidence"] = asdict(ev)
    data = getattr(f, "agent_data", None)
    if data:
        # 규칙6이 요구하는 Probe는 dataclass다. 펴지 않으면 json.dumps가 터진다.
        out["agent_data"] = {
            k: asdict(v) if is_dataclass(v) else v for k, v in data.items()
        }
    return out


__all__ = [
    "Confidence", "HttpExchange", "Evidence", "AgentFinding",
    "RequestParameter", "RequestSeed", "Probe", "Coverage",
    "AgentCompletion", "AgentResult", "ReconResult",
    "TARGET_KINDS", "PARAM_LOCATIONS", "PARAM_TYPES",
    "validate_finding", "validate_result", "finding_to_dict",
    "CATEGORIES", "MAX_EXCERPT", "Severity",
]
