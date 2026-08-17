"""에이전트 결과 계약 (Finding v0).

`finding-v0-proposal.md`의 코드판. 기존 `models.py`를 **건드리지 않는다** —
`AgentFinding`이 기존 `Finding`을 상속하므로 리포터·테스트가 그대로 먹는다.

v0가 팀에서 승인되면 이 파일의 필드를 `models.py`의 `Finding`으로 옮기고
`AgentFinding = Finding` 별칭만 남기면 된다. 그때 에이전트 코드는 안 고쳐도 된다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..models import Finding, Severity

MAX_EXCERPT = 2048
MASKED = "***"
SENSITIVE_HEADERS = ("authorization", "cookie", "set-cookie", "x-api-key")

# ground_truth.json이 이미 쓰는 어휘 + 에이전트용 2개.
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
class AgentFinding(Finding):
    """기존 Finding + v0 추가 필드. 전부 기본값이 있어 상속이 안전하다."""

    confidence: Confidence = Confidence.CONFIRMED
    category: str = ""
    evidence: Evidence | None = None
    agent_data: dict = field(default_factory=dict)   # 자기 이름 키 아래에만


@dataclass(frozen=True)
class Endpoint:
    """정찰의 주 산출물. 취약점이 아니라 **목록**이다 — Finding에 넣지 말 것.

    `url_template`이 값이 아니라 모양인 게 핵심이다. IDOR 에이전트는
    `/api/orders/1001`이 아니라 `/api/orders/{id}`를 받아야 "id를 바꿔본다"는
    행동을 할 수 있다.
    """

    method: str
    url_template: str                # "/api/orders/{id}"
    params: tuple[str, ...] = ()
    auth_required: bool | None = None    # None = 미확인
    observed_status: int | None = None
    content_type: str = ""
    source: str = ""                 # "link" | "robots.txt" | "guess"


def validate_finding(f: Finding) -> list[str]:
    """CLAUDE.md의 계약 5개를 검사. 빈 리스트면 통과.

    문서로만 둔 약속은 주말 이틀이면 무너지지만 assert는 안 무너진다.
    커밋 전에, 그리고 CI에서 돌린다.
    """
    errs: list[str] = []

    if f.category and f.category not in CATEGORIES:
        errs.append(f"category가 어휘 밖: {f.category!r} (허용: {', '.join(CATEGORIES)})")

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
    strays = [k for k in getattr(f, "agent_data", {}) if k != agent_name]
    if strays:
        errs.append(f"규칙4: agent_data에 남의 이름공간 침범 {strays} (허용: {agent_name!r})")

    # --- 규칙 1 보조: raw는 스캐너 원본 전용
    if f.raw:
        errs.append("에이전트는 raw를 쓰지 않는다 (agent_data를 쓸 것)")

    return errs


def finding_to_dict(f: Finding, *, include_evidence: bool = True) -> dict:
    """리포터용 직렬화. 기존 JSONReporter는 필드를 화이트리스트로 고르기 때문에
    v0 필드가 **조용히 사라진다** — 리포터를 고칠 때까지 이걸 쓴다."""
    from dataclasses import asdict

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
    if getattr(f, "agent_data", None):
        out["agent_data"] = f.agent_data
    return out


__all__ = [
    "Confidence", "HttpExchange", "Evidence", "AgentFinding", "Endpoint",
    "validate_finding", "finding_to_dict", "CATEGORIES", "MAX_EXCERPT",
    "Severity",
]
