"""에이전트 키트 — 스캐너와 같은 안전 경계 위에서 에이전트를 만드는 최소 도구.

에이전트를 만들 때 이 다섯 개만 알면 된다:

    from dast_harness.agent_kit import (
        Agent, AgentHttpClient, AgentFinding, Confidence, Probe,
    )

`Agent`를 상속하고 `run()`을 구현한다. `Probe`는 규칙 6이 요구하는 타입이므로
`agent_data`에 반드시 들어간다. HTTP는 `AgentHttpClient`로만 보낸다.

`recon.py`가 동작하는 골격이다. 명세를 처음부터 구현하지 말고 복사해서
`_probe()`만 고쳐라. 결과 형식 계약은 `finding-v0-proposal.md`에 있다.
"""

from .base import Agent
from .contract import (CATEGORIES, MAX_EXCERPT, TARGET_KINDS, AgentFinding,
                       AgentResult, Confidence, Coverage, Endpoint, Evidence,
                       HttpExchange, Probe, finding_to_dict, validate_finding,
                       validate_result)
from .http import AgentHttpClient, RequestBudgetExceeded

__all__ = [
    "Agent",
    "AgentHttpClient",
    "RequestBudgetExceeded",
    "AgentFinding",
    "AgentResult",
    "Confidence",
    "Coverage",
    "Endpoint",
    "Evidence",
    "HttpExchange",
    "Probe",
    "validate_finding",
    "validate_result",
    "finding_to_dict",
    "CATEGORIES",
    "MAX_EXCERPT",
    "TARGET_KINDS",
]
