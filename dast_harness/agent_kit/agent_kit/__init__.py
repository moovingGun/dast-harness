"""에이전트 키트 — 스캐너와 같은 안전 경계 위에서 에이전트를 만드는 최소 도구.

에이전트를 만들 때 이 세 개만 알면 된다:

    from dast_harness.agent_kit import AgentHttpClient, AgentFinding, Confidence

`recon.py`가 동작하는 골격이다. 복사해서 `_probe()`만 고쳐라.
"""

from .contract import (CATEGORIES, MAX_EXCERPT, AgentFinding, Confidence,
                       Endpoint, Evidence, HttpExchange, finding_to_dict,
                       validate_finding)
from .http import AgentHttpClient, RequestBudgetExceeded

__all__ = [
    "AgentHttpClient",
    "RequestBudgetExceeded",
    "AgentFinding",
    "Confidence",
    "Endpoint",
    "Evidence",
    "HttpExchange",
    "validate_finding",
    "finding_to_dict",
    "CATEGORIES",
    "MAX_EXCERPT",
]
