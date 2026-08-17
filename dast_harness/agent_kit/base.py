"""에이전트 인터페이스. `scanners/base.py`의 `Scanner`에 대응하는 에이전트판.

스캐너는 `Scanner` ABC가 `is_available()`/`run()`을 강제해서 nuclei와 nikto를
오케스트레이터가 똑같이 다룰 수 있다. 에이전트에는 그 대응물이 없어서
생성자 시그니처도 `run()` 반환값도 사람마다 달라질 수 있었다.

에이전트를 만들 때는 `recon.py`를 복사해라. 이 파일을 직접 읽을 필요는 없다.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping

from ..models import Finding
from .contract import (AgentCompletion, AgentResult, Coverage, validate_result)
from .http import AgentHttpClient


class Agent(ABC):
    """정찰/injection/IDOR 에이전트의 공통 골격.

    구현할 것은 `run()` 하나다. 마지막 줄을 `return self.finish(...)`로 끝내면
    `AgentResult`가 계약대로 채워지고 검사까지 된다.
    """

    name: str = ""              # "recon" / "injection" / "idor". scanner는 f"agent:{name}"
    unit: str = "endpoint"      # Coverage.unit — 이 에이전트가 세는 단위
    result_cls: type[AgentResult] = AgentResult   # 고유 산출물이 있으면 하위 타입으로

    def __init__(self, client: AgentHttpClient) -> None:
        # 에이전트는 이 클라이언트만 쓴다. 직접 requests를 쓰면 안전 경계를 우회한다.
        self.client = client
        # 찾는 대로 여기에 append 한다. 중단되더라도 여기까지는 살아남는다.
        self.findings: list[Finding] = []

    @abstractmethod
    def run(self, base: str) -> AgentResult:
        """`base`를 스캔하고 `AgentResult`를 돌려준다.

        마지막은 `return self.finish(...)`로 끝낸다.
        """

    def finish(
        self,
        findings: Iterable[Finding],
        *,
        tested: int,
        skipped: int = 0,
        skip_reasons: Mapping[str, int] | None = None,
        **extra,
    ) -> AgentResult:
        """결과를 만들고 계약을 검사한다. 위반이면 `AssertionError`.

        `coverage.findings`와 요청 수, `blocked`를 여기서 채우므로 손으로 세다가
        틀릴 일이 없다. 계약 위반을 조용히 넘기지 않는 게 요점이다 — 이 검사를
        지우면 세 에이전트가 다시 어긋난다.

        `**extra`는 `result_cls`의 고유 필드로 넘어간다
        (정찰이면 `request_seeds=[...]`).
        """
        findings = list(findings)
        result = self.result_cls(
            agent=self.name,
            findings=findings,
            coverage=Coverage(
                unit=self.unit,
                tested=tested,
                skipped=skipped,
                skip_reasons=dict(skip_reasons or {}),
                findings=len(findings),
            ),
            completion=AgentCompletion(
                requests_made=self.client.request_count,
                blocked=list(self.client.blocked),
            ),
            **extra,
        )
        problems = validate_result(result)
        if problems:
            raise AssertionError(f"계약 위반: {problems}")
        return result


__all__ = ["Agent"]
