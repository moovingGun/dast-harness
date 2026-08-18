"""IDOR 에이전트가 **손대는 곳.** 판정 로직(`agent.py`)은 안 고쳐도 된다.

객체 식별자를 어떻게 바꿔볼지가 여기 있다. 새 전략을 추가하려면 함수를 하나 쓰고
`STRATEGIES`에 등록하면 된다.

전략은 **후보 값을 만들 뿐** 취약한지 판단하지 않는다. 판단은 `agent.py`가
기준선/공격/대조를 비교해서 한다 — 그 분리를 지켜야 전략을 늘려도 오탐이 안 는다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

NUMERIC = re.compile(r"^\d+$")

# 한 파라미터에 시도할 후보 수 상한. 순차 id는 무한히 만들 수 있으므로 여기서 끊는다.
MAX_CANDIDATES = 4


@dataclass(frozen=True)
class Candidate:
    """시험해볼 값 하나."""

    value: str
    strategy: str
    note: str


def sequential(value: str) -> list[Candidate]:
    """`1001` → `1002`, `1000`. 이웃 객체가 남의 것일 가능성이 제일 높다."""
    if not NUMERIC.match(value):
        return []
    n = int(value)
    out = [Candidate(str(n + 1), "sequential-id", f"이웃 객체 (+1)")]
    if n - 1 > 0:
        out.append(Candidate(str(n - 1), "sequential-id", "이웃 객체 (-1)"))
    return out


def boundary(value: str) -> list[Candidate]:
    """`1`처럼 제일 먼저 만들어졌을 객체. 보통 관리자나 첫 사용자 것이다."""
    if not NUMERIC.match(value) or value == "1":
        return []
    return [Candidate("1", "boundary-id", "첫 번째 객체 (관리자일 가능성)")]


# 순서대로 시도한다. 앞쪽이 신호가 강한 것.
STRATEGIES: tuple[Callable[[str], list[Candidate]], ...] = (sequential, boundary)


def candidates_for(value: str) -> list[Candidate]:
    """중복을 없애고 원래 값은 빼서 후보 목록을 만든다."""
    seen = {value}
    out: list[Candidate] = []
    for strategy in STRATEGIES:
        for candidate in strategy(value):
            if candidate.value in seen:
                continue
            seen.add(candidate.value)
            out.append(candidate)
            if len(out) >= MAX_CANDIDATES:
                return out
    return out


__all__ = ["Candidate", "STRATEGIES", "MAX_CANDIDATES", "candidates_for",
           "sequential", "boundary"]
