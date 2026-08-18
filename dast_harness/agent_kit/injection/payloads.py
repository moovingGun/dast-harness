"""injection 에이전트가 **손대는 곳.** 판정 로직(`agent.py`)은 안 고쳐도 된다.

여기 있는 건 셋이다.

1. `PROBES` — 무엇을 보낼지 (구문을 깨는 값 + 그걸 복구하는 값)
2. `SQL_ERROR_SIGNATURES` — 응답에서 무엇을 SQL 오류로 볼지
3. `GENERIC_ERROR_SIGNATURES` — SQL이 아닌 그냥 서버 오류 (오탐 방지용)

**시그니처를 늘릴 때 주의.** 여기 넓은 단어(`error`, `exception`)를 넣으면
멀쩡한 엔드포인트가 전부 injection으로 잡힌다. 이 저장소의 `/lookup`이 정확히
그런 함정이다 — 긴 입력에 500을 주지만 SQL 오류는 아니다.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Probe:
    """한 번의 시도. `break_with`로 구문을 깨고 `repair_with`로 되돌린다.

    복구가 핵심이다. "따옴표를 넣었더니 500"만으로는 그냥 입력 검증이 허술한
    엔드포인트와 구별되지 않는다. **깨진 게 주석으로 되돌아와야** 우리가 건드린
    것이 문법이었다는 뜻이다.
    """

    name: str
    break_with: str          # 기준선 값 뒤에 붙여 구문을 깬다
    repair_with: str         # 같은 자리에 붙이되 구문을 되돌린다
    note: str = ""


# 순서대로 시도하고 첫 번째로 걸린 것에서 멈춘다. 파괴적이지 않은 것만 둔다 —
# UNION/시간지연/스택쿼리는 데이터를 빼거나 서버를 붙잡으므로 여기 넣지 않는다
# (안 한 것은 finding의 `withheld`에 남는다).
PROBES: tuple[Probe, ...] = (
    Probe(
        name="single-quote",
        break_with="'",
        repair_with="'--",
        note="작은따옴표로 문자열 리터럴을 깨고 주석으로 복구",
    ),
    Probe(
        name="double-quote",
        break_with='"',
        repair_with='"--',
        note="큰따옴표를 쓰는 엔진용",
    ),
    Probe(
        name="paren-quote",
        break_with="')",
        repair_with="')--",
        note="LIKE ('%...%') 처럼 괄호 안에 들어가는 자리",
    ),
)

# 응답 본문에서 이게 보이면 SQL 오류로 본다. **엔진 이름이나 SQL 문법을 지목하는
# 문구만** 넣는다 — 일반적인 오류 단어는 아래 GENERIC 쪽이다.
SQL_ERROR_SIGNATURES: tuple[str, ...] = (
    "sql syntax",
    "syntax error at or near",          # PostgreSQL
    "unclosed quotation mark",          # MSSQL
    "quoted string not properly terminated",   # Oracle
    "you have an error in your sql",    # MySQL
    "warning: mysql",
    "mysqli_",
    "pg_query",
    "sqlite3.operationalerror",
    "ora-01756",
    "odbc sql server driver",
    "sqlstate[",
)

# SQL 오류가 아닌 그냥 서버 오류. 이게 보이고 SQL 시그니처가 **없으면** injection이
# 아니라 그냥 잘 깨지는 엔드포인트다. 보고하지 않는 근거로 쓴다.
GENERIC_ERROR_SIGNATURES: tuple[str, ...] = (
    "internal server error",
    "500 - internal",
    "traceback (most recent call last)",
    "an unexpected error",
)


def looks_like_sql_error(body: str) -> str:
    """본문에서 처음 걸린 SQL 오류 시그니처, 없으면 빈 문자열."""
    low = body.lower()
    for sig in SQL_ERROR_SIGNATURES:
        if sig in low:
            return sig
    return ""


def looks_like_generic_error(body: str) -> str:
    """SQL이 아닌 서버 오류 시그니처. 오탐을 걸러낸 이유를 적을 때 쓴다."""
    low = body.lower()
    for sig in GENERIC_ERROR_SIGNATURES:
        if sig in low:
            return sig
    return ""


__all__ = [
    "PROBES",
    "Probe",
    "SQL_ERROR_SIGNATURES",
    "GENERIC_ERROR_SIGNATURES",
    "looks_like_sql_error",
    "looks_like_generic_error",
]
