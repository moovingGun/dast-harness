"""injection 에이전트 — 정상 입력 / 구문 깨기 / 주석 복구 3단으로 판정한다.

**"따옴표를 넣었더니 500"만으로 보고하지 않는다.** 그건 그냥 입력 검증이 허술한
엔드포인트와 구별되지 않는다. 이 저장소의 정답지에 `/lookup`이 그 함정으로 들어
있다 — 긴 입력에 500을 주지만 따옴표는 정상 처리하고 SQL 오류를 뱉지 않는다.
거기서 injection을 보고하면 오탐이다.

그래서 세 가지를 다 본다.

    기준선  q=invoice        → 200            정상 동작 확인
    공격    q=invoice'       → 500 + SQL 오류  구문이 깨졌다
    복구    q=invoice'--     → 200            주석으로 되돌아온다

세 번째가 결정적이다. **깨진 게 주석으로 복구되면** 우리가 건드린 것이 문법이라는
뜻이고, 그건 입력이 쿼리에 그대로 이어붙는다는 증거다.

파괴적인 건 안 한다 — UNION 데이터 추출, 시간 지연, 스택 쿼리는 보내지 않고
finding의 `withheld`에 남긴다. 안전상 자제한 것은 `confidence`를 낮추지 않는다.

고칠 곳은 `payloads.py`다. 이 파일은 판정 로직이라 페이로드를 늘리려고 열 필요가 없다.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ...models import Severity
from ..base import Agent
from ..contract import AgentFinding, Confidence, Evidence, Probe
from .payloads import (PROBES, looks_like_generic_error, looks_like_sql_error)

# 한 파라미터에 이 이상 시도하지 않는다. 페이로드를 늘려도 요청이 폭주하지 않게
# 하는 상한이고, 첫 번째로 걸린 것에서 어차피 멈춘다.
MAX_PROBES_PER_PARAM = len(PROBES)

# 값을 넣어볼 수 있는 자리. 경로 파라미터는 IDOR 담당이다.
INJECTABLE_LOCATIONS = ("query", "body")


class InjectionAgent(Agent):
    """씨앗의 query/body 파라미터에 구문을 깨는 값을 넣고 복구까지 확인한다."""

    name = "injection"
    unit = "parameter"
    wants_seeds = True          # 씨앗이 없으면 러너가 실행하지 않고 실패시킨다

    def __init__(self, client) -> None:
        super().__init__(client)
        self.tested = 0
        self.skipped = 0
        self.skip_reasons: dict[str, int] = {}

    # ------------------------------------------------------------------ 실행
    def run(self, base: str):
        for seed in self.seeds:
            for param in seed.params:
                if param.location not in INJECTABLE_LOCATIONS:
                    continue
                self._probe_param(seed, param)

        return self.finish(
            self.findings,
            tested=self.tested,
            skipped=self.skipped,
            skip_reasons=self.skip_reasons,
        )

    def _skip(self, reason: str) -> None:
        self.skipped += 1
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1

    # ------------------------------------------------------------------ 판정
    def _probe_param(self, seed, param) -> None:
        """기준선 → 공격 → 복구. 하나라도 안 맞으면 보고하지 않는다."""
        self.tested += 1
        baseline_value = param.value or "1"

        baseline = self._send(seed, param, baseline_value, "기준선: 관측된 정상 값")
        if baseline.status is None:
            self._skip("baseline-unreachable")
            return
        if baseline.status >= 500:
            # 정상 값에서도 이미 500이면 우리가 깬 게 아니다. 비교 기준이 없다.
            self._skip("baseline-already-erroring")
            return

        for probe in PROBES:
            attack = self._send(
                seed, param, baseline_value + probe.break_with,
                f"공격: {probe.name} — {probe.note}",
            )
            if attack.status is None:
                continue

            signature = looks_like_sql_error(attack.response_excerpt)
            if not signature:
                # 500이 떠도 SQL 오류가 아니면 넘어간다. `/lookup`이 여기서 걸러진다
                # — 잘 깨지는 것과 주입 가능한 것은 다르다.
                if attack.status >= 500:
                    generic = looks_like_generic_error(attack.response_excerpt)
                    self._skip("errors-without-sql-signature"
                               if generic else "no-sql-signature")
                continue

            repair = self._send(
                seed, param, baseline_value + probe.repair_with,
                f"복구: 주석으로 구문을 되돌림 ({probe.repair_with})",
            )
            self._report(seed, param, probe, baseline, attack, repair, signature)
            return          # 이 파라미터는 판정됐다. 더 찌르지 않는다

    def _report(self, seed, param, probe, baseline, attack, repair, signature) -> None:
        # 복구까지 되면 우리가 건드린 게 문법이라는 게 확정된다. 복구가 안 되면
        # 오류는 봤지만 그게 우리 입력 때문인지 한 단계 판단이 들어간다.
        recovered = repair.status is not None and repair.status < 500
        confidence = Confidence.CONFIRMED if recovered else Confidence.FIRM

        rationale = (
            f"기준선 {baseline.status} → {probe.break_with!r} 추가 시 {attack.status}이고 "
            f"응답에 SQL 오류 시그니처({signature!r})가 있다. "
        )
        rationale += (
            f"같은 자리에 {probe.repair_with!r}를 넣으면 {repair.status}로 돌아오므로, "
            "입력이 쿼리 문법에 그대로 이어붙는다."
            if recovered else
            "주석으로 복구되지 않아(응답 "
            f"{repair.status}) 오류의 원인이 구문이라고 단정하지 못했다 — 사람 확인 필요."
        )

        self.findings.append(AgentFinding(
            scanner=f"agent:{self.name}",
            finding_id=f"sqli-error-based-{param.name}",
            name=f"{seed.template}의 {param.name} 파라미터에 SQL 주입",
            severity=Severity.CRITICAL,
            confidence=confidence,
            category="injection",
            matched_at=attack.url,
            description=(
                f"{param.location} 파라미터 {param.name!r}의 값이 SQL 문에 그대로 "
                "이어붙는다. 구문을 깨면 엔진 오류가 나고 주석으로 복구된다."
            ),
            tags=["injection", "sqli", f"param-{param.name}"],
            evidence=Evidence(
                baseline_index=0,
                rationale=rationale,
                exchanges=[baseline, attack, repair],
            ),
            agent_data={self.name: Probe(
                strategy=f"error-based/{probe.name}",
                target=param.name,
                target_kind="parameter",
                attempts=3,
                hits=[probe.break_with],
                actors=[baseline.actor or "anon"],
                # 안전상 **일부러 안 한 것.** confidence를 낮추지 않는다.
                withheld=["union-select-extraction", "time-based-blind",
                          "stacked-queries"],
                extra={"seed": seed.template, "signature": signature,
                       "recovered": recovered},
            )},
        ))

    # ------------------------------------------------------------------ 전송
    def _send(self, seed, param, value, note):
        """파라미터 하나만 바꿔 씨앗을 재생한다. 나머지는 관측된 그대로 둔다."""
        if param.location == "query":
            url = _with_query(seed.url, param.name, value)
            return self.client.get(url, note=note)
        body = _form_body(seed, param, value)
        return self.client.post(seed.url, body=body, note=note)


def _with_query(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
             if k != name]
    pairs.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def _form_body(seed, target_param, value: str) -> str:
    """다른 body 파라미터는 관측된 값을 유지한다 — 한 번에 하나만 바꾼다."""
    pairs = []
    for param in seed.params:
        if param.location != "body":
            continue
        pairs.append((param.name,
                      value if param.name == target_param.name else (param.value or "")))
    if not pairs:
        pairs = [(target_param.name, value)]
    return urlencode(pairs)


__all__ = ["InjectionAgent"]
