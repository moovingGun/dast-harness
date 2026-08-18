"""IDOR 에이전트 — 자기 것 / 남의 것 / 비로그인 3단으로 판정한다.

    기준선  alice 세션으로 자기 주문 1001   → 200        정상 접근 확인
    공격    alice 세션으로 남의 주문 1002   → 200        소유권 검사가 없다
    대조    비로그인으로 1002              → 401        인증은 걸려 있다

**세 번째가 특히 중요하다.** 비로그인이 401인 걸 보여주지 않으면 "인증이 아예
없는 API"와 구별되지 않는다. 둘은 심각도도 조치 방법도 완전히 다르다.

두 번째만으로도 부족하다. 200이 떴다고 다 IDOR이 아니다 — 응답이 기준선과
**같으면** 그냥 같은 것을 돌려준 것이고(공용 리소스거나 id를 무시하는 핸들러),
그건 취약점이 아니다. 본문이 달라야 남의 것을 본 것이다.

신원은 `--auth` 시나리오가 준다. 자격증명을 여기 박지 않는다 — 대상마다 로그인
방식이 다르고(CSRF·Bearer·SSO·MFA), 박아두면 연습 타겟에서만 돈다.
`client.actors`에는 **세션이 살아있음이 확인된** 신원만 올라온다.

고칠 곳은 `strategies.py`다 (id를 어떻게 바꿔볼지). 이 파일은 판정 로직이다.
"""

from __future__ import annotations

from ...models import Severity
from ..base import Agent
from ..contract import AgentFinding, Confidence, Evidence, Probe
from .strategies import candidates_for

# 비로그인 대조에 쓰는 예약된 신원. 시나리오에서 정의할 수 없는 이름이다.
ANON = "anon"

# 객체 식별자가 실리는 자리. query/body는 injection 담당이다.
OBJECT_LOCATIONS = ("path",)


class IdorAgent(Agent):
    """씨앗의 경로 파라미터를 옆 객체로 바꿔 소유권 검사를 시험한다."""

    name = "idor"
    unit = "object-id"
    wants_seeds = True          # 씨앗이 없으면 러너가 실행하지 않고 실패시킨다

    def __init__(self, client) -> None:
        super().__init__(client)
        self.tested = 0
        self.skipped = 0
        self.skip_reasons: dict[str, int] = {}

    # ------------------------------------------------------------------ 실행
    def run(self, base: str):
        targets = [
            (seed, param)
            for seed in self.seeds
            for param in seed.params
            if param.location in OBJECT_LOCATIONS
        ]

        if not self.client.actors:
            # 세션이 없으면 판정 자체가 불가능하다. **비로그인으로 대신하지 않는다** —
            # 그러면 "인가 없음"이 아니라 "인증 없음"을 보게 되고, 0건 보고가
            # "취약하지 않음"으로 읽힌다. 못 찾은 게 아니라 안 찾아본 것이다.
            self.skip_reasons["no-auth-session"] = len(targets)
            return self.finish(self.findings, tested=0, skipped=len(targets),
                               skip_reasons=self.skip_reasons)

        owner = self.client.actors[0]
        for seed, param in targets:
            self._probe(seed, param, owner)

        return self.finish(self.findings, tested=self.tested, skipped=self.skipped,
                           skip_reasons=self.skip_reasons)

    def _skip(self, reason: str) -> None:
        self.skipped += 1
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1

    # ------------------------------------------------------------------ 판정
    def _probe(self, seed, param, owner: str) -> None:
        self.tested += 1
        baseline = self.client.get(
            seed.url, actor=owner, note=f"기준선: {owner}가 자기 객체를 조회")
        if baseline.status != 200:
            # 자기 것도 못 보면 비교 기준이 없다. 세션이 이 엔드포인트에 안 맞거나
            # 씨앗의 값이 이 신원의 것이 아니다.
            self._skip("baseline-not-200")
            return

        for candidate in candidates_for(param.value):
            attack_url = _swap(seed.url, param.value, candidate.value)
            attack = self.client.get(
                attack_url, actor=owner,
                note=f"공격: {param.name}만 {candidate.value}로 바꿈 ({candidate.note})")
            if attack.status != 200:
                continue        # 남의 것이 안 보인다 = 이 값에 대해서는 정상
            if attack.response_excerpt == baseline.response_excerpt:
                # 같은 응답이면 남의 것을 본 게 아니다. id를 무시하는 핸들러이거나
                # 공용 리소스다 — 200만 보고 보고하면 여기서 오탐이 난다.
                self._skip("same-response-as-baseline")
                continue

            control = self.client.get(
                attack_url, actor=ANON,
                note="대조: 비로그인 — 인증은 있고 인가만 없는지 가른다")
            self._report(seed, param, candidate, baseline, attack, control, owner)
            return          # 이 파라미터는 판정됐다

    def _report(self, seed, param, candidate, baseline, attack, control, owner) -> None:
        # 비로그인이 막히면 "인증은 있고 인가만 없다"가 확정된다. 안 막히면 인증
        # 자체가 없는 API일 수 있어 판단이 한 단계 들어간다.
        auth_enforced = control.status in (401, 403)
        confidence = Confidence.CONFIRMED if auth_enforced else Confidence.FIRM

        rationale = (
            f"{owner} 세션으로 자기 객체({param.value})가 {baseline.status}이고, "
            f"{param.name}만 {candidate.value}로 바꾸면 {attack.status}인데 본문이 "
            "기준선과 다르다 — 남의 객체가 보인다. "
        )
        rationale += (
            f"비로그인 요청은 {control.status}이므로 인증 자체는 걸려 있고 "
            "소유권 검사만 없다. '인증 누락'이 아니라 IDOR이다."
            if auth_enforced else
            f"다만 비로그인도 {control.status}라서 인증 자체가 없는 엔드포인트일 수 "
            "있다 — 그 경우 조치 방법이 달라지므로 사람 확인이 필요하다."
        )

        self.findings.append(AgentFinding(
            scanner=f"agent:{self.name}",
            finding_id="idor-object-ownership-missing",
            name=f"{seed.template}에 객체 소유권 검사 없음",
            severity=Severity.HIGH,
            confidence=confidence,
            category="idor",
            matched_at=attack.url,
            description=(
                f"로그인한 사용자가 {param.name}만 바꿔 타인의 객체를 조회할 수 있다."
            ),
            tags=["idor", "broken-access-control", f"param-{param.name}"],
            evidence=Evidence(
                baseline_index=0,
                rationale=rationale,
                exchanges=[baseline, attack, control],
            ),
            agent_data={self.name: Probe(
                strategy=candidate.strategy,
                target=param.name,
                target_kind="object-id",
                attempts=2,
                hits=[candidate.value],
                actors=[owner, ANON],
                # 안전상 **일부러 안 한 것.** confidence를 낮추지 않는다.
                withheld=["write-methods", "bulk-enumeration"],
                extra={"seed": seed.template, "baseline_id": param.value,
                       "auth_enforced": auth_enforced},
            )},
        ))


def _swap(url: str, old: str, new: str) -> str:
    """경로에서 관측된 값 하나만 바꾼다.

    `str.replace`를 그냥 쓰면 `/api/1001/items/1001`처럼 같은 값이 두 번 나올 때
    둘 다 바뀌어, 우리가 보내지 않은 요청을 보낸 것으로 기록된다. 마지막 것만
    바꾼다 — 객체 식별자는 보통 경로 끝에 온다.
    """
    head, sep, tail = url.rpartition(old)
    return head + new + tail if sep else url


__all__ = ["IdorAgent"]
