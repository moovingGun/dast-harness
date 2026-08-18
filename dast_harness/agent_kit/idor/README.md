# IDOR 에이전트

씨앗의 `path` 파라미터를 옆 객체로 바꿔 **소유권 검사가 있는지** 시험한다.

```python
from dast_harness.agent_kit.idor import IdorAgent
```

이 폴더는 공용 계약(`agent_kit/contract.py`, `base.py`, `http.py`) 외에 아무것도
의존하지 않는다. **폴더째 복사하면 다른 저장소로 옮겨진다.**

## 어디를 고치나

| 하고 싶은 것 | 파일 |
|---|---|
| id 변형 방식 추가 (UUID, 해시 등) | `strategies.py` |
| 판정 규칙 변경 | `agent.py` |

새 전략은 함수 하나 쓰고 `STRATEGIES`에 등록하면 된다. 전략은 **후보 값만 만들고**
취약한지는 판단하지 않는다 — 그 분리를 지켜야 전략을 늘려도 오탐이 안 는다.

## 판정 방식

```
기준선  alice 세션 → 자기 주문 1001   → 200        정상 접근
공격    alice 세션 → 남의 주문 1002   → 200        소유권 검사 없음
대조    비로그인   → 1002            → 401        인증은 걸려 있음
```

**세 번째가 특히 중요하다.** 비로그인이 401인 걸 보여주지 않으면 "인증이 아예 없는
API"와 구별되지 않는다. 둘은 심각도도 조치 방법도 완전히 다르다.

두 번째만으로도 부족하다. **200이 떴다고 다 IDOR이 아니다** — 응답이 기준선과 같으면
그냥 같은 것을 돌려준 것이고(공용 리소스거나 id를 무시하는 핸들러), 그건 취약점이
아니다. 본문이 달라야 남의 것을 본 것이다.

- 비로그인이 401/403이면 `confidence = confirmed`
- 비로그인도 통과하면 `firm` — 인증 자체가 없는 API일 수 있어 조치가 달라진다

## 신원은 `--auth`가 준다

**자격증명을 이 폴더에 박지 마라.** 대상마다 로그인 방식이 다르고(CSRF·Bearer·SSO·
MFA), 박아두면 연습 타겟에서만 돈다.

```python
owner = self.client.actors[0]     # 세션이 살아있음이 확인된 신원만 올라온다
```

`client.actors`가 비어 있으면 **비로그인으로 대신하지 않는다.** 그러면 "인가 없음"이
아니라 "인증 없음"을 보게 되고, 0건 보고가 "취약하지 않음"으로 읽힌다.
`skipped` + `skip_reasons={"no-auth-session": n}`으로 넘긴다 — 못 찾은 게 아니라
안 찾아본 것이다.

## 안 하는 것

`withheld`에 남기고 실제로는 보내지 않는다.

- `write-methods` — PUT/DELETE로 남의 객체를 수정/삭제
- `bulk-enumeration` — id를 대량으로 훑어 데이터 수집

## 직접 돌려보기

```bash
python3 targets/vulnerable_app/app.py &
```

```python
from dast_harness.agent_kit import AgentHttpClient
from dast_harness.agent_kit.auth import establish, load_actors
from dast_harness.agent_kit.recon import ReconAgent
from dast_harness.agent_kit.idor import IdorAgent

BASE = "http://127.0.0.1:8080"
recon = ReconAgent(AgentHttpClient(max_requests=200)).run(BASE)

client = AgentHttpClient(max_requests=200)
establish(client, load_actors("targets/vulnerable_app/actors.json"), BASE)
agent = IdorAgent(client)
agent.seeds = recon.request_seeds      # CLI에서는 러너가 해준다
result = agent.run(BASE)
```

CLI로 (인증을 빼먹으면 아무것도 못 본다):

```bash
dast-harness scan http://127.0.0.1:8080 -s agent:recon,agent:idor \
    --auth targets/vulnerable_app/actors.json
```

정답지의 `idor-order-object-access`를 잡는 게 정상이다.
