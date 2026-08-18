# injection 에이전트

씨앗의 `query`/`body` 파라미터에 SQL 구문을 깨는 값을 넣고, **주석으로 복구되는지까지**
확인해서 판정한다.

```
from dast_harness.agent_kit.injection import InjectionAgent
```

이 폴더는 공용 계약(`agent_kit/contract.py`, `base.py`, `http.py`) 외에 아무것도
의존하지 않는다. **폴더째 복사하면 다른 저장소로 옮겨진다.**

## 어디를 고치나

| 하고 싶은 것 | 파일 |
|---|---|
| 페이로드 추가/변경 | `payloads.py`의 `PROBES` |
| 오류 시그니처 추가 | `payloads.py`의 `SQL_ERROR_SIGNATURES` |
| 판정 규칙 변경 | `agent.py` |

대부분은 `payloads.py`만 만지면 된다.

## 판정 방식

```
기준선  q=invoice        → 200            정상 동작
공격    q=invoice'       → 500 + SQL 오류  구문이 깨졌다
복구    q=invoice'--     → 200            주석으로 되돌아온다
```

**세 번째가 결정적이다.** "따옴표를 넣었더니 500"만으로는 그냥 입력 검증이 허술한
엔드포인트와 구별되지 않는다. 깨진 게 주석으로 복구되면 우리가 건드린 것이 **문법**
이라는 뜻이고, 그건 입력이 쿼리에 그대로 이어붙는다는 증거다.

- 복구까지 되면 `confidence = confirmed`
- 오류는 봤지만 복구가 안 되면 `firm` (사람 확인 필요)
- SQL 오류 시그니처가 없으면 **보고하지 않는다**

## 오탐 함정

정답지의 `must_not_detect`에 `/lookup`이 있다. 긴 입력에 500을 주지만 따옴표는
정상 처리하고 SQL 오류를 뱉지 않는다. **거기서 injection을 보고하면 감점이다.**

시그니처를 늘릴 때 `error`, `exception` 같은 넓은 단어를 넣으면 정확히 이 함정에
걸린다. 엔진 이름이나 SQL 문법을 지목하는 문구만 넣는다.

## 안 하는 것

`withheld`에 남기고 실제로는 보내지 않는다.

- `union-select-extraction` — 데이터 추출
- `time-based-blind` — 서버를 붙잡는다
- `stacked-queries` — 상태를 바꾼다

**안전상 자제한 것은 `confidence`를 낮추지 않는다.** 그건 증거의 약점이 아니다.

## 직접 돌려보기

```bash
python3 targets/vulnerable_app/app.py &
```

```python
from dast_harness.agent_kit import AgentHttpClient
from dast_harness.agent_kit.recon import ReconAgent
from dast_harness.agent_kit.injection import InjectionAgent

BASE = "http://127.0.0.1:8080"
recon = ReconAgent(AgentHttpClient(max_requests=200)).run(BASE)
agent = InjectionAgent(AgentHttpClient(max_requests=200))
agent.seeds = recon.request_seeds      # CLI에서는 러너가 해준다
result = agent.run(BASE)
```

CLI로:

```bash
dast-harness scan http://127.0.0.1:8080 -s agent:recon,agent:injection
python -m dast_harness.validate -s agent:recon,agent:injection
```

정답지의 `sqli-error-based-search-q`를 잡고 `/lookup`은 안 건드리는 게 정상이다.
