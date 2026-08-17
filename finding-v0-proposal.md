# Finding v0 — 에이전트 결과 형식 (합의용 초안)

> 목적: IDOR / injection / 정찰 에이전트가 **같은 모양의 결과**를 내게 한다.
> 이 문서는 확정본이 아니라 **15분 리뷰용 초안**이다. 빠진 것/틀린 것 말해줘.
> 승인되면 `dast_harness/models.py`에 반영한다.

---

## 0. 왜 코드보다 이걸 먼저 정하는가

취약 앱에 표면이 없으면 **테스트가 늦어질** 뿐이다. 하지만 결과 형식이 다르면
셋이 각자 만든 걸 **합칠 수가 없다.** 앞의 건 지연이고 뒤의 건 재작업이다.

지금 얼리는 건 **필수 필드와 그 의미**뿐이다. 네이밍 체계, severity 기준,
중복 제거 규칙은 각자 실제 finding을 하나씩 본 뒤에 정한다 (§6).

---

## 1. 기존 `Finding`은 그대로 둔다

지금 하네스의 `Finding`은 nuclei/nikto 결과를 정규화하는 데 쓰이고 있고,
리포터·테스트가 전부 여기에 물려 있다. **필드를 지우거나 이름을 바꾸지 않는다.**
추가하는 필드는 전부 기본값을 가지므로 기존 스캐너 어댑터는 한 줄도 안 고친다.

```python
# 기존 (변경 없음)
scanner: str
finding_id: str
name: str
severity: Severity
matched_at: str
description: str = ""
tags: list[str] = field(default_factory=list)
raw: dict = field(default_factory=dict)
```

### 한 가지 약속: `scanner` 필드는 "만든 주체"로 읽는다

에이전트는 스캐너가 아니지만, 이름을 바꾸면 리포터·테스트가 전부 깨진다.
필드는 그대로 두고 **의미만 넓힌다.** 대신 접두사를 강제한다.

| 만든 주체 | `scanner` 값 |
|---|---|
| 스캐너 | `nuclei`, `nikto` |
| 에이전트 | `agent:recon`, `agent:injection`, `agent:idor` |

`agent:` 접두사가 있으면 필터링·집계가 한 줄로 된다.

---

## 2. 추가하는 것

### 2-1. `Confidence` — severity와 **별개 축**

가장 중요한 규칙이다. 둘을 절대 하나로 합치지 않는다.

- **`severity`** = 진짜라면 얼마나 심각한가
- **`confidence`** = 진짜일 가능성이 얼마나 되는가

LLM 에이전트는 "심각한데 확신 없음"을 자주 뱉는다. 하나로 뭉개면 그 정보가 사라지고,
트리아지하는 사람이 뭘 먼저 볼지 정할 수 없게 된다.

```python
class Confidence(str, Enum):
    CONFIRMED = "confirmed"    # 재현 절차만으로 결정적으로 증명됨
    FIRM      = "firm"         # 증거는 강하나 판단이 개입함
    TENTATIVE = "tentative"    # 정황뿐. 사람 확인 필요
```

**왜 0.0~1.0 실수가 아닌가:** LLM이 뱉는 0.6과 0.7은 보정된 값이 아니다.
세 명이 각자 만든 에이전트의 0.6은 서로 비교조차 안 된다. 판정 기준을 글로 적은
3단계가 실제로는 더 정확하고 비교 가능하다. (Burp의 Certain/Firm/Tentative와 같은 발상)

각 단계 판정 기준:

| 단계 | 기준 | 예 |
|---|---|---|
| `CONFIRMED` | 첨부한 요청/응답만 보면 누구나 같은 결론에 도달 | alice 세션으로 bob 데이터가 200으로 반환됨 |
| `FIRM` | 증거는 명확하나 "그래서 취약하다"는 판단이 한 단계 들어감 | DB 오류 메시지는 떴지만 데이터 추출은 미시도 |
| `TENTATIVE` | 응답이 수상하지만 결정적이지 않음 | 응답 시간이 길어졌으나 재현이 불안정 |

**스캐너 findings의 기본값은 `CONFIRMED`** — 기존 동작이 안 바뀐다.

### 2-2. `HttpExchange` — 재현 절차는 문자열이 아니라 구조체

"user1으로 요청했더니 나왔다" 같은 산문이면 아무도 검증할 수 없다.
**남이 그대로 재생할 수 있는 형태**여야 한다.

```python
@dataclass(frozen=True)
class HttpExchange:
    method: str
    url: str
    status: int | None
    actor: str = ""                 # 어느 신원으로 보냈나: "alice", "bob", "anon"
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_excerpt: str = ""      # 판단 근거가 된 부분 (상한 2048자)
    note: str = ""                  # 이 요청이 왜 있는지 한 줄
```

**`actor`가 핵심이다.** IDOR은 "누구의 신원으로 보냈는가"가 취약점의 정의 자체다.
이 필드가 없으면 IDOR finding은 의미를 잃는다.

**마스킹 규칙 (필수):** `request_headers`의 `Authorization`, `Cookie`는 값을
`***`로 마스킹해서 넣는다. 세션 토큰이 리포트 파일에 그대로 남으면 안 된다.
`actor`로 어느 신원이었는지는 이미 알 수 있다.

### 2-3. `Evidence` — 교환 묶음 + 왜 취약한지

```python
@dataclass
class Evidence:
    exchanges: list[HttpExchange]
    rationale: str                  # 왜 취약하다고 판단했는지 (사람이 읽음)
    baseline_index: int | None = None   # exchanges 중 "정상 기준선"이 몇 번째인지
```

**`baseline_index`가 있는 이유:** 에이전트 취약점은 거의 다 **대조**로 증명된다.
IDOR = 자기 것 접근(정상) vs 남의 것 접근(비정상). Injection = 정상 입력 vs 주입 입력.
기준선이 뭔지 명시하지 않으면 읽는 사람이 요청 목록만 보고 추측해야 한다.

### 2-4. 최종 `Finding`

```python
@dataclass
class Finding:
    # --- 기존 (한 줄도 안 바뀜) ---
    scanner: str
    finding_id: str
    name: str
    severity: Severity
    matched_at: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    # --- v0 추가: 전부 기본값 있음 ---
    confidence: Confidence = Confidence.CONFIRMED
    category: str = ""                                  # §3 어휘 사용
    evidence: Evidence | None = None
    agent_data: dict = field(default_factory=dict)      # 에이전트 전용 이름공간
```

`agent_data`는 **자기 이름 아래에만 쓴다**: `agent_data["idor"] = {...}`.
`raw`는 스캐너 원본 전용이므로 에이전트는 건드리지 않는다. 이렇게 나눠야
셋이 같은 dict에서 충돌하지 않는다.

---

## 3. `category` 어휘 — 정답지와 같은 말을 쓴다

`ground_truth.json`이 이미 쓰고 있는 어휘를 그대로 쓰고, 두 개만 추가한다.
이래야 에이전트 findings도 `validate.py`로 채점할 수 있다.

```
exposure                  (기존)
information-disclosure    (기존)
misconfiguration          (기존)
idor                      ← 추가
injection                 ← 추가
```

---

## 4. 얼리는 규칙 5개

1. `severity`와 `confidence`를 섞지 않는다. (§2-1)
2. `confidence`가 `CONFIRMED`가 아니면 **`evidence`는 필수**다.
3. `scanner` 값에 에이전트는 `agent:` 접두사를 붙인다.
4. `agent_data`는 자기 에이전트 이름 키 아래에만 쓴다.
5. `Authorization` / `Cookie` 헤더 값은 마스킹한다. `response_excerpt`는 2048자 이내.

---

## 5. 정찰 에이전트는 결과가 두 종류다 (중요)

정찰의 주 산출물은 **취약점이 아니라 목록**이다. 엔드포인트 목록을 억지로
`Finding`에 밀어 넣으면 안 된다 — "발견한 URL 40개"가 findings 40건이 되면
리포트가 망가진다.

정찰은 **두 개**를 낸다:

- **엔드포인트 인벤토리** (아래 `Endpoint` 리스트) → injection·IDOR 에이전트의 **입력**
- 진짜 취약점만 `Finding`으로 (예: 사용자 열거 — §6 예시 3)

```python
@dataclass(frozen=True)
class Endpoint:
    method: str
    url_template: str               # "/api/orders/{id}" — 값이 아니라 모양
    params: list[str]               # ["id"]
    auth_required: bool | None      # None = 미확인
    observed_status: int | None
    content_type: str = ""
    source: str = ""                # 어떻게 찾았나: "link", "robots.txt", "guess"
```

**`url_template`이 값이 아니라 모양인 게 핵심이다.** IDOR 에이전트는
`/api/orders/1001`이 아니라 `/api/orders/{id}`를 받아야 "id를 바꿔본다"는
행동을 할 수 있다.

> **B, C에게:** 정찰이 끝날 때까지 기다리지 마. 이 모양으로 **가짜 데이터를
> 직접 만들어서** 각자 진행하고, 나중에 A의 실제 출력으로 갈아끼우면 된다.

---

## 6. 채워진 예시 3개

> 아래 경로(`/login`, `/api/orders/{id}`, `/search`)는 **아직 취약 앱에 없다.**
> 내가 오늘 안에 추가하고 정답지에도 넣는다. 예시는 그 완성 형태 기준이다.

### 예시 1 — IDOR (`agent:idor`)

```python
Finding(
    scanner="agent:idor",
    finding_id="idor-order-object-access",
    name="주문 조회 API에 객체 소유권 검사 없음",
    severity=Severity.HIGH,
    confidence=Confidence.CONFIRMED,
    category="idor",
    matched_at="http://127.0.0.1:8080/api/orders/1002",
    description="인증된 사용자가 id만 바꿔 타인의 주문을 그대로 조회할 수 있다.",
    tags=["idor", "broken-access-control", "api"],
    evidence=Evidence(
        baseline_index=0,
        rationale=(
            "alice 세션으로 bob의 주문(1002)이 200으로 반환됐고 본문에 "
            "bob@example.com이 들어 있다. 3번 요청이 401인 것으로 보아 인증 자체는 "
            "걸려 있으나 객체 소유권 검사가 없다 — 즉 '인증 누락'이 아니라 IDOR이다."
        ),
        exchanges=[
            HttpExchange(
                method="GET", url="http://127.0.0.1:8080/api/orders/1001",
                actor="alice", status=200,
                request_headers={"Cookie": "***"},
                response_excerpt='{"id":1001,"owner":"alice@example.com","total":42000}',
                note="기준선: alice가 자기 주문을 조회 (정상)",
            ),
            HttpExchange(
                method="GET", url="http://127.0.0.1:8080/api/orders/1002",
                actor="alice", status=200,
                request_headers={"Cookie": "***"},
                response_excerpt='{"id":1002,"owner":"bob@example.com","total":128000}',
                note="공격: id만 1002로 바꿈. bob의 데이터가 그대로 반환됨",
            ),
            HttpExchange(
                method="GET", url="http://127.0.0.1:8080/api/orders/1002",
                actor="anon", status=401,
                response_excerpt='{"error":"authentication required"}',
                note="대조: 비로그인은 차단됨 → 인증은 있고 인가만 없음",
            ),
        ],
    ),
    agent_data={"idor": {
        "id_strategy": "sequential-numeric",
        "probed_ids": [1000, 1001, 1002, 1003],
        "leaked_ids": [1002],
    }},
)
```

세 번째 요청이 이 예시의 핵심이다. 그게 없으면 "인증이 아예 없는 API"와
구별이 안 되고, 심각도·조치 방법이 완전히 달라진다.

### 예시 2 — Injection (`agent:injection`)

```python
Finding(
    scanner="agent:injection",
    finding_id="sqli-error-based-search-q",
    name="검색 파라미터 q에 SQL 구문 주입 가능",
    severity=Severity.CRITICAL,
    confidence=Confidence.FIRM,          # ← CONFIRMED 아님. 아래 rationale 참고
    category="injection",
    matched_at="http://127.0.0.1:8080/search?q=",
    description="q 값이 SQL 문자열에 그대로 이어붙는다. 홑따옴표로 구문이 깨지고 주석으로 복구된다.",
    tags=["sqli", "injection", "error-based"],
    evidence=Evidence(
        baseline_index=0,
        rationale=(
            "따옴표 하나로 500 + MySQL 구문 오류가 뜨고, 주석(--)을 붙이면 다시 "
            "200으로 돌아온다. 이 쌍이 '입력이 구문으로 해석된다'는 증거다. "
            "CONFIRMED가 아닌 이유: 실제 데이터 추출은 시도하지 않았다 "
            "(통제 타겟이라도 파괴적/추출 페이로드는 기본 미실행)."
        ),
        exchanges=[
            HttpExchange(
                method="GET", url="http://127.0.0.1:8080/search?q=invoice",
                actor="anon", status=200,
                response_excerpt="<h1>3 results for invoice</h1>",
                note="기준선: 정상 입력",
            ),
            HttpExchange(
                method="GET", url="http://127.0.0.1:8080/search?q=invoice%27",
                actor="anon", status=500,
                response_excerpt=(
                    "You have an error in your SQL syntax; check the manual ... "
                    "near \"'invoice''\" at line 1"
                ),
                note="따옴표 1개 → 구문 깨짐. DB 오류가 그대로 노출됨",
            ),
            HttpExchange(
                method="GET", url="http://127.0.0.1:8080/search?q=invoice%27--%20",
                actor="anon", status=200,
                response_excerpt="<h1>3 results for invoice</h1>",
                note="주석으로 복구 → 입력이 SQL 구문으로 해석된다는 확증",
            ),
        ],
    ),
    agent_data={"injection": {
        "parameter": "q",
        "location": "query",
        "technique": "error-based",
        "dbms_guess": "mysql",
        "payloads_tried": 7,
        "destructive_payloads_run": False,
    }},
)
```

`confidence=FIRM`인 이유를 rationale에 적은 게 포인트다. **왜 확신을 낮췄는지
안 적으면 다음 사람이 판단을 재현할 수 없다.**

### 예시 3 — 정찰 (`agent:recon`)

정찰이 내는 **진짜 취약점** 쪽 예시다. (엔드포인트 목록은 §5의 `Endpoint`로 따로 나감)

```python
Finding(
    scanner="agent:recon",
    finding_id="user-enumeration-login",
    name="로그인 응답으로 계정 존재 여부 구분 가능",
    severity=Severity.LOW,
    confidence=Confidence.FIRM,
    category="information-disclosure",
    matched_at="http://127.0.0.1:8080/login",
    description="존재하는 계정과 없는 계정의 실패 메시지가 달라 계정 목록을 수집할 수 있다.",
    tags=["user-enumeration", "auth", "recon"],
    evidence=Evidence(
        baseline_index=0,
        rationale=(
            "같은 '로그인 실패'인데 메시지가 다르다. 이 차이로 유효한 계정만 "
            "골라낼 수 있고, 이후 크리덴셜 스터핑의 입력이 된다. 단독으로는 "
            "심각도가 낮아 LOW."
        ),
        exchanges=[
            HttpExchange(
                method="POST", url="http://127.0.0.1:8080/login",
                actor="anon", status=401,
                request_body="username=alice&password=wrong",
                response_excerpt="비밀번호가 올바르지 않습니다",
                note="기준선: 실재하는 계정 + 틀린 비밀번호",
            ),
            HttpExchange(
                method="POST", url="http://127.0.0.1:8080/login",
                actor="anon", status=401,
                request_body="username=zzzz_nope&password=wrong",
                response_excerpt="존재하지 않는 사용자입니다",
                note="없는 계정 → 메시지가 다름",
            ),
        ],
    ),
    agent_data={"recon": {
        "confirmed_users": ["alice", "bob", "admin"],
        "discovery_source": "login-error-differential",
    }},
)
```

세 예시 모두 **"기준선 + 대조"** 라는 같은 뼈대를 쓴다. 이게 우연이 아니라,
에이전트가 찾는 취약점은 대부분 이 모양이다. `baseline_index`를 필수로 둔 이유다.

---

## 7. 지금 정하지 않는 것 (실제 finding 하나씩 나온 뒤에)

- `finding_id` 네이밍 체계 — 지금은 `<무엇>-<어디>` kebab-case 정도만 지키자
- 에이전트 findings의 `severity` 판단 기준 — 사람마다 다를 텐데, 실물 보고 맞추자
- 중복 제거 — 정찰과 injection이 같은 걸 찾았을 때 어떻게 합칠지
- `confidence`가 낮은 findings를 리포트에 넣을지 뺄지

---

## 8. 검증 결과 (초안 상태로 실제 돌려봄)

이 문서의 예시 3개를 실제 dataclass로 구성해서 확인했다.

```
[ok] 기존 필드 8개 전부 보존, 위치인자 호출 동일하게 동작
[ok] lint idor-order-object-access / sqli-error-based-search-q / user-enumeration-login
[ok] 린터가 위반 케이스를 잡음
[ok] JSON 직렬화/역직렬화 4849바이트, 라운드트립 성공
[ok] 기존 JSONReporter 통과, severity_counts 정상 집계
[ok] Endpoint 인벤토리 직렬화 정상
```

**§4의 규칙 5개는 코드로 강제할 수 있다.** 위 검증에서 쓴 `lint(finding)` 함수를
`Finding.validate()`로 넣으면, 규칙을 문서로만 두지 않고 CI에서 잡을 수 있다.
사람 약속은 주말 이틀이면 무너지지만 assert는 안 무너진다.

### 발견된 구멍 하나

기존 `JSONReporter._finding_dict()`는 필드를 **화이트리스트로 고른다.**
그래서 신규 필드가 리포트에 안 실린다. 확인된 출력 키:

```
['scanner', 'id', 'name', 'severity', 'matched_at', 'description', 'tags']
```

→ `confidence`, `category`, `evidence`가 **조용히 사라진다.** 예외도 안 난다.
계약을 합의해도 리포터를 같이 안 고치면 에이전트 findings의 핵심 정보가
리포트에서 증발한다. 리포터 수정은 내가 계약 확정과 **같이** 넣는다.

---

## 9. 리뷰 포인트 (여기만 봐줘도 됨)

1. `confidence` 3단계로 충분한가? 각자 에이전트에서 표현 못 하는 경우가 있나?
2. `HttpExchange`에 없어서 곤란한 필드가 있나? (타이밍? 리다이렉트 체인?)
3. `agent_data`에 각자 뭘 넣을 계획인지 한 줄씩 — 겹치는 게 있으면 지금 발견하자
4. §5 `Endpoint` 모양이 B/C가 쓰기에 충분한가? **이게 A→B,C 인터페이스라 제일 중요하다**
