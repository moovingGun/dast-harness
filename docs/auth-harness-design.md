# 인증 계층(auth harness) 설계

> 상태: **설계안(제안)**. 구현 전 리뷰용. Phase 1 범위만 확정 대상이고 Phase 2/3은
> 방향만 잡는다.
>
> 스캐너 동작은 **nuclei v3.11.1 / nikto 2.6.1에서 실측**했다(§7, §7.1, §8). 로컬
> throwaway 서버에 요청 헤더를 기록시켜 와이어에 실제로 나간 것을 관측한 결과이며,
> 도구 문서가 아니라 관측을 근거로 삼는다. 실측 결과가 초안의 권고 하나를 뒤집었다(§5).
> 아직 측정하지 않은 것은 §11에 남겨뒀다 — 추측으로 메우지 않았다.

## 0. 한 줄 요약

인증은 이 하네스에서 **기능이 아니라 안전장치 표면의 확장**이다. `safety.py`가
"스캐너가 **어디로** 요청을 보내는가"를 통제한다면, 인증 계층은 "**무엇을 실어**
보내는가"와 "그게 **정말 인증된 상태였는가**"를 통제한다. 세 축 모두 기존
`CompletionEvidence` 철학과 같은 방식(증거를 남긴다)으로 다룬다.

---

## 1. 왜 필요한가 / 무엇이 새로 위험해지는가

현재 하네스는 인증되지 않은 표면만 긁는다. 실제 앱 취약점의 대부분은 로그인 뒤에
있으므로 인증 주입이 필요하다. 그런데 크리덴셜이 들어오는 순간 지금 구조에 **답이
없는 실패 모드 3가지**가 생긴다. 설계는 전적으로 이 셋을 막기 위한 것이다.

### F1. 크리덴셜이 인가되지 않은 호스트로 새어나간다 (egress)

`Authorization` 헤더를 붙인 스캐너가 리다이렉트를 따라가면 토큰이 제3의 호스트로
간다. 대상 URL 인가만으로는 못 막는다.

> 이미 nuclei에 `-disable-redirects`가 **끌 수 없는 불변값**으로 걸려 있고, nikto는
> `-followredirects`가 옵트인이라 기본값이 안전하다. 지금 이 무력화의 근거는 "스캔
> 범위 이탈 방지"인데, 인증이 붙으면 **크리덴셜 유출 방지**라는 더 강한 근거가
> 추가된다. 동시에 이게 인증 스캔의 커버리지를 깎는 부작용을 낳는다 — §7.1에서 따로
> 다룬다.

### F2. 크리덴셜이 산출물에 박힌다 (artifact leak)

세 개의 자동 직렬화 경로가 이미 존재한다.

| 경로 | 위험 |
|---|---|
| `Finding.raw` | README 명시: raw는 **내부적으로 항상 보존**. `JSONReporter(include_raw=True)`면 파일로 나간다 |
| `ScanConfig.snapshot()` → `CompletionEvidence.config` → JSON 리포트 | **기본 리포트에 무조건 실린다** |
| 스캐너 stderr 캡처 → `ScanOutcome.error` → evidence | 에러 메시지에 요청 덤프가 섞일 수 있다 |

여기서 **가장 중요한 구조적 결정**이 나온다:

> **크리덴셜을 `ScanConfig`에 넣지 않는다.** `ScanConfig`는 `snapshot()`이라는 자동
> 직렬화 경로를 갖고 있고 그 결과가 기본 리포트에 실린다. 인증 정보를 여기 넣으면
> "레닥션을 잊지 않기"에 안전이 의존하게 된다. 별도 인자로 분리하면 **유출 불가능이
> 구조적 속성**이 된다.

### F3. 로그인 안 된 채로 스캔하고 "깨끗함"을 보고한다 (거짓 음성)

토큰이 만료됐거나, 스캐너가 그 인증 방식을 지원하지 않거나, 스캔 도중 로그아웃
엔드포인트를 밟으면 — 스캔은 **정상 완료**되고 findings 0개가 나온다. 사용자는
"취약점 없음"으로 읽는다. 이건 이 하네스가 만들어낼 수 있는 **가장 위험한 산출물**이다.

`ScanStatus`에 이걸 표현할 자리가 지금 없다. `completed`는 "스캐너가 잘 끝났다"는
뜻이지 "인증된 상태로 긁었다"는 뜻이 아니다.

---

## 2. 설계 원칙 (F1~F3에서 직접 유도)

1. **크리덴셜은 origin에 바인딩된다.** 타겟이 아니라 `scheme://host:port`에 묶이고,
   인가된 origin과 불일치하면 스캔이 시작조차 되지 않는다. (F1 1차 방어)
2. **리다이렉트 비활성은 인증 시 협상 불가다.** (F1 2차·런타임 방어)
3. **시크릿은 직렬화 가능한 자료구조에 절대 들어가지 않는다.** 증거에는 값 대신
   **지문(fingerprint)** 만 남긴다. (F2)
4. **조용한 다운그레이드 금지.** 스캐너가 요청된 인증 방식을 지원하지 않으면
   무인증으로 진행하지 않고 **실패**한다. (F3)
5. **인증은 주장이 아니라 증명이다.** 스캐너를 띄우기 전에 하네스가 직접 검증
   요청을 보내고, 결과를 `AuthEvidence`로 남긴다. (F3)
6. **스캐너 어댑터는 안전장치를 모른다.** 기존 철학 유지 — 레닥션·scope 검사·검증은
   전부 runner 계층에서 처리하고, 어댑터는 "이 크리덴셜을 CLI로 어떻게 넘기나"만 안다.

---

## 3. 모듈 구조

```
dast_harness/
  auth/
    __init__.py
    models.py     # Secret, AuthKind, Credential, AuthScope, AuthEvidence
    scope.py      # origin 바인딩 검사 (safety.py와 짝을 이루는 choke point)
    verify.py     # 인증 검증 프로브 (anon vs authed 이중 요청)
    redact.py     # 시크릿 스크러버 (2차 방어선)
```

`safety.py`는 건드리지 않는다. `authorize_target()`은 "어디"를 판정하고,
`auth/scope.py`는 그 결과물(`AuthorizedTarget`)을 입력으로 받아 "무엇을 실을지"를
판정한다. 책임이 겹치지 않는다.

---

## 4. 핵심 타입

### 4.1 `Secret` — 실수로 새지 않는 문자열

```python
class Secret:
    """값이 repr/로그/JSON에 노출되지 않는 문자열 래퍼."""
    __slots__ = ("_value",)
    def __init__(self, value: str) -> None: ...
    def reveal(self) -> str: ...          # 유일한 명시적 추출 경로
    def fingerprint(self) -> str: ...     # "sha256:1a2b3c4d" (앞 8자)
    def __repr__(self) -> str: return "Secret(***)"
    __str__ = __repr__
```

의도적으로 **dataclass가 아니다**. `dataclasses.asdict()`가 재귀적으로 `_value`를
꺼내는 걸 막기 위함이다. 또 `json.dumps`에 넣으면 `TypeError`가 나는데, 이건 버그가
아니라 **기능**이다 — 실수로 리포트에 넣으면 조용히 새는 대신 크래시한다.

`fingerprint()`는 증거용이다. 값은 안 새면서 "어떤 토큰으로 스캔했는지" 나중에 대조할
수 있다.

> **트레이드오프:** 짧거나 추측 가능한 시크릿(예: `admin:admin`)은 지문만으로 무차별
> 대입이 가능하다. 실행 간 대조를 포기하고 프로세스별 랜덤 salt를 쓰면 막히지만,
> "지난주와 같은 토큰인가"를 확인할 수 없게 된다. **제안: salt 없는 평문 SHA-256
> 앞 8자.** 이 하네스의 증거는 로컬 산출물이고, 대조 가능성이 더 가치 있다.
> 반대 의견이 있으면 여기서 갈라야 한다.

### 4.2 `Credential`

```python
class AuthKind(str, Enum):
    HEADER = "header"   # 임의 헤더 (Authorization: Bearer ..., X-API-Key: ...)
    BASIC  = "basic"    # HTTP Basic
    COOKIE = "cookie"   # 정적 쿠키

@dataclass(frozen=True)
class Credential:
    kind: AuthKind
    scope: AuthScope              # 이 크리덴셜을 붙여도 되는 origin
    header_name: str | None       # HEADER 전용
    value: Secret                 # 헤더 값 / "user:pass" / 쿠키 문자열

    def describe(self) -> dict:   # 증거·로그용, 시크릿 없음
        return {"kind": ..., "header_name": ..., "scope": ...,
                "fingerprint": self.value.fingerprint()}
```

> **범위 밖:** mTLS(클라이언트 인증서)는 v1에 넣지 않는다. nuclei에는 `-cc/-ck/-ca`가
> 있지만 nikto에는 대응이 없고, 파일 기반이라 위협 모델(시크릿이 argv·출력에 새는 것)이
> 헤더/쿠키와 다르다. 필요해지면 별도 `AuthKind.MTLS`로 추가한다.

### 4.3 `AuthScope` — F1의 1차 방어선

```python
@dataclass(frozen=True)
class AuthScope:
    scheme: str
    host: str
    port: int | None

    @classmethod
    def from_url(cls, url: str) -> "AuthScope": ...
    def covers(self, url: str) -> bool: ...
```

`start_scan()`에서 `authorize_target()` 직후, 스캐너가 뜨기 전에:

```python
if credential is not None and not credential.scope.covers(target.url):
    raise CredentialScopeError(...)
```

**서브도메인 와일드카드는 v1에서 지원하지 않는다.** `*.example.com`은 편하지만
크리덴셜 전송 범위를 넓히는 방향이고, 필요해지면 그때 근거를 갖고 추가한다.

### 4.4 `AuthEvidence` — F3의 산출물

```python
@dataclass
class AuthEvidence:
    kind: str                      # "header" | "basic" | "cookie"
    scope: str
    fingerprint: str
    injected_via: str              # "argv" | "file" — argv면 ps에 노출됐다는 뜻
    verified: bool | None          # None = 검증 프로브 미실행
    probe_url: str | None
    status_anon: int | None        # 크리덴셜 없이 보냈을 때
    status_authed: int | None      # 크리덴셜 붙여서 보냈을 때
    discriminating: bool | None    # 위 둘이 실제로 달랐는가
    session_alive_after: bool | None   # 스캔 종료 후 재검증
```

`CompletionEvidence`에 `auth: AuthEvidence | None` 필드를 추가한다. 시크릿은 없으므로
기본 리포트에 그대로 실어도 안전하다.

---

## 5. 인증 검증 프로브 (F3의 본체)

스캐너를 띄우기 **전에** 하네스가 직접 HTTP 요청을 보낸다.

```python
@dataclass(frozen=True)
class AuthCheck:
    url: str                          # 인증이 필요한 알려진 엔드포인트
    expect_status: int | None = 200
    expect_body_matches: str | None = None   # 예: r"logout|내 계정"
    forbid_body_matches: str | None = None   # 예: r"(?i)sign in|로그인"
```

**핵심 디테일 — 두 번 보낸다.** 크리덴셜 없이 한 번(anon), 붙여서 한 번(authed).

- authed만 확인하면 "200 나왔으니 로그인됨"이라고 착각하기 쉽다. 실제로는 그
  엔드포인트가 애초에 인증을 요구하지 않았을 뿐일 수 있다.
- anon과 authed 응답이 **구분되지 않으면**(`discriminating=False`) 그 프로브는 인증
  여부를 판정할 능력이 없다는 뜻이다. → 경고를 남기고 `verified=None`.

동작 규칙:

| 상황 | 결과 |
|---|---|
| authed가 기대 통과, anon은 실패 | `verified=True, discriminating=True` → 스캔 진행 |
| authed 기대 실패 | **스캔 시작 거부** (`AuthVerificationError`) |
| authed·anon 둘 다 통과 | `verified=None, discriminating=False` + 경고 → 진행 |
| `AuthCheck` 미지정 | `verified=None` + 경고("인증 미검증 스캔") → 진행 |

검증 실패 시 **기본값은 거부**다. 근거: 로그인 안 된 채 긁은 "findings 0"보다 시작도
안 하는 편이 훨씬 낫다.

> **실측이 이 절의 지위를 바꿨다.** 설계 초안에서는 검증 프로브를 "있으면 좋은 것"으로
> 두고 `AuthCheck` 미지정 시 경고 후 진행을 제안했다. 그런데 nuclei `-sf`의 `domains`에
> 포트를 빠뜨리면 **경고 한 줄 없이 크리덴셜이 안 붙은 채 스캔이 완주한다**는 것을
> 실측으로 확인했다(§7). 즉 F3는 가설이 아니라 **스캐너 기본 동작에 실재하는 함정**이다.
> → §10-2의 권고를 **"크리덴셜이 주어지면 `AuthCheck`도 필수"** 로 뒤집는다.

프로브는 `urllib.request`(표준 라이브러리)로 충분하다. 새 의존성을 만들지 않는다.
리다이렉트는 따라가지 않는다(F1 동일 원칙 + 302 to /login이 곧 판정 신호다).

**스캔 후 재검증.** 인증된 스캔은 진짜 사용자로서 상태 변경 엔드포인트를 때리고, 로그아웃
경로를 밟으면 세션이 죽어 나머지 스캔이 조용히 무인증이 된다(F3 재발). 스캔 종료 후 같은
프로브를 한 번 더 돌려 `session_alive_after`를 기록한다. 죽었으면
`completed_with_warnings` + 명시적 경고. 저비용 고효용이라 Phase 1에 포함한다.

---

## 6. 스캐너 계약 변경

```python
class Scanner(ABC):
    auth_support: frozenset[AuthKind] = frozenset()   # 기본 = 미지원

    def run(self, target, config, on_finding, stop_event=None,
            on_warning=None, credential: Credential | None = None) -> ScanOutcome: ...
```

- 기본값이 `frozenset()`이라 **기존·서드파티 어댑터는 자동으로 "인증 미지원"** 이 된다.
  안전한 기본값이고, 어댑터를 안 고쳐도 깨지지 않는다.
- `credential`이 주어졌는데 `kind not in scanner.auth_support`면 runner가 **스캐너를
  띄우기 전에** `AuthUnsupportedError`. (원칙 4)

### 다중 스캐너에서의 규칙

`MultiScanRunner.start_scan()`은 이미 "한 번만 인가하고, 실패하면 이미 뜬 자식을
롤백"하는 구조다. 인증 사전검사(scope + capability + 검증 프로브)를 **같은 자리**에
놓는다. 하나라도 인증을 지원하지 않으면 **그룹 전체를 거부**한다.

> "nuclei는 인증되고 nikto는 무인증"인 부분 진행을 기본값으로 두지 않는 이유: 병합된
> 리포트가 인증/무인증 결과를 섞어 보여주면 커버리지를 오독하게 된다. 사용자가
> `--scanner nuclei`로 **명시적으로** 고르게 강제한다.
>
> 완화 옵션으로 `--auth-unsupported=skip`을 둘 수는 있으나 **기본은 `fail`**.

---

## 7. 시크릿 전달 경로 (argv 회피)

CLI는 **리터럴 시크릿 인자를 받지 않는다.**

```bash
# 제공하지 않음 — 셸 히스토리와 ps aux에 남는다
--auth-header "Authorization: Bearer eyJ..."

# 제공
--auth-env AUTH_TOKEN          # 환경변수 이름만 받는다
--auth-file ./creds.json       # 파일 권한 0600 강제, 아니면 거부
```

기존 README의 "임의 CLI 인자 passthrough 미제공" 원칙과 같은 결이다.

하네스 → 스캐너 구간에서도 argv를 피할 수 있으면 피한다. 피할 수 없는 스캐너는 그
사실을 숨기지 않고 `AuthEvidence.injected_via="argv"`로 **증거에 남긴다**.

### 스캐너별 주입 수단

**실측 완료.** nuclei v3.11.1 / nikto 2.6.1, macOS. 로컬 throwaway HTTP 서버
(`127.0.0.1:18899`, `:18900`)가 인바운드 요청 헤더를 기록하게 해두고 **실제 와이어에
무엇이 나갔는지**를 관측했다. 아래는 전부 관측 결과다.

| | nuclei | nikto |
|---|---|---|
| 임의 헤더 (argv) | `-H, -header` | `-Add-header` (반복 가능) |
| 임의 헤더 (**파일**) | `-H <path>` · `-config <yaml>`의 `header:` 리스트 · `-sf` | **없음** |
| HTTP Basic | 헤더로 구성 / `-sf`의 `basicauth` | `-id user:pass[:realm]` (argv only) |
| 정적 쿠키 | `-H "Cookie: ..."` / `-sf`의 `cookie` | `-Option 'STATIC-COOKIE="..."'` 또는 `-config` |
| 출력 레닥션 | `-rd, -redact` (§8) | 불필요 — 출력에 안 실린다 (§8) |
| mTLS | `-cc/-ck/-ca` | — |

**nuclei는 argv를 완전히 피할 수 있다.** 세 경로 모두 와이어에서 확인했다:

1. `-H <path>` — `(cli, file)` 주석은 사실이다. 한 줄에 `Name: value` 하나.
2. `-config <yaml>` — `header:` YAML 리스트.
3. `-sf, -secret-file` — 아래.

#### `-sf` 시크릿 파일 포맷 (타입 열거 실측)

허용 타입은 **정확히 5개**다. 나머지는 `invalid type: <X>` fatal로 거부된다
(`headersauth`/`bearer`/`basic-auth` 등은 전부 거부됨).

| `type:` | 필수 하위 필드 |
|---|---|
| `basicauth` | `username` / `password` |
| `bearertoken` | `token` |
| `header` | `headers` (`key`/`value` 리스트) |
| `cookie` | `cookies` |
| `query` | `query` |

```yaml
static:
  - type: header
    domains: ["127.0.0.1:18899"]     # ← 포트 필수
    headers:
      - {key: X-Auth-Token, value: ...}
```

> **⚠ 조용한 무력화 — F3가 스캐너 자체에 실재한다.** `domains` 매칭 실측:
>
> | `domains` 값 | 헤더가 실제로 나갔나 |
> |---|---|
> | `127.0.0.1` (포트 누락) | **아니오 (경고 없음)** |
> | `127.0.0.1` + `-ps` | **아니오** |
> | `http://127.0.0.1:18899` (스킴 포함) | **아니오** |
> | `127.0.0.1:18899` | 예 |
> | `domains-regex: [".*"]` | 예 |
>
> 오타 하나로 스캔이 **무인증으로 조용히 진행되고 findings 0개를 보고한다.**
> 이것이 §5 검증 프로브를 선택 사항이 아니라 **필수**로 만드는 결정적 근거다.

**nikto는 argv를 피할 수 없다.** `-Add-header`에 파일 대응이 없다. 쿠키는
`STATIC-COOKIE`로 파일화 가능하지만 임의 헤더와 basic auth(`-id`)는 argv 전용이다.
→ `injected_via="argv"`로 증거에 남기고 경고한다.

시크릿 파일은 하네스가 `0600`으로 생성하고 종료 시 `finally`로 반드시 삭제한다.

#### nikto `-id`의 두 가지 함정

1. **반응형이다.** 200 응답에는 `Authorization`을 아예 보내지 않는다. 서버가
   `401 WWW-Authenticate`로 챌린지할 때만 붙는다. 반면 `-Add-header`는 모든 요청에
   선제적으로 붙고, **둘을 같이 주면 `-Add-header`가 `-id`를 덮어쓴다**(와이어에서
   `Bearer`만 관측, `Basic`은 안 나감).
2. **401을 만나면 기본 크리덴셜 ~150쌍을 난사한다.** nikto의 default-credential
   플러그인이 `admin:admin`, `root:root`, `tomcat:tomcat` … 을 같은 런에서 쏟아붓는다.
   **인증이 걸린 대상에 nikto를 붙이면 사실상 브루트포스 버스트가 발생한다.**
   계정 잠금·알람을 유발할 수 있으므로 반드시 경고하고, 전용 테스트 계정을 쓴다.

#### `ps` 노출 범위

argv는 `ps aux`에 그대로 보인다(따옴표는 벗겨진 맨 토큰). nikto는 Perl 스크립트라
인터프리터 라인에도 노출된다. **동일 사용자 기준으로 직접 확인했다.**

> 타 사용자 노출은 플랫폼마다 다르다. macOS는 다른 사용자 프로세스의 argv를 root로
> 제한하고, Linux는 `/proc/<pid>/cmdline`이 기본 world-readable이라 아무 로컬
> 사용자나 읽는다(`hidepid` 설정 시 예외). **타 사용자 케이스는 이번에 미측정이다.**
> 어느 쪽이든 argv는 셸 히스토리·프로세스 어카운팅·모니터링 에이전트에도 잡히므로
> 잘못된 채널이라는 결론은 같다.

---

## 7.1 리다이렉트: 안전과 커버리지가 충돌하는 지점

**이 설계에서 유일하게 진짜 트레이드오프가 있는 곳이다.**

`-disable-redirects`는 크리덴셜 유출을 막지만(F1), 동시에 **인증 스캔의 커버리지를
깎는다.** 로그인한 앱은 `/` → `/dashboard`처럼 리다이렉트로 동작하는 경우가 많은데,
리다이렉트를 끄면 스캐너는 302만 보고 멈춘다. 즉 **인증을 붙인 목적(로그인 뒤 표면
스캔) 자체가 반쯤 무력화된다.**

**실측 결과, nuclei의 문서화된 기본값은 실제 동작과 다르다.** 설정 파일에는
`#follow-redirects: false`라고 적혀 있지만 관측된 동작은:

| 시나리오 | 플래그 없음 | `-fr` | `-fhr` | `-dr` |
|---|---|---|---|---|
| 동일 host:port 리다이렉트 | **따라감** | 따라감 | 따라감 | 안 따라감 |
| **크로스 포트** (`:18899`→`:18900`) | 안 따라감 | **따라감** | 안 따라감 | 안 따라감 |

증거: 플래그 없이 `:18899/redir`을 스캔했더니 서버 로그에 `GET /redir` 다음
`GET /landed`가 찍혔고, JSONL 10건 전부 `"matched-at": ".../landed"`였다.

**즉 nuclei의 실질 기본값은 `-fhr`이고, 이를 끄는 건 `-dr`뿐이다.** 현재 하네스가
`-dr`을 불변값으로 박아둔 것은 nuclei 기본 동작을 **적극적으로 제거**하고 있는
것이며, 그만큼 인증 스캔에서 잃는 커버리지가 크다.

**크리덴셜 유출도 실측했다.** `-fr`로 크로스 오리진 리다이렉트를 태우면 `-H`로 넣은
시크릿이 **다른 오리진에 그대로 전달된다**(`secret-forwarded=YES`). 기본값과 `-fhr`은
다른 오리진에 도달조차 하지 않았다. → **`-fr`은 크리덴셜이 붙은 순간 exfiltration
primitive다.** 302로 공격자 호스트를 가리키는 대상이 Authorization 헤더를 받아간다.

**결정 (실측으로 확정):**

- **`-fr, -follow-redirects`는 절대 노출하지 않는다.** `ScanConfig`에 넣지 않는다.
- **`-fhr`을 인증 스캔에서 옵트인으로 허용한다** (`ScanConfig(follow_host_redirects=True)`,
  기본 `False`). 열려던 근거가 실측으로 확인됐다: `-fhr`은 **포트가 다르면 따라가지
  않는다.** 즉 `AuthScope`(scheme+host+port)보다 느슨하지 않다 — 이게 §10의 미해결
  질문이었고, 이제 해소됐다.
  - 남은 미측정: `http`→`https` 스킴 전환도 막는지는 확인하지 않았다. 보수적으로
    하네스가 `AuthScope` 일치를 별도로 강제한다.

nikto는 `-followredirects`가 옵트인이라 기본값이 이미 안전하다(실측: 기본 실행에서
`/landed` 히트 1회 vs `-followredirects` 시 1596회). 크로스 포트는 `-followredirects`를
켜도 따라가지 않았고 시크릿도 전달되지 않았다. 그냥 넘기지 않으면 되므로 README의
nikto 하드닝 목록에 추가할 항목은 아니다.

---

## 8. 레닥션 (F2의 2차 방어선)

원칙 3(시크릿을 직렬화 가능한 곳에 안 넣는다)이 1차 방어선이다. 레닥션은 **스캐너가
시크릿을 자기 출력에 되뱉는 경우**를 위한 2차 방어선이다.

### 8.1 nuclei: 자동 레닥션이 있지만 **믿으면 안 된다** (실측)

nuclei는 문서화되지 않은 자동 레닥션을 갖고 있다. `-H "Authorization: Bearer X"`를
넣고 그냥 `-jsonl`을 뽑으면 시크릿이 **0회** 등장한다 — 와이어에는 진짜 값이 나갔는데
출력에는 `Authorization: ***`로 찍힌다.

**여기서 방심하면 안 된다. 이건 하드코딩된 헤더명 allowlist이고, 매우 좁다.**

| 헤더명 | `***`로 가려지나 |
|---|---|
| `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key` | **예 (이 5개뿐)** |
| `X-Auth-Token`, `X-Api-Token`, `Api-Key`, `X-Access-Token`, `X-Amz-Security-Token` | **아니오** |
| `Token`, `Secret`, `Password`, `Authentication`, `X-Csrf-Token`, `X-Session-Id` | **아니오** |

`X-Auth-Token: TOKENSECRET999`로 실행했더니 JSONL에 시크릿이 **20회**(finding 10건 ×
필드 2개) 평문으로 박혔다. 새는 필드는 정확히 **`request`** 와 **`curl-command`** 다.

세 가지 함정이 더 있다:

1. **`-sf`를 써도 출력 유출은 동일하다.** 시크릿 파일 경유든 `-H`든 같은 출력 경로를
   탄다. `bearertoken`은 `Authorization`이 되니 가려지지만, `type: header`의
   `X-Auth-Token`은 `-H`와 똑같이 20회 샜다. **`-sf`가 사주는 건 argv 위생뿐이다.**
2. **`-irr`(request/response 캡처)는 기본이 `true`다.** deprecated이고 후속은 `-or`.
   즉 원본 요청 캡처는 끄지 않는 한 항상 켜져 있다.
3. **`-or, -omit-raw`는 함정이다.** `request`/`response`는 지워지지만
   **`curl-command`는 남고 거기에 시크릿이 그대로 있다**(finding당 1회, 10회 유출 확인).

**따라서 규칙은 하나다 — 주입하는 모든 크리덴셜 헤더명을 `-rd`에 등록한다.**
`-rd "x-auth-token"`으로 유출 **0회**를 확인했고, 매칭은 대소문자 무시다.
`-or`는 완화책이 아니다. 이건 옵션이 아니라 **불변값**으로 박는다.

### 8.2 nikto: 출력이 구조적으로 깨끗하다 (실측)

`-Format json`으로 뽑은 결과 파일에 `-Add-header` 시크릿과 `-id` 비밀번호를 grep했더니
**하나도 안 나왔다.** JSON 스키마 자체가 요청 헤더를 담지 않는다:

```
end_time, host, ip, port, server_banner, start_time,
vulnerabilities: [ {id, method, msg, references, url}, ... ]
```

nikto는 **출력 유출이 구조적으로 불가능하다** — nuclei와 정반대다. nikto의 위험은
전적으로 argv 노출과 §7의 기본 크리덴셜 난사 쪽에 있다.

### 8.3 하네스 레벨 스크러버 (최후 방어선)

위 두 절은 스캐너별 대책이고, 아래는 스캐너 무관 안전망이다.

runner 계층에서 콜백을 감싼다:

```python
scanner.run(target, config,
            redactor.wrap_finding(state.add_finding),
            stop_event,
            redactor.wrap_warning(state.add_warning),
            credential)
```

스캐너 어댑터는 레닥션을 모른다(원칙 6). `Redactor`는 스캔 시작 시 등록된 시크릿
리터럴을 `***REDACTED***`로 치환하며, 대상은 `Finding.raw` 삽입 전 · 경고 메시지 ·
`ScanOutcome.error`다.

**등록해야 하는 변형들**(이걸 놓치면 레닥션이 무용지물):

- 원본 값
- Basic auth의 base64 인코딩 값 (`base64(user:pass)`)
- URL 인코딩된 값

**한계를 명시한다.** 스캐너가 시크릿을 위 목록에 없는 방식으로 변형하면 못 잡는다.
레닥션은 안전망이지 보증이 아니다.

---

## 9. 단계 구분

### Phase 1 (구현 대상)

정적 크리덴셜만. `Credential`(header/basic/cookie) + scope 바인딩 + capability 검사 +
검증 프로브(전·후) + 레닥션 + `AuthEvidence`.

> **`AuthProvider` ABC는 Phase 1에 넣지 않는다.** 구현체가 하나뿐인데 추상 기반
> 클래스를 미리 파는 건 이 레포의 가이드라인("단일 사용 코드에 추상화 금지") 위반이다.
> `start_scan(target, config, credential=None)` 시그니처는 나중에 provider를 받도록
> 확장 가능하므로, 지금 미리 만들 이유가 없다.

### Phase 2

`FormLoginProvider` — 로그인 폼에 POST해서 쿠키/토큰을 얻어 `Credential`을 만든다.
이때 비로소 구현체가 둘이 되므로 `AuthProvider` ABC를 도입한다.

> **여기서 새로 생기는 안전 문제:** 로그인 엔드포인트가 스캔 대상과 다른 호스트일 수
> 있다(SSO/IdP). 그러면 "인가된 스캔 대상"과 "크리덴셜을 보내도 되는 로그인 호스트"가
> 갈라진다. 설정으로 임의 로그인 URL을 받으면 **공격자가 조작한 설정으로 크리덴셜을
> 유출**할 수 있다. Phase 2 착수 시 이 부분을 별도로 설계해야 한다.

### Phase 3

스캔 도중 세션 갱신. 서브프로세스 스캐너 구조상 근본적으로 어렵다 — nuclei는 실행
중에 헤더를 못 바꾼다. 현실적 방안은 스캔을 짧은 청크로 쪼개 재실행하며 갱신된
크리덴셜을 다시 주입하는 것인데, 여기서 처음으로 실질적 복잡도가 생긴다. **명확히
나중으로 미룬다.** Phase 1의 `session_alive_after` 증거가 "갱신이 필요한 상황"을
관측하게 해주므로, 실제로 필요한지 데이터를 보고 결정한다.

---

## 10. 결정이 필요한 지점

1. **지문 salt** (§4.1) — 평문 SHA-256 앞 8자(실행 간 대조 가능) vs 프로세스별 salt
   (약한 시크릿 보호). 제안: 전자.
2. **`AuthCheck` 미지정 시** (§5) — ~~경고 후 진행~~ → **실측 후 권고 변경: 크리덴셜을
   주면 `AuthCheck`도 필수**로 하고, 없으면 거부. 근거는 §5 인용 박스(`-sf` 포트 누락 시
   조용한 무인증 완주). 도입 마찰보다 거짓 음성 비용이 크다.
3. **`--auth-unsupported`** (§6) — 기본 `fail` vs `skip`. 제안: `fail`.
4. ~~**`-follow-host-redirects` 판정 범위**~~ — **실측으로 해소됨**(§7.1). `-fhr`은
   포트가 다르면 따라가지 않으므로 `AuthScope`보다 느슨하지 않다. 옵트인 허용,
   기본 `False`로 확정. (스킴 전환만 미측정 → 하네스가 `AuthScope`로 별도 강제)
5. **nikto에 크리덴셜 허용 여부** (§7) — argv 노출은 회피 불가이고, 여기에 더해
   **401 시 기본 크리덴셜 ~150쌍 난사**가 실측으로 확인됐다. 경고 후 허용 vs 금지.
   제안: 경고 후 허용하되 경고 문구에 브루트포스 버스트를 명시.

## 11. 실측 현황

초안에서 미측정으로 남겼던 항목은 **전부 해소됐다.** 결과는 각 절에 반영돼 있다.

- [x] nuclei JSONL이 `-H` 값을 출력에 싣는가 → **헤더명 allowlist 5개만 가려지고
      나머지는 `request`·`curl-command`에 평문. `-rd`가 유일한 확실한 통제** (§8.1)
- [x] `-secret-file` 포맷과 지원 타입 → **5개 타입 확정, `domains`에 포트 필수이며
      누락 시 조용한 무인증** (§7)
- [x] `-follow-host-redirects` 판정 범위 → **포트까지 구분함** (§7.1)
- [x] nikto JSON이 크리덴셜을 되뱉는가 → **아니오, 스키마상 불가능** (§8.2)

남은 미측정 (설계 결론을 바꾸지 않는 것들):

- [ ] `-fhr`이 `http`→`https` 스킴 전환을 막는지 (보수적으로 `AuthScope`로 강제 중)
- [ ] macOS에서 **타 사용자**가 `ps`로 argv를 보는지 (동일 사용자 노출은 확인함;
      Linux `/proc`는 기본 공개라 어느 쪽이든 결론 동일)
