# dast-harness

[![CI](https://github.com/moovingGun/dast-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/moovingGun/dast-harness/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

여러 스캐너와 에이전트를 **같은 인터페이스 뒤에 꽂는** 최소 DAST 하네스.
스캔을 실행하고 상태·결과를 조회하며, **loopback 또는 명시적으로 허가된 대상만**
스캔하도록 안전장치를 강제한다. 런타임 의존성 없음 (stdlib only).

두 부분으로 되어 있다.

| | 무엇 | 어디 |
|---|---|---|
| **스캐너 하네스** | nuclei·nikto 같은 기성 도구를 실행하고 결과를 `Finding`으로 정규화 | `dast_harness/scanners/`, `runner.py`, `orchestrator.py` |
| **에이전트 키트** | 직접 만드는 정찰·injection·IDOR 에이전트가 **같은 모양의 결과**를 내게 하는 계약과 도구 | `dast_harness/agent_kit/` |

둘 다 같은 `Finding`을 내고 같은 리포터를 통과한다. 그래서 스캐너 결과와 에이전트
결과를 한 리포트에서 볼 수 있다.

## 처음 보는 사람은 여기서부터

```bash
python3 -m unittest discover -s tests            # 1) 도커·스캐너 없이 전부 통과하는지
python3 targets/vulnerable_app/app.py &          # 2) 통제 취약 타겟 (127.0.0.1:8080)
python3 -m dast_harness.agent_kit.recon http://127.0.0.1:8080   # 3) 동작하는 에이전트
```

3번 출력이 이 프로젝트가 무엇을 주고받는지 가장 빠르게 보여준다.

**에이전트를 만들러 왔다면 → [AGENT_GUIDE.md](AGENT_GUIDE.md)** 하나만 읽으면 된다.
아래 "팀원이 봐야 할 것"에 순서가 있다.

## 구현 상태

| | 기능 |
|---|---|
| ✅ | nuclei / nikto 어댑터 (실행·파싱·`Finding` 정규화) |
| ✅ | 다중 스캐너 병렬 실행, 상태 롤업, 중단·타임아웃, 완료 증거 |
| ✅ | 안전장치 — loopback/allowlist 강제, 리다이렉트 차단 |
| ✅ | console / json 리포터 |
| ✅ | 통제 취약 타겟 + 정답지, 스캐너 탐지 정확도 채점 |
| ✅ | **에이전트 결과 계약** — `AgentFinding`/`AgentResult`/`RequestSeed` + 검증기 |
| ✅ | **정찰 에이전트** — 크롤 + 폼 파싱 → 요청 씨앗 인벤토리 |
| ⬜ | injection 에이전트 ← 팀원 작업 |
| ⬜ | IDOR 에이전트 ← 팀원 작업 |
| ✅ | 리포터에 에이전트 필드(`confidence`/`evidence`/`agent_data`) 반영 |
| ⬜ | 에이전트를 CLI·오케스트레이터에 꽂는 배관 |
| ⬜ | 에이전트 findings 정확도 채점, 오탐(`must_not_detect`) 채점 |

테스트 254개가 위 ✅ 항목을 고정한다 (도커·스캐너 설치 불필요).

## 설치

```bash
pip install .            # 런타임 의존성 없음 (stdlib only), Python 3.11+
dast-harness --help      # 콘솔 스크립트
```

설치 없이 저장소에서 바로 쓰려면 `python -m dast_harness ...` 로 동일하게 동작한다.

## CLI

```bash
dast-harness scan http://127.0.0.1:8080 \
    --scanner nuclei,nikto \      # 기본: 설치된 것 전부
    --allow staging.internal \    # allowlist 추가 (반복 가능)
    --severity high,critical \    # nuclei passthrough
    --timeout 120 \               # 그룹 전체 deadline
    --format json -o results.json # console(기본) | json
```

종료 코드(스크립팅/CI 연동용):

| 코드 | 의미 |
|---|---|
| `0` | `completed` / `completed_with_warnings` |
| `1` | `partial` / `failed` |
| `2` | 잘못된 인자·설정, 대상 거부, 스캐너 미설치 |
| `124` | 그룹 timeout |
| `130` | 사용자 중단(Ctrl-C) |

## 폴더 구조

`📖` = 에이전트 만들 때 읽을 것 · `✍️` = 새 에이전트가 추가되는 곳 · `🔒` = 수정 금지

```
dast_harness/
├── models.py            공통 자료형: Target, ScanConfig, Finding, Severity,
│                        ScanStatus, ScanState, CompletionEvidence
├── safety.py         🔒 이 프로젝트의 유일한 안전 경계. loopback/allowlist 외 거부
│
├── scanners/            ── 기성 도구 어댑터 ──
│   ├── base.py          Scanner 추상 인터페이스 (is_available / run)
│   ├── nuclei.py        nuclei 실행 + JSONL 스트리밍 파싱 → Finding
│   └── nikto.py         nikto 실행 + 종료 후 JSON 파싱 → Finding
│
├── agent_kit/           ── 직접 만드는 에이전트용 ──
│   ├── contract.py   📖 결과 형식 계약. AgentFinding / Evidence / HttpExchange /
│   │                    Probe / Coverage / RequestSeed / AgentResult +
│   │                    validate_finding() / validate_result()
│   ├── base.py       📖 Agent 추상 클래스. 상속해서 run() 하나만 구현한다
│   ├── http.py       📖 AgentHttpClient — 에이전트가 쓸 수 있는 유일한 HTTP 통로
│   └── recon.py      📖 동작하는 정찰 에이전트. **이걸 복사해서 시작한다**
│      ✍️ idor.py         ← IDOR 담당자가 여기에 추가
│      ✍️ injection.py    ← injection 담당자가 여기에 추가
│
├── runner.py            단일 스캐너 생명주기: start_scan/get_status/get_results/
│                        stop_scan/wait
├── orchestrator.py      MultiScanRunner: 여러 스캐너 병렬 실행 + 상태 롤업/결과 병합
├── cli.py               one-shot CLI (python -m dast_harness scan)
├── validate.py          정답지 대비 탐지 정확도 채점
└── reporters/           출력 전용 계층 (console, json)

targets/
├── compose.yml                   통제 취약 타겟 컨테이너 (127.0.0.1 전용 게시)
└── vulnerable_app/
    ├── app.py                 📖 의도적으로 취약한 stdlib 앱 — 연습 대상
    └── ground_truth.json      ✍️ 이 앱의 취약점 정답지. 새 취약점을 찾게 만들면
                                  여기에도 항목을 추가한다

tests/                           도커·스캐너 설치 없이 전부 돈다
├── test_agent_contract.py   📖 에이전트 계약 테스트 (규칙을 실제로 강제하는 곳)
├── test_target_app.py           취약 타겟이 문서대로 취약한지
└── test_safety.py ...           안전장치·러너·리포터 등

AGENT_GUIDE.md            📖 **에이전트 작성 가이드. 여기서 시작.**
CLAUDE.md                 📖 저장소 작업 규칙 (사람·AI 공통)
finding-v0-proposal.md       계약을 정할 때의 설계 논의 기록 (읽지 않아도 된다)
example.py / example_multi.py   스캐너 사용 예시
```

각 스캔은 완료 증거(`CompletionEvidence`: 종료코드·파싱 계정·버전·중단 여부 등)를
스캐너별로 기록하며, `get_status`의 `evidence` 필드로 조회된다.

## 팀원이 봐야 할 것

정찰 / injection / IDOR 에이전트를 만든다면 이 순서로 보면 된다.

1. **[AGENT_GUIDE.md](AGENT_GUIDE.md)** — 이것만 읽어도 시작할 수 있다.
   5분 첫 실행, 뼈대, 증거 만드는 법, 동작하는 전체 예시, 커밋 전 체크리스트
2. **`dast_harness/agent_kit/recon.py`** — 명세를 처음부터 구현하지 말고
   **이 파일을 복사해서** 고친다. 세 에이전트의 구조가 같아야 마지막에 합쳐진다
3. **`targets/vulnerable_app/app.py`** — 연습 대상. 계정과 취약점 목록은 가이드 8장
4. **`dast_harness/agent_kit/contract.py`** — 필드 의미가 궁금할 때 찾아보는 곳.
   외울 필요는 없다. 어기면 `AssertionError`가 난다

작업 중 지켜야 할 것 두 개만 미리 알아두면 된다.

- **HTTP는 `AgentHttpClient`로만 보낸다.** `requests`/`httpx`/`urllib`를 직접 쓰면
  안전 경계를 우회한다 (타겟 응답을 읽고 다음 URL을 정하는 구조라서 위험하다)
- **`safety.py`는 수정하지 않는다.** 새 도구는 우회하지 말고 통과시킨다

자세한 규칙은 [CLAUDE.md](CLAUDE.md)에 있다.

> **아직 안 된 것:** 에이전트를 CLI에 자동으로 꽂는 배관이 없다. `cli.py` /
> `orchestrator.py` / `validate.py`는 아직 에이전트를 모르므로, 지금은 직접
> import해서 실행한다. 배관이 붙는 지점은 `AgentResult`이고 그 모양은 확정됐으니
> **에이전트 코드는 나중에 고치지 않아도 된다.**

## 스캐너 (scanners/)

같은 `Scanner` 인터페이스 뒤에 여러 도구를 꽂는다. `ScanRunner`와 안전장치·리포팅은
스캐너를 몰라도 된다.

- **nuclei**: 실행 중 stdout으로 JSONL을 **스트리밍** → 결과를 실시간 관측.
- **nikto**: 종료 시 JSON **파일 하나**를 씀 → 완료 후 파싱해 일괄 전달. Nikto는
  severity 개념이 없어 모든 finding이 `Severity.UNKNOWN`이다. nuclei 전용
  `ScanConfig` 필드(severities/tags/template_ids)는 무시하고 맞는 것만 사용한다.

여러 스캐너 결과는 각 `Finding`의 `scanner` 필드로 출처가 구분된다.

### 다중 스캐너 (MultiScanRunner)

한 타겟에 여러 스캐너를 병렬 실행하고 하나의 병합 뷰로 조회한다. `ScanRunner` 위에
얹은 얇은 오케스트레이터로, 안전장치·리포팅을 그대로 재사용한다.

```python
from dast_harness import (MultiScanRunner, NucleiScanner, NiktoScanner,
                          Target, build_report, ConsoleReporter)

runner = MultiScanRunner([NucleiScanner(), NiktoScanner()])
scan_id = runner.start_scan(Target("http://127.0.0.1:8080"))
runner.wait(scan_id)
print(ConsoleReporter().render(build_report(runner, scan_id)))
```

- `get_status`는 롤업 상태와 스캐너별 breakdown, `results_partial`을 함께 준다.
- `get_results`/`get_warnings`는 전 스캐너 결과를 병합한다(경고는 `[scanner]` 접두).
- `example_multi.py` 참고.

#### 상태 규칙

**스캐너별 상태** (`ScanRunner`, 위→아래 우선):

| 조건 | 상태 |
|---|---|
| 사용자 중단이 실제 적용됨 (stop_effective) | `stopped` |
| fatal 파싱오류 또는 종료코드 ∉ {0, None} | `failed` |
| 비치명적 파싱 경고 존재(invalid_records > 0), 결과 사용 가능 | `completed_with_warnings` |
| 종료코드 0 · 출력/파일 정상 파싱 · 경고 없음 | `completed` |

**다중 롤업** (`MultiScanRunner`, 위→아래 우선):

| 조건 | 상태 |
|---|---|
| 하나라도 진행 중 | `running` |
| 하나라도 실제 중단됨 (중단 우선) | `stopped` |
| 전부 성공, 하나라도 경고 | `completed_with_warnings` |
| 전부 성공(완료) | `completed` |
| 일부 성공 · 일부 실패 | `partial` |
| 전부 실패 | `failed` |

성공 = {`completed`, `completed_with_warnings`}. 이미 완료된 스캐너는 그룹 중단 후에도
`completed`와 결과를 유지하며, 실행 중 스캐너에만 중단 신호가 전달된다. **모두 완료된
뒤의 `stop_scan()`은 no-op**으로, 기존 완료 상태를 그대로 둔다.
`results_partial` = 전체 상태가 성공(위 두 상태) 이외일 때 `True`.

## 리포팅 (reporters/)

스캔 결과(`Finding` 리스트)를 출력 포맷으로 내보내는 얇은 계층. 스캔 로직과 분리돼
있고, `Finding`이 스캐너 무관이라 스캐너를 추가해도 그대로 재사용된다.

```python
from dast_harness import build_report, ConsoleReporter, JSONReporter

report = build_report(runner, scan_id)
print(ConsoleReporter().render(report))          # 콘솔 요약
open("results.json", "w").write(JSONReporter().render(report))  # JSON 저장
```

JSON 리포트에는 전체 상태·`results_partial`·스캐너별 상태/오류/완료 증거·findings·
warnings가 포함된다. `raw`(스캐너 원본)는 각 `Finding`에 **내부적으로 항상 보존**되며,
출력에는 `JSONReporter(include_raw=True)`일 때만 실린다(기본 `False`, 안전).

## 안전장치 (safety.py)

`ScanRunner.start_scan()`은 스캐너 프로세스가 뜨기 전에 `authorize_target()`을
반드시 통과시킨다. 대상은 다음 중 하나일 때만 허용된다.

1. 대상이 loopback IP 또는 `localhost`
2. 호스트가 명시적 `allowlist`에 포함 (허가된 대상 예외)

사설망과 link-local 주소도 기본적으로 거부한다. 임의의 DNS 이름은 Nuclei 실행 시
다시 해석될 수 있으므로 `localhost` 이외에는 명시적 allowlist가 필요하다.

### 런타임 하드닝 (스캐너 실행 옵션)

URL 인증만으로는 못 막는 스캐너 런타임 동작을 기본값으로 차단한다.

nuclei:
- **`-disable-redirects` (항상)**: 로컬 대상이 공인 URL로 리다이렉트해 스캔을
  비인가 호스트로 유도하는 것을 결정적으로 차단한다. 끌 수 없는 안전 불변값.
- **`-no-interactsh` (기본)**: OAST 콜백을 위해 외부 interactsh 서버와 통신하는
  것을 막아 스캔을 로컬로 격리한다. blind/OOB 탐지가 필요하면
  `ScanConfig(enable_interactsh=True)`로 켤 수 있다(외부 통신 발생).
- **`-disable-update-check` (항상)**: 시작 시 nuclei/템플릿 업데이트 확인용 외부
  통신을 차단한다.

nikto:
- **`-nocheck` (항상)**: 시작 시 외부 업데이트 확인을 차단한다.
- **`-ask no` (항상)**: 업데이트 제출 프롬프트를 띄우지 않는다.

## 통제 취약 타겟 (targets/)

정확도를 재려면 "무엇이 있는지 아는" 타겟이 필요하다. `targets/vulnerable_app`은
그 목적으로 직접 만든 stdlib 전용 앱이고, 앱이 노출하는 모든 약점은
`ground_truth.json`에 정답지로 적혀 있다. 테스트(`tests/test_target_app.py`)가
정답지의 각 항목을 실제로 서빙하는지 확인하므로 앱과 정답지는 어긋날 수 없다.

```bash
docker compose -f targets/compose.yml up -d --build   # http://127.0.0.1:8080
docker compose -f targets/compose.yml down
```

컨테이너는 **`127.0.0.1:8080`에만 게시**된다(LAN 노출 금지). 의도적으로 취약한
앱이므로 포트 매핑을 `0.0.0.0`으로 바꾸지 말 것 — 이 불변식도 테스트로 고정돼 있다.
`read_only`, `cap_drop: ALL`, `no-new-privileges`로 컨테이너 자체는 굳혀 둔다.

Docker 없이 쓰려면 `python3 targets/vulnerable_app/app.py` (기본 바인드 `127.0.0.1`).

정답지 항목: `/.env` 노출, `/.git/config` 노출, `/backup.sql` 노출, `/phpinfo.php`
정보 누출, `/uploads/` 디렉터리 리스팅, `/admin/` 무인증 관리 페이지, 보안 헤더 누락.

## 탐지 정확도 검증 (validate.py)

```bash
docker compose -f targets/compose.yml up -d --build
python -m dast_harness.validate                 # 사람이 읽는 요약
python -m dast_harness.validate --json          # 기계용 (stdout은 순수 JSON)
```

정답지 항목마다 "어느 스캐너가 무슨 finding으로 탐지했는가"를 붙이고 **recall**
(= 탐지된 항목 / 전체 항목)을 계산한다. 매칭은 finding의 id·name에 대한 키워드
매칭이며, 정답지 순서상 **먼저 나온 항목이 이긴다**(구체적인 항목을 위에 둘 것).
한 finding이 두 항목에 중복 계상되지 않는다.

정답지에 매칭되지 않은 finding은 **false positive가 아니라 `unexpected`(수동 트리아지
대상)** 로 분류한다. 타겟이 정답지에 안 적힌 것을 노출할 수도 있으므로(예: robots.txt),
사람이 보기 전에 오탐으로 단정하지 않는다.

종료 코드: `0` 전부 탐지, `1` 하나 이상 미탐, `2` 인자·대상 오류, `130` 중단.

### 실측 결과 (nuclei v3.11.1 + nikto 2.6.1, 기본 설정 전체 템플릿)

```
detected 7/7 documented weaknesses (recall 100%)

  [x] exposed-dotenv            /.env          nikto, nuclei
  [x] exposed-git-config        /.git/config   nikto, nuclei
  [x] exposed-db-backup         /backup.sql    nikto
  [x] phpinfo-disclosure        /phpinfo.php   nikto
  [x] directory-listing         /uploads/      nikto
  [x] exposed-admin-panel       /admin/        nikto
  [x] missing-security-headers  /              nikto, nuclei

unexpected findings (manual triage needed): 16  [high: 1, info: 10, low: 1, medium: 1, unknown: 3]
```

recall은 100%지만 **정답지 7개 중 4개는 nikto 단독 탐지**였다. 스캐너 하나로는
같은 수치가 나오지 않는다 — 다중 스캐너 하네스를 만든 이유가 여기서 수치로 확인된다.

`unexpected` 16건을 직접 트리아지한 결과 네 부류였고, 자동으로 오탐이라 부르지
않은 이유가 그대로 드러난다.

| 부류 | 건수 | 예시 | 판정 |
|---|---|---|---|
| 이미 탐지된 항목의 **다른 이름** | 2 | nuclei `MySQL - Dump Files` @ `/backup.sql`, `Laravel - Sensitive Information Disclosure` @ `/.env` | 진짜 탐지. 키워드 사전(`match_any`)이 못 잡은 것 |
| **다른 포트/프로토콜**로 새어나간 스캔 | 9 | `SMB Version - Detection` @ `127.0.0.1:445`, mDNS@5353, SNMP@161 | 타겟 밖. 아래 참고 |
| 정답지에 없지만 **실재하는 노출** | 4 | `robots.txt` 항목 노출 (nuclei 2건, nikto 2건) | 진짜. 정답지를 좁게 잡은 결과 |
| **오탐** | 1 | nikto `PHP Easter Eggs` @ `/?=PHPB8B5F2A0-...` | 앱이 쿼리스트링을 무시하고 `/`를 200으로 돌려주므로 오탐 |

즉 "정답지에 없다 = 오탐"이 아니다. 16건 중 실제 오탐은 1건이었고, 2건은 채점기의
키워드 사전 한계였다. 이 구분을 자동화하지 않고 사람이 보게 남겨둔 것이 설계 의도다.

> **스코프 관찰**: nuclei는 URL의 포트(8080)뿐 아니라 **같은 호스트의 다른 포트**
> (445/5353/161)에도 network 템플릿을 던졌다. 대상 인증(`safety.py`)은 호스트
> 단위이므로 loopback 안에서 끝났지만, 허가된 원격 호스트를 스캔할 때는 "허가한
> 포트"보다 넓게 나갈 수 있다는 뜻이다. 알려진 한계로 기록해 둔다.

## 실행 (macOS 등 nuclei 설치 환경)

```bash
brew install nuclei
nuclei -version
python3 example.py http://127.0.0.1:8080
```

허가된 원격 대상을 스캔하려면 `example.py`의 `allowlist`에 호스트명을 추가한다.

## API

```python
from dast_harness import NucleiScanner, ScanRunner, ScanConfig, Target, Severity

runner = ScanRunner(NucleiScanner(), allowlist=set())
scan_id = runner.start_scan(Target("http://127.0.0.1:8080"),
                            ScanConfig(severities=[Severity.HIGH, Severity.CRITICAL]))

runner.get_status(scan_id)   # dict: status, findings_count, ...
runner.get_results(scan_id)  # list[Finding] (스캔 중에도 스냅샷 조회 가능)
runner.stop_scan(scan_id)    # 중단 요청
runner.wait(scan_id)         # 완료 대기
```

임의 CLI 인자를 그대로 전달하는 기능은 제공하지 않는다. 특히 `-u`, `-list` 같은
대상 변경 옵션이 허가 검사를 우회하지 않도록 모든 지원 옵션을 `ScanConfig` 필드로
명시한다.

## 테스트

```bash
python3 -m unittest discover -s tests -v
```

의존성·도커·스캐너 설치 없이 전부 돌아간다(가짜 스캐너와 인메모리 타겟 사용).
실제 도구를 쓰는 측정은 `python -m dast_harness.validate`로 분리돼 있다.
