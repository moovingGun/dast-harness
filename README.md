# dast-harness

[![CI](https://github.com/moovingGun/dast-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/moovingGun/dast-harness/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

여러 스캐너를 같은 인터페이스 뒤에 꽂는 최소 DAST 하네스 (현재 nuclei, nikto).
스캔을 실행하고 상태·결과를 조회하며, **loopback 또는 명시적으로 허가된 대상만**
스캔하도록 안전장치를 강제한다.

## 구조

```
dast_harness/
  models.py          # Target, ScanConfig, Finding, Severity, ScanStatus, ScanState
  safety.py          # 로컬/허가 대상 검증 (스캔 전 강제 choke point)
  scanners/base.py   # Scanner 추상 인터페이스
  scanners/nuclei.py # nuclei 실행 + JSONL 스트리밍 파싱 → Finding 정규화
  scanners/nikto.py  # nikto 실행 + 종료 후 JSON 파일 파싱 → Finding 정규화
  runner.py          # 단일 스캐너: start_scan / get_status / get_results / stop_scan / wait
  orchestrator.py    # MultiScanRunner: 여러 스캐너 병렬 실행 + 롤업/병합
  reporters/base.py  # Reporter 인터페이스 + ScanReport (출력 전용 계층)
  reporters/json_reporter.py     # findings → JSON 문자열
  reporters/console_reporter.py  # 심각도별 콘솔 요약
example.py           # 단일 스캐너 예시
example_multi.py     # 다중 스캐너 예시
```

각 스캔은 완료 증거(`CompletionEvidence`: 종료코드·파싱 계정·버전·중단 여부 등)를
스캐너별로 기록하며, `get_status`의 `evidence` 필드로 조회된다.

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
