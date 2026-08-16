# nuclei-harness

단일 스캐너(nuclei) 기반 최소 DAST 하네스. nuclei를 실행하고 스캔 상태·결과를
조회하며, **loopback 또는 명시적으로 허가된 대상만** 스캔하도록
안전장치를 강제한다.

## 구조

```
dast_harness/
  models.py          # Target, ScanConfig, Finding, Severity, ScanStatus, ScanState
  safety.py          # 로컬/허가 대상 검증 (스캔 전 강제 choke point)
  scanners/base.py   # Scanner 추상 인터페이스
  scanners/nuclei.py # nuclei 실행 + JSONL 스트리밍 파싱 → Finding 정규화
  runner.py          # start_scan / get_status / get_results / stop_scan / wait
  reporters/base.py  # Reporter 인터페이스 + ScanReport (출력 전용 계층)
  reporters/json_reporter.py     # findings → JSON 문자열
  reporters/console_reporter.py  # 심각도별 콘솔 요약
example.py           # 사용 예시
```

## 리포팅 (reporters/)

스캔 결과(`Finding` 리스트)를 출력 포맷으로 내보내는 얇은 계층. 스캔 로직과 분리돼
있고, `Finding`이 스캐너 무관이라 스캐너를 추가해도 그대로 재사용된다.

```python
from dast_harness import build_report, ConsoleReporter, JSONReporter

report = build_report(runner, scan_id)
print(ConsoleReporter().render(report))          # 콘솔 요약
open("results.json", "w").write(JSONReporter().render(report))  # JSON 저장
```

## 안전장치 (safety.py)

`ScanRunner.start_scan()`은 스캐너 프로세스가 뜨기 전에 `authorize_target()`을
반드시 통과시킨다. 대상은 다음 중 하나일 때만 허용된다.

1. 대상이 loopback IP 또는 `localhost`
2. 호스트가 명시적 `allowlist`에 포함 (허가된 대상 예외)

사설망과 link-local 주소도 기본적으로 거부한다. 임의의 DNS 이름은 Nuclei 실행 시
다시 해석될 수 있으므로 `localhost` 이외에는 명시적 allowlist가 필요하다.

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
