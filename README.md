# nuclei-harness

단일 스캐너(nuclei) 기반 최소 DAST 하네스. nuclei를 실행하고 스캔 상태·결과를
조회하며, **로컬(loopback/private) 또는 명시적으로 허가된 대상만** 스캔하도록
안전장치를 강제한다.

## 구조

```
dast_harness/
  models.py          # Target, ScanConfig, Finding, Severity, ScanStatus, ScanState
  safety.py          # 로컬/허가 대상 검증 (스캔 전 강제 choke point)
  scanners/base.py   # Scanner 추상 인터페이스
  scanners/nuclei.py # nuclei 실행 + JSONL 스트리밍 파싱 → Finding 정규화
  runner.py          # start_scan / get_status / get_results / stop_scan / wait
example.py           # 사용 예시
```

## 안전장치 (safety.py)

`ScanRunner.start_scan()`은 스캐너 프로세스가 뜨기 전에 `authorize_target()`을
반드시 통과시킨다. 대상은 다음 중 하나일 때만 허용된다.

1. 호스트가 resolve되는 **모든** IP가 loopback / private / link-local
2. 호스트가 명시적 `allowlist`에 포함 (허가된 대상 예외)

공인 도메인은 기본 거부. DNS로 우회하려 해도 resolve된 IP 중 하나라도 public이면
거부된다.

## 실행 (칼리 등 nuclei 설치 환경)

```bash
which nuclei || sudo apt install -y nuclei   # 칼리엔 대개 이미 있음
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
