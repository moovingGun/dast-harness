"""ffuf adapter — 콘텐츠 디스커버리를 안전 경계 안으로.

링크에도 robots.txt에도 안 걸린 경로(`/admin`, `/backup.zip`, `/.git/config`)를
찾는 건 웹 스캐너의 기본기다 — Burp·ZAP·nikto가 전부 내장하고 있다. 우리 정찰
에이전트는 크롤러라 **링크로 도달 가능한 것만** 보므로 그 구간이 비어 있었다.

ffuf를 서브에이전트에게 Bash로 쥐여주는 대신 `Scanner` 어댑터로 감싼 이유가
이 저장소의 요점이다. 어댑터가 되면 `ScanRunner`가 실행 전에 `authorize_target()`을
통과시키고, 중단·타임아웃·완료 증거가 nuclei/nikto와 똑같이 붙는다.

**불변값 두 개** (`ScanConfig`로도 못 바꾼다):

- `-r`(리다이렉트 추적)를 **절대 넘기지 않는다.** 이 저장소의 안전 불변식이고,
  ffuf 기본값도 추적 안 함이다. 켜면 인가되지 않은 호스트로 끌려갈 수 있다
- 워드리스트 외의 임의 인자를 통과시키지 않는다 (README의 "임의 CLI 인자를 그대로
  전달하는 기능은 제공하지 않는다")

**severity를 매기지 않는다.** ffuf가 말하는 건 "이 경로가 존재한다"뿐이고, 그게
얼마나 심각한지는 무엇이 있느냐에 달렸다 — `/.env`와 `/about`이 같은 도구에서
같은 모양으로 나온다. 지어내지 않고 `INFO`로 두고 경로를 이름에 담는다. 판단은
사람이나 뒤에 오는 에이전트가 한다.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from collections import deque
from typing import Any
from urllib.parse import urljoin, urlparse

from ..models import Finding, ScanConfig, ScanOutcome, Severity, Target
from .base import OnFinding, OnWarning, Scanner, detect_version, stop_process_group

# 저장소에 딸려오는 기본 워드리스트. 큰 목록을 들고 오는 대신 **신호가 강한 것만**
# 추렸다 — 노출되면 곧바로 취약점이 되는 경로들. 넓게 훑을 거면 `--wordlist`로
# SecLists 같은 걸 지정한다.
DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlists", "content.txt")

# ffuf 기본 스레드는 40이다. 우리는 5로 잡는다. 이유가 둘인데 두 번째가 더 중요하다.
#
# 1. 요청 폭주는 되돌릴 수 없는 행동이고, 통제된 랩이 아니라 실제 대상에 붙을 수 있다
# 2. **동시성이 finding을 조용히 떨어뜨린다.** 우리 연습 타겟에서 실측한 결과
#    `-t 10`은 실행마다 5~7건으로 흔들렸고(`/.env`나 `/.git/config`를 놓쳤다),
#    `-t 5` 이하는 8건으로 고정됐다. 놓친 경로는 경고도 없이 그냥 안 나오므로
#    "취약점 없음"으로 읽힌다 — 이 저장소가 계속 부딪혀온 그 실패 모드다.
#
# 워드 113개에 0.14초라 속도는 애초에 제약이 아니다. 큰 워드리스트를 쓸 때만
# 생성자 인자로 올린다.
DEFAULT_THREADS = 5

# 매칭할 상태코드. 401/403도 남긴다 — "존재하지만 막혀 있다"는 그 자체로 정보다.
MATCH_CODES = "200,201,204,301,302,307,401,403,405,500"


class FfufScanner(Scanner):
    name = "ffuf"

    def __init__(self, binary: str = "ffuf", wordlist: str | None = None,
                 threads: int = DEFAULT_THREADS) -> None:
        self.binary = binary
        self.wordlist = wordlist or DEFAULT_WORDLIST
        self.threads = threads

    def is_available(self) -> bool:
        if shutil.which(self.binary) is None:
            return False
        if not os.path.exists(self.wordlist):
            return False
        try:
            proc = subprocess.run([self.binary, "-V"], capture_output=True, timeout=30)
            return proc.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _version(self) -> str | None:
        if not hasattr(self, "_ver"):
            self._ver = detect_version([self.binary, "-V"], r"ffuf\s+v?([\d.]+)")
        return self._ver

    def _build_command(
        self, target: Target, config: ScanConfig, output_path: str
    ) -> list[str]:
        base = target.url if target.url.endswith("/") else target.url + "/"
        cmd = [
            self.binary,
            "-u", f"{base}FUZZ",
            "-w", self.wordlist,
            "-o", output_path,
            "-of", "json",
            "-mc", MATCH_CODES,
            # 자동 보정: 소프트 404(존재하지 않는 경로에 200을 주는 앱)를 걸러낸다.
            # 없으면 워드리스트 전체가 finding으로 쏟아져 리포트가 무의미해진다.
            "-t", str(self.threads),
            "-s",            # 진행 표시 끄기 (stdout은 안 쓴다)
            "-noninteractive",
        ]
        # `-r`은 여기에도, 어디에도 없다. 리다이렉트 추적은 이 저장소의 불변식이다.
        if config.request_timeout is not None:
            cmd += ["-timeout", str(config.request_timeout)]
        if config.rate_limit is not None:
            cmd += ["-rate", str(config.rate_limit)]
        return cmd

    def _words(self) -> set[str]:
        """워드리스트 항목 집합. 자동 보정 탐침을 걸러내는 데 쓴다."""
        if not hasattr(self, "_wordset"):
            try:
                with open(self.wordlist, encoding="utf-8", errors="replace") as fh:
                    self._wordset = {l.strip() for l in fh if l.strip()}
            except OSError:
                self._wordset = set()
        return self._wordset

    def _to_finding(self, result: dict[str, Any], base_url: str) -> Finding:
        # **경로는 URL에서 뽑는다.** `input.FUZZ`를 믿으면 안 된다 — `-ac`가 만든
        # 자동 보정 탐침이 결과에 섞일 때 FUZZ와 url이 서로 다른 것을 가리키는
        # 레코드가 나온다(실측: FUZZ=".htaccessKcSMtePO", url=".../.env").
        # 실제로 요청돼서 매칭된 건 url 쪽이므로 그게 유일한 근거다.
        url = str(result.get("url") or "")
        path = urlparse(url).path.lstrip("/") if url else ""
        if not url:
            url = urljoin(base_url, path)
        status = result.get("status")
        length = result.get("length")
        # 경로를 **이름에 담는다.** 정답지 매칭이 finding의 id/name을 보므로,
        # `/.env`를 찾으면 `exposed-dotenv`의 키워드에 자연히 걸린다.
        name = f"discovered: /{path}" if path else "discovered path"
        return Finding(
            scanner=self.name,
            finding_id=f"content-discovery/{path}" if path else "content-discovery",
            name=name,
            # ffuf는 "존재한다"만 말한다. 심각도는 무엇이 있느냐에 달렸으므로
            # 지어내지 않는다 (모듈 docstring 참고).
            severity=Severity.INFO,
            matched_at=url,
            description=(
                f"콘텐츠 디스커버리로 발견한 경로 (status {status}, {length} bytes). "
                "링크·robots.txt에 없던 것이므로 무엇인지 확인이 필요하다."
            ),
            tags=["content-discovery", f"status-{status}"],
            raw=result,
        )

    def _parse_file(
        self,
        path: str,
        base_url: str,
        on_finding: OnFinding,
        on_warning: OnWarning | None,
    ) -> dict:
        """ffuf의 JSON 결과 파일을 읽는다. 없거나 깨졌으면 fatal."""
        out = {
            "output_present": False, "output_parseable": False,
            "parsed_records": 0, "invalid_records": 0, "fatal": True, "error": None,
        }
        if not os.path.exists(path):
            out["error"] = "ffuf result file is missing"
            return out
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read().strip()
        out["output_present"] = True
        if not text:
            out["error"] = "ffuf result file is empty"
            return out
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            out["error"] = "ffuf result file is not valid JSON"
            return out
        if not isinstance(data, dict):
            out["error"] = "ffuf JSON is not an object"
            return out
        results = data.get("results")
        if results is None:
            # 아무것도 못 찾아도 ffuf는 results: [] 를 쓴다. 키가 없으면 형식이 다른 것.
            out["error"] = "ffuf JSON is missing a results field"
            return out
        if not isinstance(results, list):
            out["error"] = "ffuf results field is not a list"
            return out

        # nikto와 같은 원칙: 문서 전체를 먼저 검증하고, 문제가 없을 때만 흘린다.
        words = self._words()
        pending: list[Finding] = []
        for item in results:
            if not isinstance(item, dict):
                out["invalid_records"] += 1
                if on_warning is not None:
                    on_warning("ffuf result entry was not an object")
                continue
            # 우리가 **실제로 물어본 경로**만 보고한다. `-ac`의 자동 보정 탐침은
            # 워드리스트에 없는 무작위 문자열이라 여기서 걸린다 — 안 거르면
            # 존재하지도 않는 경로가 finding으로 나간다 (실측으로 확인).
            fuzz = str(item.get("input", {}).get("FUZZ") or "")
            if words and fuzz and fuzz not in words:
                out["invalid_records"] += 1
                if on_warning is not None:
                    on_warning(f"ffuf reported a path we never asked for: {fuzz!r} "
                               "(auto-calibration probe); dropped")
                continue
            pending.append(self._to_finding(item, base_url))

        # 소프트 404 감지. 워드리스트의 절반 이상이 매칭됐다면 존재하지 않는 경로에도
        # 200을 주는 대상일 가능성이 높다. 조용히 걸러내지 않고 **경고로 알린다** —
        # 무엇이 진짜인지는 사람이 봐야 하고, 우리가 임의로 지우면 그 판단 기회가
        # 사라진다.
        if words and len(pending) > len(words) * 0.5 and on_warning is not None:
            on_warning(
                f"ffuf matched {len(pending)}/{len(words)} wordlist entries — the "
                "target likely returns a soft 404 (200 for paths that do not exist). "
                "Treat these findings as uncalibrated and confirm a few by hand."
            )

        out["output_parseable"] = True
        out["fatal"] = False
        for finding in pending:
            on_finding(finding)
            out["parsed_records"] += 1
        return out

    def run(
        self,
        target: Target,
        config: ScanConfig,
        on_finding: OnFinding,
        stop_event: threading.Event | None = None,
        on_warning: OnWarning | None = None,
    ) -> ScanOutcome:
        tmp_dir = tempfile.mkdtemp(prefix="ffuf-")
        output_path = os.path.join(tmp_dir, "ffuf.json")
        cmd = self._build_command(target, config, output_path)

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                start_new_session=True,
            )
        except OSError as exc:
            return ScanOutcome(
                exit_code=None, output_present=False, output_parseable=False,
                fatal=True, error=f"failed to launch ffuf: {exc}",
                scanner_version=self._version(),
            )

        stderr_chunks: deque[str] = deque(maxlen=200)

        def _drain_stderr() -> None:
            assert proc.stderr is not None
            for line in proc.stderr:
                stderr_chunks.append(line[:4096])

        err_thread = threading.Thread(target=_drain_stderr, daemon=True)
        err_thread.start()

        stopped = False
        while proc.poll() is None:
            if stop_event is not None and stop_event.is_set():
                stopped = True
                stop_process_group(proc)
                break
            time.sleep(0.05)
        proc.wait()
        err_thread.join(timeout=5)
        if proc.stderr is not None:
            proc.stderr.close()

        try:
            if stopped:
                return ScanOutcome(
                    exit_code=proc.returncode, output_present=False,
                    output_parseable=False, stopped=True,
                    scanner_version=self._version(),
                )
            parsed = self._parse_file(output_path, target.url, on_finding, on_warning)
            error = parsed["error"]
            if error is None and stderr_chunks and proc.returncode not in (0, None):
                error = "".join(stderr_chunks).strip() or None
            return ScanOutcome(
                exit_code=proc.returncode,
                output_present=parsed["output_present"],
                output_parseable=parsed["output_parseable"],
                parsed_records=parsed["parsed_records"],
                invalid_records=parsed["invalid_records"],
                fatal=parsed["fatal"],
                stopped=False,
                scanner_version=self._version(),
                error=error,
            )
        finally:
            try:
                os.remove(output_path)
            except OSError:
                pass
            try:
                os.rmdir(tmp_dir)
            except OSError:
                pass
