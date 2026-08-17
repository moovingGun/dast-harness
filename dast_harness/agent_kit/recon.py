"""골격 정찰 에이전트 — **이 파일을 복사해서 고쳐라.**

IDOR/injection 에이전트를 명세만 보고 처음부터 짜지 말 것. 세 에이전트의 구조가
같아야 마지막에 합칠 수 있다. 고칠 곳은 `_probe()` 하나다.

정찰은 산출물이 **두 종류**다:
  - `endpoints`: 엔드포인트 인벤토리 → injection/IDOR 에이전트의 **입력**
  - `findings` : 진짜 취약점만. 발견한 URL 40개가 findings 40건이 되면 안 된다.

지금 상태로 기존 취약 앱(변경 없이)에 대해 동작한다:
    python3 targets/vulnerable_app/app.py &
    python3 -m dast_harness.agent_kit.recon http://127.0.0.1:8080
"""

from __future__ import annotations

import re
import sys
from collections import deque
from urllib.parse import parse_qsl, urlparse, urlunparse

from ..models import Severity
from .contract import (AgentFinding, Confidence, Coverage, Endpoint, Evidence,
                       Probe, validate_finding)
from .http import AgentHttpClient

HREF = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'>\s]+)""", re.I)
NUMERIC_SEG = re.compile(r"^\d+$")


def _templatize(path: str) -> str:
    """`/api/orders/1001` → `/api/orders/{id}`.

    값이 아니라 **모양**을 넘겨야 IDOR 에이전트가 "id를 바꿔본다"를 할 수 있다.
    """
    segs = [("{id}" if NUMERIC_SEG.match(s) else s) for s in path.split("/")]
    return "/".join(segs)


class ReconAgent:
    """같은 origin을 얕게 훑어 엔드포인트를 모으고, 정찰 고유 취약점을 낸다."""

    name = "recon"                       # scanner 값은 f"agent:{name}"

    def __init__(self, client: AgentHttpClient, *, max_pages: int = 40) -> None:
        self.client = client
        self.max_pages = max_pages
        self.endpoints: dict[tuple[str, str], Endpoint] = {}
        self.findings: list[AgentFinding] = []
        self.exchanges: dict[str, object] = {}   # url -> HttpExchange (증거 재사용)

    # ------------------------------------------------------------------- 수집
    def _record(self, ex, source: str) -> None:
        parsed = urlparse(ex.url)
        template = _templatize(parsed.path or "/")
        params = tuple(k for k, _ in parse_qsl(parsed.query))
        key = (ex.method, template)
        prev = self.endpoints.get(key)
        if prev is not None:
            params = tuple(dict.fromkeys(prev.params + params))
        self.endpoints[key] = Endpoint(
            method=ex.method,
            url_template=template,
            params=params,
            # 401/403이면 인증 필요, 200이면 불필요. 그 외는 미확인(None).
            auth_required={401: True, 403: True}.get(ex.status, False if ex.status == 200 else None),
            observed_status=ex.status,
            content_type=_ct(ex.response_headers),
            source=source,
        )

    def crawl(self, base: str) -> None:
        seen: set[str] = set()
        queue: deque[tuple[str, str]] = deque([(base, "seed")])

        robots = self.client.get(
            _join(base, "/robots.txt"), note="정찰: robots.txt는 비공개 경로를 광고한다"
        )
        self.exchanges[robots.url] = robots
        if robots.status == 200:
            self._record(robots, "guess")
            for line in robots.response_excerpt.splitlines():
                if ":" in line and line.split(":", 1)[0].strip().lower() in ("disallow", "allow"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        queue.append((_join(base, path), "robots.txt"))

        while queue and len(seen) < self.max_pages:
            url, source = queue.popleft()
            norm = _strip_fragment(url)
            if norm in seen:
                continue
            seen.add(norm)

            ex = self.client.get(norm, note=f"정찰: {source}에서 발견")
            self.exchanges[norm] = ex
            self._record(ex, source)

            if "html" in _ct(ex.response_headers).lower():
                for href in HREF.findall(ex.response_excerpt):
                    # resolve()가 같은 origin이 아니면 None을 준다 — 타겟 페이지에
                    # 심어진 외부 링크(프롬프트 인젝션 포함)를 여기서 1차로 거른다.
                    nxt = self.client.resolve(norm, href)
                    if nxt and _strip_fragment(nxt) not in seen:
                        queue.append((nxt, "link"))

    # ------------------------------------------------------------------- 판정
    def _probe(self, base: str) -> None:
        """**여기만 고치면 다른 에이전트가 된다.**

        지금은 예시로 하나만 본다: robots.txt가 광고한 경로가 실제로 접근되는가.
        증거는 항상 "기준선 + 대조"로 만든다.
        """
        robots = self.exchanges.get(_join(base, "/robots.txt"))
        if robots is None or robots.status != 200:
            return

        disallowed = [
            line.split(":", 1)[1].strip()
            for line in robots.response_excerpt.splitlines()
            if line.lower().startswith("disallow:") and line.split(":", 1)[1].strip() not in ("", "/")
        ]
        reachable = [
            p for p in disallowed
            if (ex := self.exchanges.get(_join(base, p))) is not None and ex.status == 200
        ]
        if not reachable:
            return

        proof = self.exchanges[_join(base, reachable[0])]
        self.findings.append(AgentFinding(
            scanner=f"agent:{self.name}",
            finding_id="robots-discloses-reachable-paths",
            name="robots.txt가 실제 접근 가능한 비공개 경로를 광고함",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            category="information-disclosure",
            matched_at=_join(base, "/robots.txt"),
            description=(
                "robots.txt의 Disallow 목록이 숨기려던 경로를 그대로 알려주고, "
                f"그 경로가 인증 없이 200으로 응답한다: {', '.join(reachable)}"
            ),
            tags=["recon", "information-disclosure", "robots"],
            evidence=Evidence(
                baseline_index=0,
                rationale=(
                    "robots.txt 자체는 취약점이 아니지만, 광고된 경로가 실제로 "
                    "접근되면 공격자에게 목록을 제공한 셈이 된다. 두 번째 요청이 "
                    "200인 것이 '광고 + 실제 접근 가능'을 동시에 증명한다."
                ),
                exchanges=[robots, proof],
            ),
            agent_data={self.name: Probe(
                strategy="robots-disallow-then-fetch",
                target="/robots.txt",
                target_kind="endpoint",
                attempts=len(disallowed),
                hits=reachable,
                actors=["anon"],
                extra={"disallowed": disallowed},
            )},
        ))

    # -------------------------------------------------------------------- 실행
    def run(self, base: str) -> dict:
        self.crawl(base)
        self._probe(base)

        problems = {f.finding_id: errs for f in self.findings if (errs := validate_finding(f))}
        if problems:   # 계약 위반은 조용히 넘기지 않는다
            raise AssertionError(f"계약 위반: {problems}")

        return {
            "endpoints": sorted(self.endpoints.values(), key=lambda e: (e.url_template, e.method)),
            "findings": self.findings,
            "coverage": Coverage(
                unit="endpoint",
                tested=len(self.exchanges),
                requests=self.client.request_count,
                findings=len(self.findings),
            ),
            "requests_made": self.client.request_count,
            "blocked": self.client.blocked,
        }


def _ct(headers: dict) -> str:
    return {k.lower(): v for k, v in headers.items()}.get("content-type", "")


def _join(base: str, path: str) -> str:
    p = urlparse(base)
    return urlunparse((p.scheme, p.netloc, path, "", "", ""))


def _strip_fragment(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))


def main(argv: list[str]) -> int:
    base = argv[1] if len(argv) > 1 else "http://127.0.0.1:8080"
    client = AgentHttpClient(allowlist=set(), max_requests=200)
    result = ReconAgent(client).run(base)

    print(f"엔드포인트 {len(result['endpoints'])}건 (요청 {result['requests_made']}회)")
    for e in result["endpoints"]:
        auth = {True: "auth", False: "open", None: "?"}[e.auth_required]
        params = f" ?{','.join(e.params)}" if e.params else ""
        print(f"  {e.method:4} {e.url_template:24}{params:12} {e.observed_status}  {auth:4} [{e.source}]")

    print(f"\nfindings {len(result['findings'])}건")
    for f in result["findings"]:
        print(f"  [{f.severity.value}/{f.confidence.value}] {f.finding_id} @ {f.matched_at}")
        print(f"      {f.description}")

    if result["blocked"]:
        print(f"\n안전장치가 거부한 요청 {len(result['blocked'])}건:")
        for url, why in result["blocked"]:
            print(f"  {url} — {why}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
