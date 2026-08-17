"""골격 정찰 에이전트 — **이 파일을 복사해서 고쳐라.**

IDOR/injection 에이전트를 명세만 보고 처음부터 짜지 말 것. 세 에이전트의 구조가
같아야 마지막에 합칠 수 있다. 고칠 곳은 `_probe()` 하나다.

정찰은 산출물이 **두 종류**다:
  - `request_seeds`: 실제로 보낼 수 있는 검사 요청 → injection/IDOR의 **입력**
  - `findings`     : 진짜 취약점만. 발견한 요청 40개가 findings 40건이 되면 안 된다.

지금 상태로 기존 취약 앱(변경 없이)에 대해 동작한다:
    python3 targets/vulnerable_app/app.py &
    python3 -m dast_harness.agent_kit.recon http://127.0.0.1:8080
"""

from __future__ import annotations

import re
import sys
from collections import deque
from dataclasses import replace
from urllib.parse import parse_qsl, urlparse, urlunparse

from ..models import Severity
from .base import Agent
from .contract import (AgentFinding, Confidence, Evidence, Probe,
                       ReconResult, RequestParameter, RequestSeed)
from .http import AgentHttpClient

HREF = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'>\s]+)""", re.I)
FORM = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
FIELD = re.compile(r"<(?:input|select|textarea)\b([^>]*)>", re.I)
ATTR = re.compile(r"""([\w-]+)\s*=\s*["']?([^"'>\s]*)""")
NUMERIC_SEG = re.compile(r"^\d+$")

# 값이 아니라 데이터가 아닌 컨트롤. 주입 대상이 아니다.
NON_DATA_FIELDS = ("submit", "button", "reset", "image")

# <input type> → RequestParameter.type. 숫자 칸에 문자열 페이로드를 넣으면
# 타입 오류가 SQL 오류로 오인되므로 이 정보가 injection 팀에 필요하다.
FIELD_TYPES = {"number": "int", "range": "int", "checkbox": "bool"}


def _attrs(chunk: str) -> dict[str, str]:
    return {k.lower(): v for k, v in ATTR.findall(chunk)}


def _guess_type(value: str) -> str:
    """관측된 값에서 타입을 추정. 폼처럼 선언된 타입이 없을 때만 쓴다."""
    if NUMERIC_SEG.match(value):
        return "int"
    if value.lower() in ("true", "false"):
        return "bool"
    return "string"


def _path_params(path: str) -> tuple[RequestParameter, ...]:
    """`/api/orders/1001` → `id=1001` (location="path").

    전에는 경로를 `/api/orders/{id}`로 바꿔서 넘겼다. 지금은 **실제 값을 보존**하고
    "이 세그먼트가 변수다"를 파라미터로 말한다 — IDOR은 값을 알아야 기준선을
    잡고 옆 id로 옮겨갈 수 있다.
    """
    numeric = [s for s in path.split("/") if NUMERIC_SEG.match(s)]
    return tuple(
        RequestParameter(
            name="id" if len(numeric) == 1 else f"id{i + 1}",
            location="path", value=seg, type="int",
        )
        for i, seg in enumerate(numeric)
    )


class ReconAgent(Agent):
    """같은 origin을 얕게 훑어 엔드포인트를 모으고, 정찰 고유 취약점을 낸다."""

    name = "recon"                       # scanner 값은 f"agent:{name}"
    unit = "endpoint"                    # Coverage.unit — 정찰은 엔드포인트를 센다
    result_cls = ReconResult             # 고유 산출물: request_seeds

    def __init__(self, client: AgentHttpClient, *, max_pages: int = 40) -> None:
        super().__init__(client)
        self.max_pages = max_pages
        self.seeds: dict[tuple[str, str], RequestSeed] = {}   # (method, template) -> seed
        self.exchanges: dict[str, object] = {}   # url -> HttpExchange (증거 재사용)

    # ------------------------------------------------------------------- 수집
    def _add(self, seed: RequestSeed) -> None:
        """씨앗을 등록한다. 같은 (method, template)이면 파라미터를 합친다.

        값마다 씨앗을 만들면 `/api/orders/1001`, `1002`, ...로 목록이 값에
        뒤덮인다. template으로 묶고 파라미터만 누적한다.
        """
        key = (seed.method, seed.template)
        prev = self.seeds.get(key)
        if prev is None:
            self.seeds[key] = seed
            return
        merged = {(p.name, p.location): p for p in prev.params}
        for p in seed.params:            # 나중에 본 쪽이 값을 갱신한다
            merged[(p.name, p.location)] = p
        self.seeds[key] = replace(
            prev,
            params=tuple(merged.values()),
            # 관측값은 실제로 보낸 쪽(status가 있는 쪽)을 남긴다.
            observed_status=seed.observed_status or prev.observed_status,
            observed_content_type=seed.observed_content_type or prev.observed_content_type,
            auth_required=(seed.auth_required if seed.auth_required is not None
                           else prev.auth_required),
            body_content_type=seed.body_content_type or prev.body_content_type,
        )

    def _record(self, ex, source: str) -> None:
        """관측한 요청 하나를 씨앗으로."""
        parsed = urlparse(ex.url)
        query = tuple(
            RequestParameter(name=k, location="query", value=v, type=_guess_type(v))
            for k, v in parse_qsl(parsed.query)
        )
        self._add(RequestSeed(
            method=ex.method,
            url=ex.url,
            params=_path_params(parsed.path or "/") + query,
            # 401/403이면 인증 필요, 200이면 불필요. 그 외는 미확인(None).
            auth_required={401: True, 403: True}.get(
                ex.status, False if ex.status == 200 else None),
            observed_status=ex.status,
            observed_content_type=_ct(ex.response_headers),
            source=source,
        ))

    def _record_forms(self, page_url: str, html: str) -> None:
        """폼에서 씨앗을 만든다. **injection 팀이 POST 파라미터를 받는 경로다.**

        크롤러는 `action` 속성만 보고 `<input name=...>`은 버리고 있었다. 그래서
        `/login`을 찾아도 `username`/`password`가 있다는 걸 injection 팀이 다시
        긁어야 했다. 정찰이 이미 본 정보를 버리지 않는다.

        폼은 **보내지 않는다.** 상태를 바꾸는 POST를 정찰이 눌러볼 수는 없으므로
        `observed_status`는 비운다 — "모양은 찾았고 아직 안 보냈다"는 뜻이다.
        """
        for raw_attrs, body in FORM.findall(html):
            attrs = _attrs(raw_attrs)
            method = attrs.get("method", "GET").upper()
            action = self.client.resolve(page_url, attrs.get("action") or page_url)
            if not action:               # 다른 origin으로 보내는 폼은 버린다
                continue

            location = "body" if method == "POST" else "query"
            params = []
            for raw_field in FIELD.findall(body):
                f = _attrs(raw_field)
                name, kind = f.get("name"), f.get("type", "text").lower()
                if not name or kind in NON_DATA_FIELDS:
                    continue
                params.append(RequestParameter(
                    name=name, location=location, value=f.get("value", ""),
                    type=FIELD_TYPES.get(kind, "string"),
                ))
            if not params:
                continue

            self._add(RequestSeed(
                method=method,
                url=action,
                params=_path_params(urlparse(action).path or "/") + tuple(params),
                body_content_type=(
                    (attrs.get("enctype") or "application/x-www-form-urlencoded")
                    if method == "POST" else ""
                ),
                source="form",
            ))

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
                self._record_forms(norm, ex.response_excerpt)
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
    def run(self, base: str) -> ReconResult:
        self.crawl(base)
        self._probe(base)

        # finish()가 coverage/요청수/blocked를 채우고 계약을 검사한다.
        # 위반이면 AssertionError — 조용히 넘기지 않는다.
        return self.finish(
            self.findings,
            tested=len(self.exchanges),
            request_seeds=sorted(self.seeds.values(),
                                 key=lambda s: (s.template, s.method)),
        )


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

    done = result.completion
    print(f"요청 씨앗 {len(result.request_seeds)}건 (요청 {done.requests_made}회)")
    for s in result.request_seeds:
        auth = {True: "auth", False: "open", None: "?"}[s.auth_required]
        params = ", ".join(
            f"{p.name}={p.value or '?'}:{p.location}/{p.type}" for p in s.params
        )
        status = s.observed_status if s.observed_status is not None else "-"
        print(f"  {s.method:4} {s.template:24} {str(status):4} {auth:4} [{s.source}]")
        if params:
            print(f"       {params}")

    print(f"\nfindings {len(result.findings)}건")
    for f in result.findings:
        print(f"  [{f.severity.value}/{f.confidence.value}] {f.finding_id} @ {f.matched_at}")
        print(f"      {f.description}")

    cov = result.coverage
    print(f"\ncoverage: {cov.unit} {cov.tested}건 검사, {cov.skipped}건 건너뜀")

    if done.blocked:
        print(f"\n안전장치가 거부한 요청 {len(done.blocked)}건:")
        for url, why in done.blocked:
            print(f"  {url} — {why}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
