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

import html
import re
import sys
from collections import deque
from dataclasses import replace
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Severity
from .base import Agent
from .contract import (AgentFinding, Confidence, Evidence, Probe,
                       ReconResult, RequestParameter, RequestSeed)
from .http import AgentHttpClient

HREF = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'>\s]+)""", re.I)

# 태그 여는 부분: 따옴표 안의 `>`는 태그 끝이 아니다.
# `<form onsubmit="return a>b" method="post">`에서 `[^>]*`를 쓰면 onsubmit 안의
# `>`에서 끊겨 method/action을 못 읽고, GET + 현재 페이지로 잘못 폴백한다.
_TAG_ATTRS = r"""((?:[^>"']|"[^"]*"|'[^']*')*)"""

FORM = re.compile(rf"<form\b{_TAG_ATTRS}>(.*?)</form>", re.I | re.S)
FIELD = re.compile(rf"<(?:input|select|textarea)\b{_TAG_ATTRS}>", re.I)

# 속성 하나. 따옴표로 감싼 값은 **통째로** 먹는다 — 값 안의 공백에서 멈추면
# 그 뒤를 다시 스캔해서 유령 속성을 만든다. `placeholder="hint: type=submit"`이
# type=submit으로 읽혀 비밀번호 필드가 조용히 사라지는 사고가 났다.
ATTR = re.compile(r"""([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]*))""")

NUMERIC_SEG = re.compile(r"^\d+$")

# 사용자 열거 판정에 쓰는 값들.
# 비밀번호는 하나만 쓴다 — 계정 잠금을 유발하지 않기 위해서다.
WRONG_PASSWORD = "not-the-password-9f2a"
# 존재하지 않는다고 확신할 수 있는 이름 둘. 응답이 안정적인지 보려면 둘이 필요하다.
ABSENT_USERS = ("nonexistent-user-7c1d", "nonexistent-user-3b8e")
USERNAME_FIELDS = ("user", "email", "login", "account", "id")
PASSWORD_FIELDS = ("pass", "pwd", "secret")
# 경로가 이렇게 생겼으면 인증을 처리할 가능성이 높다 (정렬에만 쓴다).
LOGIN_PATH_HINTS = ("login", "signin", "sign-in", "auth", "session")
# 폼이 여러 개일 때 몇 개까지 시도할지. 폼마다 3회를 보내므로 상한을 둔다.
MAX_LOGIN_CANDIDATES = 3

# 값이 아니라 데이터가 아닌 컨트롤. 주입 대상이 아니다.
NON_DATA_FIELDS = ("submit", "button", "reset", "image")

# <input type> → RequestParameter.type. 숫자 칸에 문자열 페이로드를 넣으면
# 타입 오류가 SQL 오류로 오인되므로 이 정보가 injection 팀에 필요하다.
FIELD_TYPES = {"number": "int", "range": "int", "checkbox": "bool"}


def _attrs(chunk: str) -> dict[str, str]:
    """태그 속성을 dict로. 값의 HTML 엔티티는 풀어준다 (`&amp;` → `&`)."""
    return {
        name.lower(): html.unescape(double or single or bare)
        for name, double, single, bare in ATTR.findall(chunk)
    }


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
        # 수집 중인 씨앗. `self.seeds`는 부모가 **받는 쪽** 입력으로 쓰므로
        # (정찰은 만드는 쪽이라 비어 있다) 이름을 겹치지 않게 둔다.
        self._collected: dict[tuple[str, str], RequestSeed] = {}  # (method, template) -> seed
        self.exchanges: dict[str, object] = {}   # url -> HttpExchange (증거 재사용)
        # url -> 잘리지 않은 본문. exchange.response_excerpt는 증거용으로 잘려
        # 있으므로 파싱에 쓰면 경계 뒤의 폼이 조용히 사라진다.
        self.bodies: dict[str, str] = {}
        self.skipped = 0
        self.skip_reasons: dict[str, int] = {}

    # ------------------------------------------------------------------- 수집
    def _add(self, seed: RequestSeed) -> None:
        """씨앗을 등록한다. 같은 (method, template)이면 파라미터를 합친다.

        값마다 씨앗을 만들면 `/api/orders/1001`, `1002`, ...로 목록이 값에
        뒤덮인다. template으로 묶고 파라미터만 누적한다.
        """
        key = (seed.method, seed.template)
        prev = self._collected.get(key)
        if prev is None:
            self._collected[key] = seed
            return

        # `url`과 `location="path"` 파라미터는 한 쌍이다. 따로 합치면
        # url=/api/orders/1001 + id=7 처럼 **존재하지 않았던 요청**이 만들어지고
        # template이 자기 키와 달라진다. 그래서 실제로 보낸 쪽을 통째로 고른다.
        if prev.observed_status is None and seed.observed_status is not None:
            primary, other = seed, prev
        else:
            primary, other = prev, seed

        # 경로 밖 파라미터만 합친다. 나중에 본 쪽(seed)이 값을 갱신한다.
        non_path = {(p.name, p.location): p
                    for p in prev.params if p.location != "path"}
        non_path.update({(p.name, p.location): p
                         for p in seed.params if p.location != "path"})

        self._collected[key] = replace(
            primary,
            params=tuple(p for p in primary.params if p.location == "path")
                   + tuple(non_path.values()),
            observed_status=primary.observed_status or other.observed_status,
            observed_content_type=(primary.observed_content_type
                                   or other.observed_content_type),
            auth_required=(primary.auth_required if primary.auth_required is not None
                           else other.auth_required),
            body_content_type=primary.body_content_type or other.body_content_type,
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

    def _record_forms(self, page_url: str, page_html: str) -> None:
        """폼에서 씨앗을 만든다. **injection 팀이 POST 파라미터를 받는 경로다.**

        크롤러는 `action` 속성만 보고 `<input name=...>`은 버리고 있었다. 그래서
        `/login`을 찾아도 `username`/`password`가 있다는 걸 injection 팀이 다시
        긁어야 했다. 정찰이 이미 본 정보를 버리지 않는다.

        폼은 **보내지 않는다.** 상태를 바꾸는 POST를 정찰이 눌러볼 수는 없으므로
        `observed_status`는 비운다 — "모양은 찾았고 아직 안 보냈다"는 뜻이다.
        """
        for raw_attrs, body in FORM.findall(page_html):
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

        robots, robots_body = self.client.fetch(
            _join(base, "/robots.txt"), note="정찰: robots.txt는 비공개 경로를 광고한다"
        )
        self.exchanges[robots.url] = robots
        self.bodies[robots.url] = robots_body
        if robots.status == 200:
            self._record(robots, "guess")
            for line in robots_body.splitlines():
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

            ex, page = self.client.fetch(norm, note=f"정찰: {source}에서 발견")
            self.exchanges[norm] = ex
            self.bodies[norm] = page
            self._record(ex, source)

            if "html" in _ct(ex.response_headers).lower():
                self._record_forms(norm, page)
                for raw_href in HREF.findall(page):
                    # HTML 엔티티를 풀지 않으면 `?a=1&amp;b=2`가 그대로 요청되고
                    # 파라미터 이름이 `amp;b`로 잡힌다.
                    href = html.unescape(raw_href)
                    # resolve()가 같은 origin이 아니면 None을 준다 — 타겟 페이지에
                    # 심어진 외부 링크(프롬프트 인젝션 포함)를 여기서 1차로 거른다.
                    nxt = self.client.resolve(norm, href)
                    if nxt and _strip_fragment(nxt) not in seen:
                        queue.append((nxt, "link"))

    # --------------------------------------------------------- 사용자 열거 판정
    def _probe_user_enumeration(self, base: str) -> None:
        """로그인 실패 응답이 계정 존재 여부를 알려주는가.

        **대조를 두 번 한다.** 실재 계정과 없는 계정의 응답이 다르다는 것만으로는
        부족하다 — 응답에 타임스탬프나 토큰이 섞여 있으면 매번 다르기 때문이다.
        그래서 없는 계정을 **두 번** 보내 그 둘이 같은지 확인한다.

            기준선  실재 계정 + 틀린 비밀번호  → 응답 A
            공격    없는 계정1 + 틀린 비밀번호 → 응답 B
            대조    없는 계정2 + 틀린 비밀번호 → 응답 B와 같아야 한다

        A ≠ B 이고 B == B2 이면 차이의 원인이 **계정 존재 여부**로 좁혀진다.
        B ≠ B2 이면 응답이 원래 흔들리는 것이므로 판정하지 않는다.

        비밀번호는 틀린 것 하나만 쓴다. 계정 잠금을 유발할 수 있어 시도를 3회로
        묶고, 무차별 대입은 `withheld`에 남긴다.
        """
        candidates = self._login_seeds()
        if not candidates:
            self._skip("no-login-form")
            return
        # 사용자명/비밀번호 폼이 여럿일 수 있고(로그인·가입·관리자), 그중 **실제로
        # 인증을 처리하는 것**만 차이를 낸다. 경로 이름이 로그인처럼 생긴 것을
        # 먼저 보되, 하나만 보고 포기하지 않는다 — 예전엔 첫 후보(관리자 폼)가
        # 로그인 처리를 안 해서 조용히 아무것도 못 찾았다.
        for seed, user_field, pass_field in candidates[:MAX_LOGIN_CANDIDATES]:
            if self._differential(seed, user_field, pass_field):
                return

    def _differential(self, seed, user_field, pass_field) -> bool:
        """이 폼 하나를 판정한다. finding을 냈으면 True."""
        known = self._known_username(seed, user_field)
        if known is None:
            # 실재한다고 믿을 만한 계정이 없으면 기준선을 못 잡는다. 아무 이름이나
            # 넣고 "실재 계정"이라 가정하면 판정이 통째로 무의미해진다.
            self._skip("no-known-account")
            return False

        def attempt(username: str, note: str):
            body = urlencode({user_field: username, pass_field: WRONG_PASSWORD})
            return self.client.post(seed.url, body=body, note=note)

        baseline = attempt(known, f"기준선: 실재 계정 {known!r} + 틀린 비밀번호")
        absent1 = attempt(ABSENT_USERS[0], "공격: 없는 계정 + 틀린 비밀번호")
        absent2 = attempt(ABSENT_USERS[1], "대조: 다른 없는 계정 — 응답이 안정적인지 확인")

        if baseline.status is None or absent1.status is None:
            self._skip("login-unreachable")
            return False
        if absent1.response_excerpt != absent2.response_excerpt:
            # 없는 계정끼리도 응답이 다르다 = 응답이 원래 흔들린다. 계정 존재
            # 여부 때문이라고 말할 수 없다.
            self._skip("login-response-unstable")
            return False
        if baseline.response_excerpt == absent1.response_excerpt:
            return False    # 같은 응답 = 열거 불가. 이 폼은 정상이다.

        same_status = baseline.status == absent1.status
        self.findings.append(AgentFinding(
            scanner=f"agent:{self.name}",
            finding_id="user-enumeration-login",
            name="로그인 실패 응답이 계정 존재 여부를 알려줌 (username enumeration)",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            category="information-disclosure",
            matched_at=seed.url,
            description=(
                "실재하는 계정과 없는 계정의 로그인 실패 응답이 서로 다르다. "
                "공격자가 유효한 사용자명 목록을 만들 수 있고, 그건 비밀번호 공격의 "
                "출발점이 된다."
            ),
            tags=["recon", "user-enumeration", "information-disclosure"],
            evidence=Evidence(
                baseline_index=0,
                rationale=(
                    f"실재 계정 {known!r}과 없는 계정의 실패 응답이 다르다"
                    + (f" (둘 다 {baseline.status}인데 본문이 다름)" if same_status
                       else f" ({baseline.status} vs {absent1.status})")
                    + ". 없는 계정 두 개의 응답은 서로 같으므로, 차이의 원인은 "
                      "응답의 흔들림이 아니라 계정 존재 여부다."
                ),
                exchanges=[baseline, absent1, absent2],
            ),
            agent_data={self.name: Probe(
                strategy="login-differential",
                target=seed.template,
                target_kind="endpoint",
                attempts=3,
                hits=[known],
                actors=["anon"],
                # 계정 잠금을 유발할 수 있어 일부러 안 한 것.
                withheld=["credential-bruteforce", "account-lockout-probing",
                          "timing-side-channel"],
                extra={"user_field": user_field,
                       "same_status": same_status},
            )},
        ))
        return True

    def _login_seeds(self):
        """사용자명/비밀번호를 둘 다 받는 POST 씨앗들. 로그인처럼 생긴 것 우선."""
        found = []
        for seed in self._collected.values():
            if seed.method != "POST":
                continue
            user = next((p.name for p in seed.params
                         if p.location == "body"
                         and any(k in p.name.lower() for k in USERNAME_FIELDS)), None)
            pw = next((p.name for p in seed.params
                       if p.location == "body"
                       and any(k in p.name.lower() for k in PASSWORD_FIELDS)), None)
            if user and pw:
                found.append((seed, user, pw))
        # 경로가 로그인처럼 생긴 것을 앞으로. 그게 인증을 처리할 가능성이 높다.
        found.sort(key=lambda item: not any(
            hint in urlparse(item[0].url).path.lower() for hint in LOGIN_PATH_HINTS))
        return found

    def _known_username(self, seed, user_field: str) -> str | None:
        """실재한다고 믿을 만한 계정 이름.

        1) `--auth`가 세션을 세운 actor — 로그인이 실제로 됐으므로 확실하다
        2) 폼에 박혀 있던 값 (`value="admin"` 같은 것)
        지어내지 않는다. 없으면 None.
        """
        actors = [a for a in self.client.actors if a != "anon"]
        if actors:
            return actors[0]
        observed = next((p.value for p in seed.params
                         if p.name == user_field and p.value), None)
        return observed or None

    def _skip(self, reason: str) -> None:
        self.skipped += 1
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1

    # ------------------------------------------------------------------- 판정
    def _probe(self, base: str) -> None:
        """**여기만 고치면 다른 에이전트가 된다.**

        지금은 예시로 하나만 본다: robots.txt가 광고한 경로가 실제로 접근되는가.
        증거는 항상 "기준선 + 대조"로 만든다.
        """
        robots_url = _join(base, "/robots.txt")
        robots = self.exchanges.get(robots_url)
        if robots is None or robots.status != 200:
            return

        disallowed = [
            line.split(":", 1)[1].strip()
            for line in self.bodies.get(robots_url, "").splitlines()
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
        self._probe_user_enumeration(base)

        # finish()가 coverage/요청수/blocked를 채우고 계약을 검사한다.
        # 위반이면 AssertionError — 조용히 넘기지 않는다.
        return self.finish(
            self.findings,
            tested=len(self.exchanges),
            skipped=self.skipped,
            skip_reasons=self.skip_reasons,
            request_seeds=sorted(self._collected.values(),
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
