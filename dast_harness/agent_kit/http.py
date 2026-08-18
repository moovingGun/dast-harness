"""에이전트용 HTTP 클라이언트. 스캐너와 같은 안전 경계를 통과한다.

설계 원칙: **계약 준수를 규율이 아니라 구조로 강제한다.**
`request()`가 이미 채워진 `HttpExchange`를 돌려주므로, 에이전트 작성자가
`actor`나 마스킹을 빼먹을 수 없다.

`ScanRunner`의 상속이 아니라 **형제**다. `ScanConfig`의 severities/tags/
template_ids는 에이전트에 무의미하므로 `Scanner` 인터페이스에 끼우지 않는다.

stdlib만 쓴다 (저장소 규칙). `requests`/`httpx`를 쓰지 않는다.
"""

from __future__ import annotations

import gzip
import http.cookiejar
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

from ..safety import TargetNotAuthorizedError, authorize_target
from .contract import MAX_EXCERPT, HttpExchange

DEFAULT_UA = "dast-harness-agent/0.1 (+local scan)"

# 파싱용 본문 상한. 증거용 `MAX_EXCERPT`(2048자)와 **별개**다 — 증거는 리포트에
# 실리므로 짧아야 하지만, 링크·폼을 파싱하는 쪽은 페이지 전체가 필요하다.
MAX_BODY = 131072


class RequestBudgetExceeded(RuntimeError):
    """에이전트 루프가 폭주했다. 통제 타겟이라도 무한 요청은 막는다."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """리다이렉트를 따라가지 않는다.

    nuclei에 `-disable-redirects`를 항상 붙이는 것과 같은 이유다. 로컬 대상이
    공인 URL로 리다이렉트해 스캔을 비인가 호스트로 유도하는 것을 결정적으로 막는다.
    끌 수 없는 안전 불변값.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class AgentHttpClient:
    """에이전트가 쓰는 유일한 HTTP 통로.

    - **매 요청** `authorize_target()` 통과 (LLM이 URL을 고르기 때문)
    - 리다이렉트 미추적
    - `actor`별 쿠키 격리 (IDOR은 두 신원이 동시에 필요하다)
    - 자격증명 헤더 자동 마스킹된 `HttpExchange` 반환
    - 요청 예산 상한
    """

    def __init__(
        self,
        allowlist: set[str] | None = None,
        *,
        max_requests: int = 500,
        timeout: float = 10.0,
        delay: float = 0.0,
        user_agent: str = DEFAULT_UA,
    ) -> None:
        self.allowlist = {h.lower() for h in (allowlist or set())}
        self.max_requests = max_requests
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent
        self.request_count = 0
        self._jars: dict[str, http.cookiejar.CookieJar] = {}
        self._openers: dict[str, urllib.request.OpenerDirector] = {}
        self._blocked: list[tuple[str, str]] = []   # (url, 거부 사유)
        self._actor_headers: dict[str, dict[str, str]] = {}
        # 세션이 **살아있음을 확인한** actor만 여기 들어온다. auth.establish()가
        # 채운다. 에이전트는 이 목록만 믿으면 된다 — 설정에 alice가 적혀 있다는
        # 사실과 alice로 로그인이 됐다는 사실은 다른 얘기다.
        self._actors: list[str] = []

    # ------------------------------------------------------------------ actor
    def _opener(self, actor: str) -> urllib.request.OpenerDirector:
        """actor마다 독립된 쿠키 항아리. alice와 bob이 섞이면 IDOR 판정이 무의미해진다."""
        if actor not in self._openers:
            jar = http.cookiejar.CookieJar()
            self._jars[actor] = jar
            self._openers[actor] = urllib.request.build_opener(
                _NoRedirect(), urllib.request.HTTPCookieProcessor(jar)
            )
        return self._openers[actor]

    def cookies(self, actor: str) -> list[str]:
        return [c.name for c in self._jars.get(actor, [])]

    @property
    def actors(self) -> list[str]:
        """세션이 확인된 actor 이름들. **IDOR 에이전트의 진입점이다.**

            for actor in self.client.actors: ...

        비어 있으면 `--auth`가 없었거나 전부 인증에 실패한 것이다. 그때 비로그인
        요청으로 대신하지 말고 `skipped`로 넘겨라 — 아무것도 못 찾은 결과와
        로그인 없이 찾아본 결과는 다르다.
        """
        return list(self._actors)

    def mark_authenticated(self, actor: str) -> None:
        """`auth.establish()`가 verify를 통과시킨 뒤에만 부른다."""
        if actor not in self._actors:
            self._actors.append(actor)

    def set_actor_headers(self, actor: str, headers: dict[str, str]) -> None:
        """이 actor의 모든 요청에 붙일 헤더 (`Authorization: Bearer ...` 등).

        요청마다 준 헤더가 우선한다. 값은 `HttpExchange`에서 마스킹된다.
        """
        self._actor_headers.setdefault(actor, {}).update(headers)

    def set_cookie(self, actor: str, name: str, value: str, url: str) -> None:
        """이 actor의 쿠키 항아리에 쿠키를 직접 넣는다.

        사람이 브라우저로 로그인해서 받은 세션을 그대로 넘겨줄 때 쓴다 — SSO나
        MFA가 걸린 실제 대상에서는 로그인 자동화가 아예 불가능하므로, 이 경로가
        자동 로그인보다 오히려 본체다.
        """
        # 호스트를 그대로 쓰면 안 된다. cookiejar는 점 없는 이름을 `localhost`가
        # 아니라 `localhost.local`로 취급해서, 도메인이 안 맞는 쿠키를 **조용히
        # 안 보낸다.** 그러면 세션이 멀쩡한데 verify가 401로 떨어진다.
        # 규칙을 베껴 쓰지 말고 stdlib가 쓰는 그 함수를 그대로 쓴다.
        _, domain = http.cookiejar.eff_request_host(urllib.request.Request(url))
        jar = self._jars.get(actor)
        if jar is None:
            self._opener(actor)          # 항아리와 opener를 함께 만든다
            jar = self._jars[actor]
        jar.set_cookie(http.cookiejar.Cookie(
            version=0, name=name, value=value, port=None, port_specified=False,
            domain=domain, domain_specified=True, domain_initial_dot=False,
            path="/", path_specified=True, secure=False, expires=None,
            discard=True, comment=None, comment_url=None, rest={}, rfc2109=False,
        ))

    @property
    def blocked(self) -> list[tuple[str, str]]:
        """안전장치가 거부한 요청들. 프롬프트 인젝션 흔적이 여기 남는다."""
        return list(self._blocked)

    # ----------------------------------------------------------------- request
    def request(
        self,
        method: str,
        url: str,
        *,
        actor: str = "anon",
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        note: str = "",
    ) -> HttpExchange:
        """요청 한 건. 항상 `HttpExchange`를 돌려준다 (예외 대신 status=None).

        Raises:
            TargetNotAuthorizedError: 대상이 허가 범위 밖 — 에이전트가 삼키지 말 것
            RequestBudgetExceeded: 예산 초과
        """
        exchange, _ = self._send(method, url, actor=actor, headers=headers,
                                 body=body, note=note)
        return exchange

    def fetch(self, url: str, **kw) -> tuple[HttpExchange, str]:
        """GET + **잘리지 않은 본문**. 링크·폼을 파싱하는 쪽이 쓴다.

        `HttpExchange.response_excerpt`는 증거용으로 `MAX_EXCERPT`에서 잘린다.
        그걸로 HTML을 파싱하면 **잘림 경계 뒤의 폼이 통째로 사라진다** — 조용히,
        아무 경고도 없이. 파싱은 이 메서드가 주는 본문으로 한다.
        """
        return self._send("GET", url, **kw)

    def _send(
        self,
        method: str,
        url: str,
        *,
        actor: str = "anon",
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        note: str = "",
    ) -> tuple[HttpExchange, str]:
        if self.request_count >= self.max_requests:
            raise RequestBudgetExceeded(
                f"요청 예산 {self.max_requests}건 초과. 루프가 폭주했는지 확인할 것."
            )

        # 이것이 요점: 스캔 시작 때 한 번이 아니라 **매 요청** 검사한다.
        try:
            authorize_target(url, self.allowlist)
        except TargetNotAuthorizedError as exc:
            self._blocked.append((url, str(exc)))
            raise

        # actor 기본 헤더가 먼저, 요청별 헤더가 나중 — 호출부가 항상 이긴다.
        req_headers = {**self._actor_headers.get(actor, {}), **(headers or {})}
        req_headers.setdefault("User-Agent", self.user_agent)
        req_headers.setdefault("Accept-Encoding", "gzip")

        data = body.encode() if isinstance(body, str) else body
        if data is not None:
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        req = urllib.request.Request(
            url, data=data, headers=req_headers, method=method.upper()
        )

        started = time.monotonic()
        status: int | None = None
        resp_headers: dict[str, str] = {}
        text = ""
        try:
            with self._opener(actor).open(req, timeout=self.timeout) as resp:
                status = resp.status
                resp_headers = dict(resp.headers.items())
                text = _decode(resp.read(MAX_BODY), resp_headers)
        except urllib.error.HTTPError as exc:
            # 4xx/5xx와, _NoRedirect 때문에 여기로 오는 3xx.
            status = exc.code
            resp_headers = dict(exc.headers.items()) if exc.headers else {}
            try:
                text = _decode(exc.read(MAX_BODY), resp_headers)
            except Exception:
                text = ""
        except (urllib.error.URLError, OSError, ValueError) as exc:
            text = f"[transport error] {exc}"
        finally:
            self.request_count += 1
            if self.delay:
                time.sleep(self.delay)

        exchange = HttpExchange(   # __post_init__이 마스킹·길이 제한을 강제한다
            method=method.upper(),
            url=url,
            status=status,
            actor=actor,
            request_headers=req_headers,
            request_body=body if isinstance(body, str) else None,
            response_headers=resp_headers,
            response_excerpt=text[:MAX_EXCERPT],
            note=note,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
        # 증거는 잘린 excerpt, 파싱은 전체 본문. 둘을 섞지 않는다.
        return exchange, text

    def get(self, url: str, **kw) -> HttpExchange:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> HttpExchange:
        return self.request("POST", url, **kw)

    def resolve(self, base: str, href: str) -> str | None:
        """페이지에서 뽑은 링크를 절대 URL로. **같은 origin이 아니면 None.**

        LLM이나 타겟 페이지가 준 링크를 그대로 따라가지 않기 위한 1차 거름망이다
        (2차는 request()의 authorize_target).
        """
        try:
            absolute = urljoin(base, href)
        except ValueError:
            return None
        b, a = urlparse(base), urlparse(absolute)
        if a.scheme not in ("http", "https"):
            return None
        if (a.hostname, a.port or _default_port(a.scheme)) != (
            b.hostname, b.port or _default_port(b.scheme)
        ):
            return None
        return absolute


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _decode(raw: bytes, headers: dict[str, str]) -> str:
    enc = {k.lower(): v for k, v in headers.items()}.get("content-encoding", "")
    if "gzip" in enc.lower():
        try:
            raw = gzip.decompress(raw)
        except (OSError, EOFError):
            pass
    return raw.decode("utf-8", errors="replace")


__all__ = ["AgentHttpClient", "RequestBudgetExceeded"]
