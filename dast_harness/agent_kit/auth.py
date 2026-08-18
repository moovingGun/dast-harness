"""인증 시나리오 — 에이전트가 로그인 뒤를 볼 수 있게 하는 부분.

실제로 값나가는 취약점(IDOR, 접근통제 우회, 권한 상승)은 거의 전부 로그인 뒤에
있다. 인증을 못 붙이면 에이전트는 비로그인으로 보이는 표면만 훑게 되고, 그건
스캐너가 이미 하는 일이다.

**로그인 절차를 코드에 박지 않는다.** 시나리오 파일을 읽어서 재생할 뿐이다.
실제 대상은 CSRF 토큰, `Authorization: Bearer`, OAuth 리다이렉트, MFA로 제각각이라
"POST /login에 username/password"를 코드로 정해두면 우리 연습 타겟에서만 돈다.

세션을 얻는 방법은 둘이다.

1. `login` — 요청 시퀀스를 재생한다. 폼 로그인처럼 자동화가 되는 경우.
2. `cookies` / `headers` — **이미 딴 세션을 그대로 받는다.** MFA·CAPTCHA·SSO가
   걸린 대상은 로그인 자동화가 원리적으로 불가능하다. 사람이 브라우저로 로그인한
   뒤 쿠키나 Bearer 토큰을 넘겨주는 이 경로가 실전에서는 오히려 본체다.

어느 쪽으로 얻었든 `verify`를 통과해야 한다. **`verify`는 선택이 아니다.**
세션이 만료됐거나 로그인이 조용히 실패하면 스캔 전체가 비로그인으로 돌면서
"IDOR 없음"을 보고한다 — 깨끗한 성적표로 보이는 완전한 미탐이다. 이 실패 모드를
막는 게 이 파일의 존재 이유이므로, verify 없는 actor는 로드 단계에서 거부한다.

    {
      "actors": {
        "alice": {
          "login": [{"method": "POST", "path": "/login",
                     "body": {"username": "alice", "password": "alice123"}}],
          "verify": {"path": "/api/orders/1001", "expect_status": 200}
        },
        "bob": {
          "cookies": {"session": "bob-session"},
          "verify": {"path": "/api/orders/1002", "expect_status": 200}
        }
      }
    }

로그인 교환은 **증거에 남기지 않는다.** 평문 비밀번호가 실려 있어서, 리포트를
공유하는 순간 자격증명이 같이 나간다. 남는 것은 "alice 인증됨"이라는 사실뿐이다.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlencode, urljoin

from .http import AgentHttpClient

# 시나리오가 지정할 수 있는 메서드. 로그인에 DELETE를 쓰는 대상은 없고, 오타로
# 파괴적인 요청을 재생하는 사고를 막는다.
LOGIN_METHODS = ("GET", "POST", "PUT", "PATCH")


class AuthConfigError(Exception):
    """시나리오 파일이 잘못됐다. 스캔을 시작하기 전에 터진다."""


@dataclass(frozen=True)
class Step:
    """로그인 시퀀스의 요청 한 건."""

    method: str
    path: str
    body: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Verify:
    """세션이 실제로 살아있는지 보는 관문. actor마다 필수다."""

    path: str
    expect_status: int = 200
    body_contains: str = ""

    def check(self, status: int | None, body: str) -> str:
        """통과면 빈 문자열, 실패면 사람이 읽을 이유."""
        if status != self.expect_status:
            return f"{self.path} 응답이 {status} (기대 {self.expect_status})"
        if self.body_contains and self.body_contains not in body:
            return f"{self.path} 본문에 {self.body_contains!r}가 없음"
        return ""


@dataclass(frozen=True)
class Actor:
    """한 신원. 세션을 얻는 방법과, 얻었는지 확인하는 방법."""

    name: str
    verify: Verify
    login: tuple[Step, ...] = ()
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AuthResult:
    """actor 하나의 인증 결과. 실패해도 조용히 넘어가지 않게 이유를 남긴다."""

    actor: str
    ok: bool
    reason: str = ""
    requests_made: int = 0

    def to_dict(self) -> dict:
        return {"actor": self.actor, "ok": self.ok, "reason": self.reason,
                "requests_made": self.requests_made}


# ------------------------------------------------------------------- 파일 읽기
def load_actors(path: str) -> dict[str, Actor]:
    """시나리오 파일을 읽어 검사한다. 잘못됐으면 `AuthConfigError`.

    스캔이 시작된 뒤에 터지면 절반쯤 돌아간 결과를 남기므로 여기서 다 본다.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except OSError as exc:
        raise AuthConfigError(f"인증 시나리오를 읽을 수 없다: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise AuthConfigError(f"인증 시나리오가 올바른 JSON이 아니다: {exc}") from exc
    return parse_actors(raw)


def parse_actors(raw: dict) -> dict[str, Actor]:
    if not isinstance(raw, dict) or not isinstance(raw.get("actors"), dict):
        raise AuthConfigError("최상위에 'actors' 객체가 있어야 한다")
    actors_raw = raw["actors"]
    if not actors_raw:
        raise AuthConfigError("'actors'가 비어 있다")

    actors: dict[str, Actor] = {}
    for name, spec in actors_raw.items():
        if name == "anon":
            # 비로그인 대조군은 클라이언트의 기본 actor다. 여기에 세션을 붙이면
            # "로그인 안 한 상태"라는 대조 자체가 사라진다.
            raise AuthConfigError("'anon'은 비로그인 대조군 이름이라 정의할 수 없다")
        actors[name] = _parse_actor(name, spec)
    return actors


def _parse_actor(name: str, spec) -> Actor:
    where = f"actors.{name}"
    if not isinstance(spec, dict):
        raise AuthConfigError(f"{where}: 객체여야 한다")

    verify_raw = spec.get("verify")
    if not isinstance(verify_raw, dict):
        raise AuthConfigError(
            f"{where}: 'verify'가 필수다. 세션이 죽은 걸 모르고 스캔하면 전체가 "
            f"비로그인으로 돌면서 '취약점 없음'을 보고한다"
        )
    verify = _parse_verify(where, verify_raw)

    login = tuple(
        _parse_step(f"{where}.login[{i}]", s)
        for i, s in enumerate(spec.get("login") or ())
    )
    cookies = _str_map(f"{where}.cookies", spec.get("cookies"))
    headers = _str_map(f"{where}.headers", spec.get("headers"))
    if not login and not cookies and not headers:
        raise AuthConfigError(
            f"{where}: 세션을 얻을 방법이 없다 — 'login', 'cookies', 'headers' 중 "
            f"하나는 있어야 한다"
        )
    return Actor(name=name, verify=verify, login=login, cookies=cookies,
                 headers=headers)


def _parse_verify(where: str, raw: dict) -> Verify:
    path = raw.get("path")
    if not isinstance(path, str) or not path:
        raise AuthConfigError(f"{where}.verify: 'path'가 필요하다")
    status = raw.get("expect_status", 200)
    if not isinstance(status, int) or isinstance(status, bool):
        raise AuthConfigError(f"{where}.verify: 'expect_status'는 정수여야 한다")
    contains = raw.get("body_contains", "")
    if not isinstance(contains, str):
        raise AuthConfigError(f"{where}.verify: 'body_contains'는 문자열이어야 한다")
    return Verify(path=path, expect_status=status, body_contains=contains)


def _parse_step(where: str, raw) -> Step:
    if not isinstance(raw, dict):
        raise AuthConfigError(f"{where}: 객체여야 한다")
    method = str(raw.get("method", "POST")).upper()
    if method not in LOGIN_METHODS:
        raise AuthConfigError(
            f"{where}: method {method!r}는 허용되지 않는다 "
            f"(허용: {', '.join(LOGIN_METHODS)})"
        )
    path = raw.get("path")
    if not isinstance(path, str) or not path:
        raise AuthConfigError(f"{where}: 'path'가 필요하다")
    return Step(
        method=method, path=path,
        body=_str_map(f"{where}.body", raw.get("body")),
        headers=_str_map(f"{where}.headers", raw.get("headers")),
    )


def _str_map(where: str, raw) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise AuthConfigError(f"{where}: 문자열 객체여야 한다")
    out = {}
    for k, v in raw.items():
        if not isinstance(v, (str, int, float)) or isinstance(v, bool):
            raise AuthConfigError(f"{where}.{k}: 문자열이어야 한다")
        out[str(k)] = str(v)
    return out


# ------------------------------------------------------------------- 세션 수립
def establish(
    client: AgentHttpClient, actors: dict[str, Actor], base: str
) -> dict[str, AuthResult]:
    """actor마다 세션을 만들고 verify를 통과시킨다.

    통과한 actor만 `client.actors`에 올라간다. 실패는 예외로 올리지 않고
    `AuthResult`로 돌려준다 — 어느 신원이 왜 실패했는지 리포트에 남아야 하고,
    그 판단(계속 돌지 말지)은 부르는 쪽 몫이다.
    """
    results: dict[str, AuthResult] = {}
    for name, actor in actors.items():
        before = client.request_count
        try:
            reason = _establish_one(client, actor, base)
        except Exception as exc:  # noqa: BLE001 - 한 신원의 실패가 나머지를 막지 않는다
            reason = f"인증 중 오류: {exc}"
        spent = client.request_count - before
        if not reason:
            client.mark_authenticated(name)
        results[name] = AuthResult(actor=name, ok=not reason, reason=reason,
                                   requests_made=spent)
    return results


def _establish_one(client: AgentHttpClient, actor: Actor, base: str) -> str:
    """성공이면 빈 문자열, 실패면 사람이 읽을 이유."""
    if actor.headers:
        client.set_actor_headers(actor.name, actor.headers)
    for cookie_name, value in actor.cookies.items():
        client.set_cookie(actor.name, cookie_name, value, base)

    for i, step in enumerate(actor.login):
        body = urlencode(step.body) if step.body else None
        exchange = client.request(
            step.method, urljoin(base, step.path), actor=actor.name,
            headers=step.headers or None, body=body,
            # 이 교환은 증거로 나가지 않는다 — 평문 비밀번호가 들어 있다.
            note="인증: 로그인 시퀀스 (증거에서 제외)",
        )
        if exchange.status is None or exchange.status >= 400:
            return f"login[{i}] {step.method} {step.path} 응답 {exchange.status}"

    # fetch는 잘리지 않은 본문을 준다. body_contains를 excerpt로 보면 경계 뒤의
    # 문자열을 못 찾아 멀쩡한 세션을 죽었다고 판정한다.
    exchange, body = client.fetch(
        urljoin(base, actor.verify.path), actor=actor.name,
        note="인증: 세션 확인",
    )
    return actor.verify.check(exchange.status, body)


__all__ = [
    "Actor",
    "AuthConfigError",
    "AuthResult",
    "Step",
    "Verify",
    "establish",
    "load_actors",
    "parse_actors",
]
