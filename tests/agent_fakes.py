"""Test doubles for agent tests. **Copy FakeClient when you test your agent.**

An agent talks to the target only through `AgentHttpClient`, so a fake client is
all you need to test one — no server, no sockets, no Docker. That keeps agent
tests as fast and portable as the rest of the suite.
"""

from dast_harness.agent_kit import HttpExchange

ORIGIN = "http://t.invalid"


class FakeClient:
    """A stand-in for `AgentHttpClient`. Serves canned pages from a dict.

    Implements only what an agent is allowed to touch: `get`/`post`/`fetch`/
    `resolve`/`request_count`/`blocked`/`actors`. If your agent needs something else from the real
    client, that is a hint the agent is reaching too far.

        client = FakeClient({f"{ORIGIN}/search": (200, "text/html", "<h1>0</h1>")})
        result = MyAgent(client).run(ORIGIN)

    신원이 필요한 에이전트(IDOR 등)는 `actors=`로 준다:

        client = FakeClient(pages, actors=("alice", "bob"))
    """

    def __init__(self, pages=None, *, post_pages=None, actors=()):
        # url -> (status, content_type, body)
        self.pages = dict(pages or {})
        self.post_pages = dict(post_pages or {})
        self.request_count = 0
        self.blocked = []
        self.sent = []                     # (method, url, actor, body) 순서 기록
        # 세션이 확인된 신원. 실제로는 `auth.establish()`가 채운다. 비워두면
        # 에이전트는 "인증 없음"으로 보고 건너뛰어야 한다 — 그 동작도 테스트 대상이다.
        self.actors = list(actors)

    def _exchange(self, method, url, table, kw):
        self.request_count += 1
        self.sent.append((method, url, kw.get("actor", "anon"), kw.get("body")))
        status, content_type, body = table.get(url, (404, "text/plain", ""))
        return HttpExchange(
            method=method, url=url, status=status,
            actor=kw.get("actor", "anon"),
            request_body=kw.get("body"),
            response_headers={"Content-Type": content_type},
            response_excerpt=body, note=kw.get("note", ""),
        )

    def get(self, url, **kw):
        return self._exchange("GET", url, self.pages, kw)

    def post(self, url, **kw):
        return self._exchange("POST", url, self.post_pages, kw)

    def fetch(self, url, **kw):
        """GET + 잘리지 않은 본문. 실제 클라이언트와 같은 (exchange, body) 쌍."""
        exchange = self._exchange("GET", url, self.pages, kw)
        _, _, body = self.pages.get(url, (404, "text/plain", ""))
        return exchange, body

    def resolve(self, base, href):
        """Same contract as the real client: cross-origin returns None."""
        if href.startswith("http"):
            return href if href.startswith(ORIGIN) else None
        return ORIGIN + (href if href.startswith("/") else "/" + href)
