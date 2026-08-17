"""A deliberately vulnerable web app used as a *controlled* scan target.

Every weakness it serves is listed in ground_truth.json, which is what the
accuracy validation scores scanner findings against. Stdlib only, no state, no
real credentials — the "secrets" below are obvious fakes.

Run locally:   python3 targets/vulnerable_app/app.py
In Docker:     docker compose -f targets/compose.yml up -d   (127.0.0.1:8080)
"""

from __future__ import annotations

import argparse
import html
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_HOST = "127.0.0.1"  # never 0.0.0.0 by default: this app is vulnerable
DEFAULT_PORT = 8080

HTML = "text/html; charset=utf-8"
TEXT = "text/plain; charset=utf-8"
JSON = "application/json"

INDEX = """<!DOCTYPE html>
<html><head><title>Acme Intranet</title></head><body>
<h1>Acme Intranet</h1>
<p>Deliberately vulnerable target for dast-harness. Do not deploy.</p>
<ul>
  <li><a href="/admin/">Admin</a></li>
  <li><a href="/uploads/">Uploads</a></li>
  <li><a href="/phpinfo.php">Server info</a></li>
  <li><a href="/login">Sign in</a></li>
  <li><a href="/search?q=invoice">Invoice search</a></li>
  <li><a href="/lookup?q=alice">Directory lookup</a></li>
</ul>
</body></html>
"""

DOTENV = """APP_NAME=acme-intranet
APP_ENV=production
APP_KEY=base64:FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE=
APP_DEBUG=true
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_DATABASE=acme
DB_USERNAME=acme_app
DB_PASSWORD=not-a-real-password
AWS_ACCESS_KEY_ID=AKIAFAKEFAKEFAKEFAKE
AWS_SECRET_ACCESS_KEY=fake/secret/key/for/scan/target/only
"""

GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://github.com/example/acme-intranet.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""

BACKUP_SQL = """-- MySQL dump 10.13  Distrib 8.0.32
-- Host: 127.0.0.1    Database: acme
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
);
INSERT INTO `users` VALUES (1,'admin@example.com','$2y$10$fakehashfakehashfake');
"""

PHPINFO = """<!DOCTYPE html>
<html><head><title>phpinfo()</title></head><body>
<h1 class="p">PHP Version 7.4.3</h1>
<table>
<tr><td class="e">System</td><td class="v">Linux acme 5.15.0 x86_64</td></tr>
<tr><td class="e">Server API</td><td class="v">FPM/FastCGI</td></tr>
<tr><td class="e">Loaded Configuration File</td><td class="v">/etc/php/7.4/fpm/php.ini</td></tr>
<tr><td class="e">disable_functions</td><td class="v">no value</td></tr>
<tr><td class="e">allow_url_fopen</td><td class="v">On</td></tr>
</table>
<h2>PHP Credits</h2>
</body></html>
"""

UPLOADS_INDEX = """<!DOCTYPE html>
<html><head><title>Index of /uploads</title></head><body>
<h1>Index of /uploads</h1>
<pre>
<a href="../">../</a>
<a href="invoice-2024-01.pdf">invoice-2024-01.pdf</a>   2024-01-31 11:04   84K
<a href="employees.csv">employees.csv</a>               2024-02-02 09:12   12K
<a href="db-backup.tar.gz">db-backup.tar.gz</a>         2024-02-02 09:15  3.2M
</pre>
</body></html>
"""

ADMIN = """<!DOCTYPE html>
<html><head><title>Admin Login</title></head><body>
<h1>Administrator Login</h1>
<form method="post" action="/admin/">
  <input type="text" name="username" value="admin">
  <input type="password" name="password">
  <input type="submit" value="Sign in">
</form>
<p>Default credentials: admin / admin</p>
</body></html>
"""

ROBOTS = """User-agent: *
Disallow: /admin/
Disallow: /uploads/
Disallow: /backup.sql
"""

LOGIN_FORM = """<!DOCTYPE html>
<html><head><title>Sign in</title></head><body>
<h1>Sign in</h1>
<form method="post" action="/login">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" value="Sign in">
</form>
<p>Your last order: <a href="/api/orders/1001">#1001</a></p>
</body></html>
"""

LOGIN_OK = """<!DOCTYPE html>
<html><head><title>Signed in</title></head><body>
<h1>Signed in as {user}</h1>
<p>Your last order: <a href="/api/orders/1001">#1001</a></p>
</body></html>
"""

SEARCH_PAGE = """<!DOCTYPE html>
<html><head><title>Invoice search</title></head><body>
<h1>{count} results for {term}</h1>
<ul>{items}</ul>
</body></html>
"""

LOOKUP_PAGE = """<!DOCTYPE html>
<html><head><title>Directory lookup</title></head><body>
<h1>{count} people matching {term}</h1>
<ul>{items}</ul>
</body></html>
"""

# Obvious fakes, and the only accounts. Distinct login failure messages below
# are what makes the account list enumerable.
USERS = {"alice": "alice123", "bob": "bob123", "admin": "admin"}

# session token -> username. In memory only: the container runs read-only.
SESSIONS = {
    "alice-session": "alice",
    "bob-session": "bob",
    "admin-session": "admin",
}

ORDERS = {
    1001: {"id": 1001, "owner": "alice@example.com", "item": "Standing desk",
           "total": 42000},
    1002: {"id": 1002, "owner": "bob@example.com", "item": "Laptop dock",
           "total": 128000},
    1003: {"id": 1003, "owner": "alice@example.com", "item": "Monitor arm",
           "total": 39000},
}

INVOICES = ["invoice-2024-01", "invoice-2024-02", "invoice-2024-03",
            "payroll-2024-q1"]

DIRECTORY = ["alice.kim", "bob.lee", "admin.ops", "carol.park"]

SQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    'to your MySQL server version for the right syntax to use near "{fragment}" '
    "at line 1"
)

# path -> (content type, body). No security headers are ever added; that
# omission is itself one of the documented weaknesses.
ROUTES = {
    "/": (HTML, INDEX),
    "/index.html": (HTML, INDEX),
    "/.env": (TEXT, DOTENV),
    "/.git/config": (TEXT, GIT_CONFIG),
    "/backup.sql": (TEXT, BACKUP_SQL),
    "/phpinfo.php": (HTML, PHPINFO),
    "/uploads/": (HTML, UPLOADS_INDEX),
    "/admin/": (HTML, ADMIN),
    "/robots.txt": (TEXT, ROBOTS),
}


def _items(names: list[str]) -> str:
    return "".join(f"<li>{html.escape(n)}</li>" for n in names)


def _session_user(cookie_header: str) -> str | None:
    for part in cookie_header.split(";"):
        name, _, value = part.strip().partition("=")
        if name == "session":
            return SESSIONS.get(value)
    return None


def _login(form: dict[str, list[str]]) -> tuple[int, str, str, str | None]:
    """The two failure messages differ by cause, which is what makes the
    account list enumerable. A single generic message would not be a weakness."""
    username = (form.get("username") or [""])[0]
    password = (form.get("password") or [""])[0]
    if username not in USERS:
        return 401, TEXT, "존재하지 않는 사용자입니다", None
    if USERS[username] != password:
        return 401, TEXT, "비밀번호가 올바르지 않습니다", None
    return (200, HTML, LOGIN_OK.format(user=html.escape(username)),
            f"session={username}-session; Path=/")


def _order(path: str, cookie_header: str) -> tuple[int, str, str, None]:
    """Authenticated but not authorized: the session is checked, the owner is
    not, so any signed-in caller reads any order. That gap is the IDOR."""
    if _session_user(cookie_header) is None:
        return 401, JSON, json.dumps({"error": "authentication required"}), None
    raw = path[len("/api/orders/"):].strip("/")
    if not raw.isdigit() or int(raw) not in ORDERS:
        return 404, JSON, json.dumps({"error": "no such order"}), None
    return 200, JSON, json.dumps(ORDERS[int(raw)]), None


def _search(q: str) -> tuple[int, str, str, None]:
    """q is concatenated into SQL, so an unbalanced quote breaks the statement
    and a -- comment repairs it. There is no database; this is simulated."""
    if "--" not in q and q.count("'") % 2:
        return 500, TEXT, SQL_ERROR.format(fragment=f"'%{q}%'"), None
    term = q.split("'")[0].strip()
    hits = [t for t in INVOICES if term.lower() in t.lower()] if term else INVOICES
    return 200, HTML, SEARCH_PAGE.format(
        count=len(hits), term=html.escape(term), items=_items(hits)), None


def _lookup(q: str) -> tuple[int, str, str, None]:
    """Negative control: NOT injectable. It 500s on absurd input like any
    brittle handler, but never echoes a SQL error, so an injection finding
    here is a false positive. Quotes are handled correctly on purpose."""
    if len(q) > 100:
        return 500, TEXT, "Internal Server Error: lookup failed", None
    hits = [n for n in DIRECTORY if q.lower() in n.lower()] if q else DIRECTORY
    return 200, HTML, LOOKUP_PAGE.format(
        count=len(hits), term=html.escape(q), items=_items(hits)), None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "AcmeHTTP/1.0"
    sys_version = ""

    def do_GET(self) -> None:
        self._respond(body=True)

    def do_HEAD(self) -> None:
        self._respond(body=False)

    def do_POST(self) -> None:
        self._respond(body=True)

    def _form(self) -> dict[str, list[str]]:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        return urllib.parse.parse_qs(raw)

    def _dispatch(self, path: str, query: str) -> tuple[int, str, str, str | None]:
        q = (urllib.parse.parse_qs(query).get("q") or [""])[0]
        if path == "/login":
            if self.command == "POST":
                return _login(self._form())
            return 200, HTML, LOGIN_FORM, None
        if self.command == "POST":
            return 405, TEXT, "405 Method Not Allowed", None
        if path.startswith("/api/orders/"):
            return _order(path, self.headers.get("Cookie") or "")
        if path == "/search":
            return _search(q)
        if path == "/lookup":
            return _lookup(q)
        route = ROUTES.get(path)
        if route is None:
            return 404, TEXT, "404 Not Found", None
        content_type, text = route
        return 200, content_type, text, None

    def _respond(self, *, body: bool) -> None:
        path, _, query = self.path.partition("?")
        path = path.split("#", 1)[0]
        status, content_type, text, set_cookie = self._dispatch(path, query)
        payload = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if body:
            self.wfile.write(payload)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Deliberately vulnerable scan target.")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args(argv)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"vulnerable target on http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
