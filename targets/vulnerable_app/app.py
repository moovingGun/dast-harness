"""A deliberately vulnerable web app used as a *controlled* scan target.

Every weakness it serves is listed in ground_truth.json, which is what the
accuracy validation scores scanner findings against. Stdlib only, no state, no
real credentials — the "secrets" below are obvious fakes.

Run locally:   python3 targets/vulnerable_app/app.py
In Docker:     docker compose -f targets/compose.yml up -d   (127.0.0.1:8080)
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_HOST = "127.0.0.1"  # never 0.0.0.0 by default: this app is vulnerable
DEFAULT_PORT = 8080

HTML = "text/html; charset=utf-8"
TEXT = "text/plain; charset=utf-8"

INDEX = """<!DOCTYPE html>
<html><head><title>Acme Intranet</title></head><body>
<h1>Acme Intranet</h1>
<p>Deliberately vulnerable target for dast-harness. Do not deploy.</p>
<ul>
  <li><a href="/admin/">Admin</a></li>
  <li><a href="/uploads/">Uploads</a></li>
  <li><a href="/phpinfo.php">Server info</a></li>
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


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "AcmeHTTP/1.0"
    sys_version = ""

    def do_GET(self) -> None:
        self._respond(body=True)

    def do_HEAD(self) -> None:
        self._respond(body=False)

    def _respond(self, *, body: bool) -> None:
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        route = ROUTES.get(path)
        if route is None:
            payload = b"404 Not Found"
            self.send_response(404)
            self.send_header("Content-Type", TEXT)
        else:
            content_type, text = route
            payload = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
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
