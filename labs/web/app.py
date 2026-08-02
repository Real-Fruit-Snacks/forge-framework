#!/usr/bin/env python3
"""Framework web lab: a deterministic target for dir-busting and brute-force
modules.

What it serves (all deliberate):
  GET  /                200  bland index
  GET  /admin /backup /secret /uploads /api /docs   200  hidden paths (dir busting)
  GET  /forbidden       403  tests status-code filtering
  GET  /protected       401  basic-auth realm "lab", creds admin:hunter2
  GET  /login           200  login form
  POST /login           200  "Welcome" (admin/hunter2) or "invalid username or password"
  everything else       404

Stdlib only, one file, no config. Predictability is the point: module tests
assert against exact behavior.
"""

import base64
import http.server
import urllib.parse

REALM = "lab"
AUTH_USER = "admin"
AUTH_PASS = "hunter2"
FORM_USER = "admin"
FORM_PASS = "hunter2"
PORT = 8080

PAGES = {
    "/": ("Home", "Nothing to see here. Or is there?"),
    "/admin": ("Admin Panel", "flag{d1r_bust1ng_w0rks}"),
    "/admin/panel": ("Admin Panel Home", "flag{d33p_d1r_bust}"),
    "/backup": ("Backups", "db_backup_2024.sql.zip"),
    "/backup/db": ("DB Backups", "db.sql"),
    "/secret": ("Secret", "you found me"),
    "/uploads": ("Uploads", "drop files here"),
    "/api": ("API", '{"status": "ok", "version": "1.0"}'),
    "/docs": ("Docs", "internal documentation"),
}

LOGIN_FORM = """<!doctype html><title>Login</title><h1>Login</h1>
<form method="post" action="/login">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <input type="submit" value="login">
</form>"""


class LabHandler(http.server.BaseHTTPRequestHandler):
    server_version = "FrameworkLab/1.0"

    def log_message(self, fmt, *args):  # keep container logs quiet
        pass

    # ------------------------------------------------------------- plumbing
    def _send(self, code, body, headers=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    @staticmethod
    def _page(title, body):
        return (
            f"<!doctype html><html><head><title>{title}</title></head>"
            f"<body><h1>{title}</h1><p>{body}</p></body></html>"
        )

    def _path(self):
        return urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"

    # --------------------------------------------------------------- routes
    def do_GET(self):
        path = self._path()
        if path == "/protected":
            if self._check_basic_auth():
                self._send(200, self._page("Protected", "flag{bas1c_auth_brut3d}"))
            else:
                self._send(401, "authentication required",
                           {"WWW-Authenticate": f'Basic realm="{REALM}"'})
            return
        if path == "/forbidden":
            self._send(403, self._page("Forbidden", "nice try"))
            return
        if path == "/login":
            self._send(200, LOGIN_FORM)
            return
        if path in PAGES:
            title, body = PAGES[path]
            self._send(200, self._page(title, body))
            return
        self._send(404, self._page("404", "not found"))

    def do_POST(self):
        if self._path() != "/login":
            self._send(404, self._page("404", "not found"))
            return
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        user = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        if user == FORM_USER and password == FORM_PASS:
            self._send(200, self._page("Welcome", "flag{f0rm_brut3_w0rks}"))
        else:
            self._send(200, self._page("Login failed", "invalid username or password"))

    def _check_basic_auth(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:]).decode()
        except Exception:
            return False
        return decoded == f"{AUTH_USER}:{AUTH_PASS}"


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("0.0.0.0", PORT), LabHandler).serve_forever()
