"""Threaded TCP connect scanner, with banner grabbing.

Open ports are half the story — vuln_search needs VERSIONS. After a port
answers, the scanner reads a protocol-appropriate banner where one
exists (SSH/SMTP/FTP greetings, HTTP Server header) and stores it in
services.info. Generic ports get a best-effort printable sniff.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.module import AuxiliaryModule
from core.options import OptAddress, OptInt, OptString

# read a greeting line from these (they speak first)
GREETING_PORTS = {21: "ftp", 22: "ssh", 25: "smtp", 110: "pop3",
                  143: "imap", 3306: "mysql", 5432: "postgres"}


def clean_banner(data):
    """Banner bytes -> printable single line, or ''. Lines with stray
    non-ASCII bytes are kept if they're >=80% printable after cleaning."""
    text = data.decode("utf-8", "replace").splitlines()
    for line in text:
        cleaned = "".join(c for c in line if c == "\t" or 32 <= ord(c) <= 126)
        cleaned = cleaned.strip()
        if cleaned and len(cleaned) >= 0.8 * len(line.strip()):
            return cleaned[:120]
    return ""


def grab_banner(host, port, timeout):
    """(name, info) for an open port — best effort, never raises.

    Order: listen for a greeting first (SSH/FTP/SMTP speak first), then
    send an HTTP probe on timeout (any port can be a web server; a fixed
    port list always misses one)."""
    name = GREETING_PORTS.get(port, "")
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(max(timeout / 2, 0.5))
            try:
                data = s.recv(256)
                if data:
                    return name, clean_banner(data)
            except OSError:
                pass  # no greeting — try HTTP instead
            try:
                s.settimeout(timeout)
                s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
                data = s.recv(4096)
                head = data.split(b"\r\n\r\n", 1)[0].decode("utf-8", "replace")
                if head.startswith("HTTP/"):
                    for line in head.splitlines():
                        if line.lower().startswith("server:"):
                            return "http", line.split(":", 1)[1].strip()[:120]
                    return "http", ""
                return name, clean_banner(data)
            except OSError:
                return name, ""
    except OSError:
        return name, ""


def parse_ports(spec):
    """Parse '22,80,8000-8100' into a sorted list of ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, _, end_s = part.partition("-")
            start, end = int(start_s), int(end_s)
            if start > end:
                raise ValueError(f"invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    for p in ports:
        if not 1 <= p <= 65535:
            raise ValueError(f"port out of range: {p}")
    return sorted(ports)


class PortScan(AuxiliaryModule):
    name = "TCP Connect Port Scanner"
    description = """
        Performs a full TCP connect() scan against one or more hosts.
        Reliable and needs no raw sockets, but noisy by nature -- expect it
        to show up in logs. Good first step when enumerating a box.
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target host(s), comma-separated"))
        self.options.add(OptString("PORTS", default="1-1024",
                                   description="Ports: '22,80,8000-8100'"))
        self.options.add(OptInt("THREADS", default=32, description="Concurrent workers"))
        self.options.add(OptInt("TIMEOUT", default=1, description="Connect timeout (seconds)"))

    def run(self):
        hosts = [h.strip() for h in str(self.get_option("RHOSTS")).split(",") if h.strip()]
        try:
            ports = parse_ports(str(self.get_option("PORTS")))
        except ValueError as e:
            self.print_error(f"Bad PORTS value: {e}")
            return
        threads = self.get_option("THREADS")
        timeout = self.get_option("TIMEOUT")

        self.print_status(f"Scanning {len(hosts)} host(s), {len(ports)} port(s) each")
        targets = [(h, p) for h in hosts for p in ports]
        open_ports = {h: [] for h in hosts}
        banners = {}

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(self._probe, h, p, timeout): (h, p) for h, p in targets}
            for future in as_completed(futures):
                host, port = futures[future]
                if future.result():
                    open_ports[host].append(port)
                    banners[(host, port)] = grab_banner(host, port, timeout + 2)
                    name, info = banners[(host, port)]
                    line = f"{host}:{port} open"
                    if name:
                        line += f" {name}"
                    if info:
                        line += f" {info}"
                    self.print_good(line)

        for host in hosts:
            found = sorted(open_ports[host])
            if found:
                self.print_status(
                    f"{host}: {len(found)} open port(s): "
                    + ", ".join(map(str, found))
                )
            else:
                self.print_status(f"{host}: no open ports found")

        store = getattr(self.framework, "store", None)
        if store is not None:
            for host in hosts:
                for port in open_ports[host]:
                    name, info = banners.get((host, port), ("", ""))
                    store.add_service(host, port, name=name, info=info)
            self.print_status("Open ports saved to the workspace ('services')")

    @staticmethod
    def _probe(host, port, timeout):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False
