"""Threaded TCP connect scanner."""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.module import AuxiliaryModule
from core.options import OptAddress, OptInt, OptString


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

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(self._probe, h, p, timeout): (h, p) for h, p in targets}
            for future in as_completed(futures):
                host, port = futures[future]
                if future.result():
                    open_ports[host].append(port)
                    self.print_good(f"{host}:{port} open")

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
                    store.add_service(host, port)
            self.print_status("Open ports saved to the workspace ('services')")

    @staticmethod
    def _probe(host, port, timeout):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False
