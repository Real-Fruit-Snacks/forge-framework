"""Grab HTTP response headers and page title."""

import http.client
import re

from core.module import AuxiliaryModule
from core.options import OptAddress, OptBool, OptInt, OptPort, OptString


class HttpHeaders(AuxiliaryModule):
    name = "HTTP Headers & Title Grabber"
    description = """
        Requests a path from a web server and reports the status code,
        Server header, and page title. Useful for quick web enumeration --
        fingerprinting what software a box is running before picking an
        exploit.
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target host(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=80, description="Target port"))
        self.options.add(OptBool("SSL", default=False, description="Use HTTPS"))
        self.options.add(OptString("PATH", default="/", description="Request path"))
        self.options.add(OptInt("TIMEOUT", default=5, description="Timeout (seconds)"))

    def run(self):
        hosts = [h.strip() for h in str(self.get_option("RHOSTS")).split(",") if h.strip()]
        rport = self.get_option("RPORT")
        use_ssl = self.get_option("SSL")
        path = self.get_option("PATH")
        timeout = self.get_option("TIMEOUT")

        for host in hosts:
            self._fetch(host, rport, use_ssl, path, timeout)

    def _fetch(self, host, port, use_ssl, path, timeout):
        conn_cls = http.client.HTTPSConnection if use_ssl else http.client.HTTPConnection
        conn = None
        try:
            conn = conn_cls(host, port, timeout=timeout)
            conn.request("GET", path, headers={"User-Agent": "framework/0.1"})
            resp = conn.getresponse()
            body = resp.read(65536).decode(errors="replace")
            scheme = "https" if use_ssl else "http"
            self.print_good(f"{scheme}://{host}:{port}{path} -> {resp.status} {resp.reason}")
            server = resp.getheader("Server")
            if server:
                self.print_status(f"  Server: {server}")
            title = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            if title:
                self.print_status(f"  Title: {title.group(1).strip()}")
            store = getattr(self.framework, "store", None)
            if store is not None:
                store.add_service(host, port, name=scheme, info=server or "")
        except (OSError, http.client.HTTPException) as e:
            self.print_error(f"{host}:{port} - {e}")
        finally:
            if conn is not None:
                conn.close()
