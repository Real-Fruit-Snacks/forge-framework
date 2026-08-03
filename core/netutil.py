"""Small network helpers shared by config and modules."""

import socket

# TEST-NET-1 (RFC 5737): routable in theory, never assigned — the UDP
# connect() sends no packets, it just makes the kernel pick a source.
_PROBE_HOST = "192.0.2.1"


def detect_local_ip(fallback="127.0.0.1"):
    """The IP this host would use to reach a target — without sending a
    single packet. UDP connect() only resolves the route, and
    getsockname() reports the source the kernel picked. fallback when
    there's no route at all (air-gapped, weird VPN)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((_PROBE_HOST, 80))
            return s.getsockname()[0]
    except OSError:
        return fallback


def psq(text):
    """PowerShell single-quote: literal except embedded quotes doubled."""
    return "'" + str(text).replace("'", "''") + "'"
