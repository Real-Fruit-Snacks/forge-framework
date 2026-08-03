"""DNS recon: wire-format queries with zero dependencies (stdlib socket).

DNS is the highest-value low-noise AD recon channel: SRV records name
the domain controllers, global catalogs, and kpasswd servers without
touching SMB or LDAP. This module speaks raw DNS over UDP — query
builder, response parser with compression-pointer following and loop
detection — so there's no dnspython dependency anywhere.

Plain mode answers one query (TARGET + TYPE). ADDISCOVER fires the
standard AD SRV set against TARGET (the domain): _ldap._tcp.dc._msdcs
(the DCs), _kerberos._tcp, _gc._tcp (global catalogs), _kpasswd._tcp.

The wire core is adapted from Mainsail's dig applet (same author,
stdlib-only), with SRV support added. Parser handles compression
pointers with a loop guard; malformed packets are refused, never
crashed.
"""

import random
import socket
import struct

from core.module import AuxiliaryModule
from core.options import OptAddress, OptBool, OptEnum, OptInt, OptString

TYPE_NUM = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
    "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255,
}
NUM_TYPE = {v: k for k, v in TYPE_NUM.items()}

RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
               4: "NOTIMP", 5: "REFUSED"}

AD_SRV_SET = (
    "_ldap._tcp.dc._msdcs",
    "_kerberos._tcp",
    "_gc._tcp",
    "_kpasswd._tcp",
)


def encode_name(name):
    """forge.local -> b'\\x05forge\\x05local\\x00' (IDNA-aware)."""
    out = bytearray()
    for label in name.strip(".").split("."):
        b = label.encode("idna" if any(ord(c) > 127 for c in label) else "ascii")
        if len(b) > 63:
            raise ValueError(f"label too long: {label!r}")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def build_query(qid, name, qtype):
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1
    return header + encode_name(name) + struct.pack("!HH", qtype, 1)


def read_name(data, offset):
    """(name, next_offset) — follows compression pointers, guards loops."""
    labels = []
    seen = set()
    pos = offset
    end = None
    while True:
        if pos in seen:
            raise ValueError("compression loop")
        seen.add(pos)
        ln = data[pos]
        if ln == 0:
            pos += 1
            if end is None:
                end = pos
            return ".".join(labels), end
        if ln & 0xC0:
            ptr = ((ln & 0x3F) << 8) | data[pos + 1]
            if end is None:
                end = pos + 2
            pos = ptr
            continue
        labels.append(data[pos + 1:pos + 1 + ln].decode("ascii", "replace"))
        pos += 1 + ln


def _format_rdata(rtype, rdata, full, offset):
    if rtype == 1 and len(rdata) == 4:  # A
        return ".".join(str(b) for b in rdata)
    if rtype == 28 and len(rdata) == 16:  # AAAA
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype in (2, 5, 12):  # NS, CNAME, PTR
        name, _ = read_name(full, offset)
        return name + "."
    if rtype == 15:  # MX
        if len(rdata) < 3:
            return rdata.hex()
        pref = struct.unpack("!H", rdata[:2])[0]
        exch, _ = read_name(full, offset + 2)
        return f"{pref} {exch}."
    if rtype == 16:  # TXT
        out = []
        i = 0
        while i < len(rdata):
            ln = rdata[i]
            i += 1
            out.append(rdata[i:i + ln].decode("utf-8", "replace"))
            i += ln
        return '"' + '" "'.join(out) + '"'
    if rtype == 33:  # SRV
        if len(rdata) < 7:
            return rdata.hex()
        prio, weight, port = struct.unpack("!HHH", rdata[:6])
        target, _ = read_name(full, offset + 6)
        return f"{prio} {weight} {port} {target}."
    if rtype == 6:  # SOA
        mname, p2 = read_name(full, offset)
        rname, p3 = read_name(full, p2)
        if len(full) >= p3 + 20:
            serial, refresh, retry, expire, minimum = struct.unpack(
                "!IIIII", full[p3:p3 + 20])
            return f"{mname}. {rname}. {serial} {refresh} {retry} {expire} {minimum}"
        return f"{mname}. {rname}."
    return rdata.hex()


def parse_response(data):
    """(rcode, [(name, type, ttl, value)]) — raises on malformed packets."""
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x000F
    pos = 12
    for _ in range(qd):
        _, pos = read_name(data, pos)
        pos += 4
    answers = []
    for _ in range(an):
        name, pos = read_name(data, pos)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        value = _format_rdata(rtype, data[pos:pos + rdlen], data, pos)
        pos += rdlen
        answers.append((name, NUM_TYPE.get(rtype, str(rtype)), ttl, value))
    return rcode, answers


def query(server, port, name, qtype, timeout=5.0):
    """One UDP query -> (rcode, answers). Raises OSError on transport."""
    qid = random.randint(0, 0xFFFF)
    packet = build_query(qid, name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(4096)
    return parse_response(data)


class DnsRecon(AuxiliaryModule):
    name = "DNS Recon (stdlib wire DNS)"
    description = """
        Raw DNS queries, no dependencies: TARGET + TYPE for plain
        lookups, ADDISCOVER for the AD SRV set (_ldap._tcp.dc._msdcs =
        the domain controllers, _kerberos, _gc, _kpasswd). Against an AD
        DC this is DC discovery with one packet and zero failed logons.
        Answers land in loot; A records also feed the hosts table.
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Nameserver(s), comma-separated"))
        self.options.add(OptInt("RPORT", default=53, description="DNS port"))
        self.options.add(OptString("TARGET", required=True,
                                   description="Name to query (the domain for "
                                               "ADDISCOVER)"))
        self.options.add(OptEnum("TYPE", list(TYPE_NUM), default="A",
                                 description="Record type (plain mode)"))
        self.options.add(OptBool("ADDISCOVER", default=False,
                                 description="Query the AD SRV set against TARGET"))
        self.options.add(OptInt("TIMEOUT", default=5,
                                description="Per-query timeout (seconds)"))

    def run(self):
        target = str(self.get_option("TARGET"))
        port = int(self.get_option("RPORT"))
        timeout = int(self.get_option("TIMEOUT"))
        discover = bool(self.get_option("ADDISCOVER"))
        qtype = TYPE_NUM[str(self.get_option("TYPE"))]
        for server in [s.strip() for s in str(self.get_option("RHOSTS")).split(",")
                       if s.strip()]:
            if discover:
                for prefix in AD_SRV_SET:
                    self._ask(server, port, f"{prefix}.{target}",
                              TYPE_NUM["SRV"], timeout)
            else:
                self._ask(server, port, target, qtype, timeout)

    def _ask(self, server, port, name, qtype, timeout):
        store = getattr(self.framework, "store", None)
        try:
            rcode, answers = query(server, port, name, qtype, timeout)
        except socket.timeout:
            self.print_error(f"{server}: no answer within {timeout}s")
            return
        except (OSError, ValueError, struct.error) as e:
            self.print_error(f"{server}: {e}")
            return
        status = RCODE_NAMES.get(rcode, str(rcode))
        if not answers:
            self.print_line(f"[-] {server}: {name} {NUM_TYPE.get(qtype)}: "
                            f"{status}, no answers")
            return
        lines = []
        for rname, rtype, ttl, value in answers:
            line = f"{rname}. {ttl} {rtype} {value}"
            lines.append(line)
            self.print_good(f"{server}: {line}")
            if store is not None and rtype == "A":
                store.add_host(value)
        if store is not None:
            store.add_loot("dns", f"{name} @ {server}",
                           "\n".join(lines), address=server)
