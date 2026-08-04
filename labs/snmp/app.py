#!/usr/bin/env python3
"""SNMP lab agent: a deterministic UDP/161 responder for spray tests.

Behavior is the entire point: it answers ONLY when the community is
"private-lab" (a correct v2c community gets sysDescr; everything else
gets silence — exactly how real SNMP treats a wrong community, and why
sprays must read silence as "possible", not "no service").

Serves a small fixed OID set so future enum modules have something to
walk: sysDescr, sysName, sysUptime.
"""

import socket
import sys

sys.path.insert(0, "/app")
from snmp_codec import (GET_RESPONSE, SYSDESCR, SYSNAME, SYSUPTIME,  # noqa: E402
                        build_get_response, parse_request)

COMMUNITY = "private-lab"
PORT = 161

ANSWERS = {
    SYSDESCR: "FORGE lab SNMP agent (python, stdlib)",
    SYSNAME: "snmp-lab.forge.local",
    SYSUPTIME: 42424200,
}


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))
    while True:
        data, addr = sock.recvfrom(4096)
        try:
            community, oid, request_id, version = parse_request(data)
        except ValueError:
            continue  # malformed: silence, like a real agent
        if community != COMMUNITY:
            continue  # wrong community: silence, like a real agent
        value = ANSWERS.get(oid)
        if value is None:
            continue  # unknown OID: silence
        sock.sendto(build_get_response(COMMUNITY, oid, value,
                                       request_id, version), addr)


if __name__ == "__main__":
    main()
