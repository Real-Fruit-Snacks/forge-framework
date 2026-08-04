"""Minimal SNMP v1/v2c wire codec (stdlib only).

SNMP's auth model is the community string sent in the clear — spraying
it needs a BER-encoded GetRequest per candidate and the discipline to
read silence honestly (a wrong community looks EXACTLY like a dead
host: nothing answers). This module is the BER layer: encode integers,
strings, OIDs, sequences; build a GetRequest; parse the response's
first varbind. No impacket (it has no SNMP), no netsnmp dependency.
"""

import random
import socket

GET_REQUEST = 0xA0
GET_RESPONSE = 0xA2

SYSDESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
SYSNAME = (1, 3, 6, 1, 2, 1, 1, 5, 0)
SYSUPTIME = (1, 3, 6, 1, 2, 1, 1, 3, 0)


# ------------------------------------------------------------- encoding
def encode_length(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag, value):
    return bytes([tag]) + encode_length(len(value)) + value


def encode_integer(n):
    if n == 0:
        return tlv(0x02, b"\x00")
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big", signed=False)
    if raw[0] & 0x80:
        raw = b"\x00" + raw  # keep it positive
    return tlv(0x02, raw)


def encode_string(s):
    return tlv(0x04, s.encode() if isinstance(s, str) else bytes(s))


def encode_null():
    return tlv(0x05, b"")


def _encode_base128(n):
    chunks = [n & 0x7F]
    n >>= 7
    while n:
        chunks.append(0x80 | (n & 0x7F))
        n >>= 7
    return bytes(reversed(chunks))


def encode_oid(arcs):
    # first two arcs pack into one base-128 subidentifier (40*a + b) —
    # which itself can exceed 127 (e.g. 2.999.*), so it gets the same
    # multi-byte treatment as the rest (X.690 8.19.4)
    out = _encode_base128(40 * arcs[0] + arcs[1])
    for arc in arcs[2:]:
        out += _encode_base128(arc)
    return tlv(0x06, out)


def encode_sequence(content, tag=0x30):
    return tlv(tag, content)


def build_get_request(community, oid, request_id, version=1):
    """A complete SNMP GetRequest message (version: 0=v1, 1=v2c)."""
    varbind = encode_sequence(encode_oid(oid) + encode_null())
    pdu = tlv(GET_REQUEST,
              encode_integer(request_id) + encode_integer(0)
              + encode_integer(0) + encode_sequence(varbind))
    return encode_sequence(encode_integer(version)
                           + encode_string(community) + pdu)


# ------------------------------------------------------------- decoding
def _read_tlv(data, pos):
    """(tag, value, next_pos) — raises ValueError on truncation."""
    if pos >= len(data):
        raise ValueError("truncated tlv")
    tag = data[pos]
    pos += 1
    if pos >= len(data):
        raise ValueError("truncated length")
    first = data[pos]
    pos += 1
    if first & 0x80:
        count = first & 0x7F
        if pos + count > len(data):
            raise ValueError("truncated long length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    else:
        length = first
    if pos + length > len(data):
        raise ValueError("truncated value")
    return tag, data[pos:pos + length], pos + length


def decode_integer(value):
    return int.from_bytes(value, "big", signed=bool(value and value[0] & 0x80))


def parse_response(data):
    """Parse an SNMP GetResponse enough for auth checking:
    (community, pdu_tag, first_varbind_value_bytes). Raises ValueError
    on malformed packets — a spray should treat them as silence."""
    tag, message, _ = _read_tlv(data, 0)
    if tag != 0x30:
        raise ValueError("not a sequence")
    _tag, _version_raw, pos = _read_tlv(message, 0)
    tag, community, pos = _read_tlv(message, pos)
    if tag != 0x04:
        raise ValueError("no community")
    tag, pdu, _pos = _read_tlv(message, pos)
    pdu_tag = tag
    # inside the pdu: request-id, error-status, error-index, varbind-list
    _t, _rid, pos = _read_tlv(pdu, 0)
    _t, _status, pos = _read_tlv(pdu, pos)
    _t, _index, pos = _read_tlv(pdu, pos)
    tag, varbinds, _pos = _read_tlv(pdu, pos)
    if tag != 0x30:
        raise ValueError("no varbind list")
    tag, varbind, _pos = _read_tlv(varbinds, 0)
    _t, _oid, pos = _read_tlv(varbind, 0)
    _vt, value, _pos = _read_tlv(varbind, pos)
    return community.decode("utf-8", "replace"), pdu_tag, value


def decode_oid(value):
    """BER OID bytes -> arc tuple (inverse of encode_oid)."""
    subids = []
    n = 0
    for byte in value:
        n = (n << 7) | (byte & 0x7F)
        if not byte & 0x80:
            subids.append(n)
            n = 0
    first = subids[0]
    if first < 40:
        return (0, first, *subids[1:])
    if first < 80:
        return (1, first - 40, *subids[1:])
    return (2, first - 80, *subids[1:])


def parse_request(data):
    """Parse a GetRequest -> (community, oid, request_id, version).
    Raises ValueError on malformed packets (agents should stay silent)."""
    tag, message, _ = _read_tlv(data, 0)
    if tag != 0x30:
        raise ValueError("not a sequence")
    tag, version_raw, pos = _read_tlv(message, 0)
    if tag != 0x02:
        raise ValueError("no version")
    version = decode_integer(version_raw)
    tag, community, pos = _read_tlv(message, pos)
    if tag != 0x04:
        raise ValueError("no community")
    tag, pdu, _pos = _read_tlv(message, pos)
    if tag != GET_REQUEST:
        raise ValueError("not a GetRequest")
    tag, rid_raw, pos = _read_tlv(pdu, 0)
    request_id = decode_integer(rid_raw)
    _t, _status, pos = _read_tlv(pdu, pos)
    _t, _index, pos = _read_tlv(pdu, pos)
    tag, varbinds, _pos = _read_tlv(pdu, pos)
    tag, varbind, _pos = _read_tlv(varbinds, 0)
    tag, oid_raw, _pos = _read_tlv(varbind, 0)
    if tag != 0x06:
        raise ValueError("no oid")
    return community.decode("utf-8", "replace"), decode_oid(oid_raw), \
        request_id, version


def build_get_response(community, oid, value, request_id, version=1):
    """A complete GetResponse message for an agent fixture. Integer
    values are encoded as INTEGER, everything else as OCTET STRING."""
    if isinstance(value, int):
        encoded = encode_integer(value)
    else:
        encoded = encode_string(value)
    varbind = encode_sequence(encode_oid(oid) + encoded)
    pdu = tlv(GET_RESPONSE,
              encode_integer(request_id) + encode_integer(0)
              + encode_integer(0) + encode_sequence(varbind))
    return encode_sequence(encode_integer(version)
                           + encode_string(community) + pdu)


def query(host, port, community, oid=SYSDESCR, timeout=3.0, version=1):
    """One GetRequest -> value_bytes or None on silence/error."""
    packet = build_get_request(community, oid,
                               request_id=random.randint(1, 0x7FFFFFFF),
                               version=version)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(4096)
    echoed, pdu_tag, value = parse_response(data)
    if pdu_tag != GET_RESPONSE or echoed != community:
        return None  # wrong community echo or an error report — treat as miss
    return value
