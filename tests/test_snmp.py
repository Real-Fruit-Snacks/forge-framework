"""Unit tests for core/snmp and the brute engine's possible verdict.

Run: python3 -m unittest discover -s tests
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import snmp  # noqa: E402
from core.brute import brute_force  # noqa: E402


class TestBerCodec(unittest.TestCase):
    def test_integer_round_trip(self):
        for n in (0, 1, 127, 128, 255, 42424200, 0x7FFFFFFF):
            encoded = snmp.encode_integer(n)
            tag, value, _ = snmp._read_tlv(encoded, 0)
            self.assertEqual(tag, 0x02)
            self.assertEqual(snmp.decode_integer(value), n, n)

    def test_oid_round_trip(self):
        for oid in (snmp.SYSDESCR, (1, 3, 6, 1, 4, 1, 77, 1, 2, 25),
                    (2, 999, 128, 1)):
            encoded = snmp.encode_oid(oid)
            tag, value, _ = snmp._read_tlv(encoded, 0)
            self.assertEqual(tag, 0x06)
            self.assertEqual(snmp.decode_oid(value), oid, oid)


class TestSnmpMessages(unittest.TestCase):
    def test_get_request_round_trip(self):
        packet = snmp.build_get_request("private-lab", snmp.SYSDESCR,
                                        request_id=1337, version=1)
        community, oid, rid, version = snmp.parse_request(packet)
        self.assertEqual(community, "private-lab")
        self.assertEqual(oid, snmp.SYSDESCR)
        self.assertEqual(rid, 1337)
        self.assertEqual(version, 1)

    def test_get_response_round_trip(self):
        packet = snmp.build_get_response("private-lab", snmp.SYSDESCR,
                                         "FORGE lab agent", 1337)
        community, pdu_tag, value = snmp.parse_response(packet)
        self.assertEqual(community, "private-lab")
        self.assertEqual(pdu_tag, snmp.GET_RESPONSE)
        self.assertEqual(value, b"FORGE lab agent")

    def test_parse_rejects_garbage(self):
        with self.assertRaises(ValueError):
            snmp.parse_response(b"\x30\x03\x02\x01")
        with self.assertRaises(ValueError):
            snmp.parse_request(b"not a packet at all")


class TestPossibleVerdict(unittest.TestCase):
    def test_possible_counted_not_error(self):
        combos = [("u", f"c{i}") for i in range(5)]
        found, attempts, errors, possibles = brute_force(
            combos,
            attempt=lambda u, p: ("possible", "silence"),
            classify=lambda r: r[0],
            threads=2,
        )
        self.assertEqual(found, [])
        self.assertEqual(errors, 0)
        self.assertEqual(possibles, 5)
        self.assertEqual(attempts, 5)

    def test_success_still_stops(self):
        combos = [("u", f"c{i}") for i in range(10)]
        found, attempts, errors, possibles = brute_force(
            combos,
            attempt=lambda u, p: ("success",) if p == "c2" else ("possible",),
            classify=lambda r: r[0],
            threads=2,
        )
        self.assertEqual(found, [("u", "c2")])
        self.assertLess(attempts, 10)


if __name__ == "__main__":
    unittest.main()
