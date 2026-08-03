"""Unit tests for the dns_recon module (stdlib-only, runs anywhere).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "dns_mod", ROOT / "modules" / "auxiliary" / "enum" / "dns_recon.py"
)
d = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(d)


def canned_response():
    """A minimal A-record answer with a compression pointer back to the
    question name — the shape real servers send."""
    qname = d.encode_name("forge.local")
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    question = qname + struct.pack("!HH", 1, 1)
    pointer = b"\xc0\x0c"  # offset 12: the question's qname
    rdata = bytes([10, 10, 10, 10])
    answer = pointer + struct.pack("!HHIH", 1, 1, 300, len(rdata)) + rdata
    return header + question + answer


class TestEncodeName(unittest.TestCase):
    def test_labels_and_terminator(self):
        self.assertEqual(d.encode_name("forge.local"),
                         b"\x05forge\x05local\x00")

    def test_trailing_dot_stripped(self):
        self.assertEqual(d.encode_name("forge.local."),
                         d.encode_name("forge.local"))


class TestReadName(unittest.TestCase):
    def test_plain(self):
        data = b"\x03www\x06google\x03com\x00"
        name, end = d.read_name(data, 0)
        self.assertEqual(name, "www.google.com")
        self.assertEqual(end, len(data))

    def test_compression_pointer(self):
        data = b"\x03www\x00" + b"\xc0\x00"  # pointer back to offset 0
        name, end = d.read_name(data, 5)
        self.assertEqual(name, "www")
        self.assertEqual(end, 7)

    def test_loop_guard(self):
        data = b"\xc0\x00"  # points at itself
        with self.assertRaises(ValueError):
            d.read_name(data, 0)


class TestFormatRdata(unittest.TestCase):
    def test_a(self):
        self.assertEqual(d._format_rdata(1, bytes([1, 2, 3, 4]), b"", 0),
                         "1.2.3.4")

    def test_srv(self):
        target = d.encode_name("dc.forge.local")
        rdata = struct.pack("!HHH", 0, 100, 389) + target
        self.assertEqual(d._format_rdata(33, rdata, rdata, 0),
                         "0 100 389 dc.forge.local.")

    def test_txt(self):
        rdata = b"\x05hello\x05world"
        self.assertEqual(d._format_rdata(16, rdata, b"", 0),
                         '"hello" "world"')


class TestParseResponse(unittest.TestCase):
    def test_canned_round_trip(self):
        rcode, answers = d.parse_response(canned_response())
        self.assertEqual(rcode, 0)
        self.assertEqual(answers, [("forge.local", "A", 300, "10.10.10.10")])


class TestModuleContract(unittest.TestCase):
    def test_no_requirements(self):
        self.assertEqual(d.DnsRecon.requirements, [])


if __name__ == "__main__":
    unittest.main()
