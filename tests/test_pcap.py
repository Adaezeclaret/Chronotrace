import hashlib
import math
import struct
import unittest
from helpers import BASE  # noqa: F401  (path bootstrap)
from chronotrace import pcap, synth

T0 = 1784030404300
ZIP = synth.exfil_zip()
PAYLOAD = synth.http_post(ZIP)
NCHUNKS = math.ceil(len(PAYLOAD) / 1200)


def stream(**kw):
    rep, blobs = pcap.analyze(synth.make_pcap(PAYLOAD, T0, **kw))
    return rep["streams"][0], rep, blobs


class PcapTests(unittest.TestCase):
    def test_complete_upload_is_recovered_byte_for_byte(self):
        st, _, blobs = stream()
        self.assertEqual(st["completeness"]["status"], "complete")
        self.assertEqual(st["archive"]["sha256"], hashlib.sha256(ZIP).hexdigest())
        self.assertEqual(blobs["C1"], ZIP)
        self.assertEqual([m["name"] for m in st["archive"]["members"]], ["synthetic-records.csv", "marker.txt"])
        self.assertEqual(st["archive"]["members"][0]["records"], 800)
        self.assertEqual(st["http"]["host"], "files-sync.example.invalid")

    def test_out_of_order_and_identical_retransmission_are_handled(self):
        st, *_ = stream(reorder=True, retransmit=True)
        self.assertEqual(st["retransmitted_segments"], 1)
        self.assertEqual(st["completeness"]["status"], "complete")

    def test_conflicting_retransmission_is_flagged(self):
        st, *_ = stream(conflict=True)
        self.assertEqual(st["completeness"]["status"], "incomplete")
        self.assertEqual(st["conflicting_retransmissions"], 1)

    def test_missing_middle_segment_is_a_gap_not_a_success(self):
        st, *_ = stream(drop=2)
        self.assertEqual(st["completeness"]["status"], "incomplete")
        self.assertEqual(len(st["gaps"]), 1)
        self.assertGreater(st["bytes_after_gap"], 0)

    def test_missing_last_segment_is_caught_by_declared_length(self):
        st, *_ = stream(drop=NCHUNKS - 1, reorder=False, retransmit=False)
        self.assertEqual(st["completeness"]["status"], "incomplete")
        self.assertTrue(any("declared bytes" in r for r in st["completeness"]["reasons"]))

    def test_sequence_number_wraparound(self):
        st, *_ = stream(isn=0xFFFFFFFF - 2000)
        self.assertEqual(st["completeness"]["status"], "complete")

    def test_payload_without_zip_reports_no_archive(self):
        junk = b"POST /u HTTP/1.1\r\nHost: a.example.invalid\r\nContent-Length: 6\r\n\r\nhello!"
        rep, _ = pcap.analyze(synth.make_pcap(junk, T0))
        self.assertEqual(rep["streams"][0]["completeness"]["status"], "no_archive")

    def test_split_archive_across_two_connections_is_reassembled_in_time_order(self):
        half = len(ZIP) // 2
        a = synth.make_pcap(ZIP[:half], T0, client=("10.0.0.5", 40001))
        b = synth.make_pcap(ZIP[half:], T0 + 5000, client=("10.0.0.5", 40002))
        merged = a + b[24:]  # one capture file, second connection captured later
        rep, blobs = pcap.analyze(merged)
        self.assertEqual(len(rep["streams"]), 2)
        self.assertIsNotNone(rep["split_archive"])
        self.assertEqual(blobs["split"], ZIP)
        self.assertEqual(rep["split_archive"]["completeness"]["status"], "unverified")

    def test_bad_inputs_raise_clear_errors_or_notes(self):
        with self.assertRaises(pcap.PcapError):
            pcap.analyze(b"definitely not a capture file at all..")
        with self.assertRaises(pcap.PcapError):
            pcap.analyze(b"short")
        cut = synth.make_pcap(PAYLOAD, T0)[:-10]
        rep, _ = pcap.analyze(cut)
        self.assertTrue(rep["notes"])

    def test_nanosecond_big_endian_header_is_read(self):
        data = bytearray(synth.make_pcap(PAYLOAD, T0))
        # rewrite the global header as big-endian microsecond and each record header likewise
        be = bytearray(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        pos = 24
        while pos < len(data):
            sec, us, inc, orig = struct.unpack("<IIII", data[pos:pos + 16])
            be += struct.pack(">IIII", sec, us, inc, orig) + data[pos + 16:pos + 16 + inc]
            pos += 16 + inc
        rep, _ = pcap.analyze(bytes(be))
        self.assertEqual(rep["streams"][0]["completeness"]["status"], "complete")

    def test_nothing_is_written_to_disk(self):
        from unittest import mock
        with mock.patch("builtins.open", side_effect=AssertionError("pcap analysis must not open files")):
            st, _, _ = stream()
        self.assertEqual(st["completeness"]["status"], "complete")


if __name__ == "__main__":
    unittest.main()
