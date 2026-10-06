import unittest
from helpers import load, proc


class IngestTests(unittest.TestCase):
    def test_malformed_and_missing_time_are_quarantined_with_line_numbers(self):
        ev, q, d, acct = load({"a.jsonl": [proc(0, "x.exe", ""), "{broken", '{"host": "H"}',
                                           '{"timestamp": "nope"}', proc(1, "y.exe", "")]})
        self.assertEqual([(x["raw_line"], x["reason"]) for x in q],
                         [(2, "malformed_json"), (3, "missing_or_unparseable_time"),
                          (4, "missing_or_unparseable_time")])
        self.assertEqual(len(ev), 2)

    def test_exact_duplicates_collapse_and_accounting_balances(self):
        row = proc(0, "x.exe", "")
        ev, q, d, acct = load({"a.jsonl": [row, row, proc(1, "y.exe", "")]})
        self.assertEqual(len(ev), 2)
        self.assertEqual(d[0]["duplicate_of_line"], 1)
        a = acct["a"]
        self.assertEqual(a["raw_rows"], a["loaded"] + a["quarantined"] + a["duplicates"])

    def test_three_schema_versions_normalise_identically(self):
        v1 = {"timestamp": "2026-07-14T12:00:00Z", "host": "H", "user": "u", "image": "a.exe",
              "parent_image": "p.exe", "command_line": "c", "event": "process_start"}
        v2 = {"event_time": "2026-07-14T12:00:00Z", "device": "H", "identity": "u", "process": "a.exe",
              "parent": "p.exe", "cmdline": "c", "event_name": "process_start"}
        v3 = {"time": "2026-07-14T12:00:00Z", "record": {"host": "H", "actor": "u", "exe": "a.exe",
              "parent_process": "p.exe", "command": "c", "action": "process_start"}}
        ev, *_ = load({"a.jsonl": [v1, v2, v3]})
        keys = {(e.host, e.actor, e.image, e.parent, e.cmd, e.event, e.raw_ts_ms) for e in ev}
        self.assertEqual(len(ev), 3)
        self.assertEqual(len(keys), 1)

    def test_destination_extracted_from_url_and_default_event(self):
        ev, *_ = load({"a.jsonl": [{"timestamp": "2026-07-14T12:00:00Z", "image": "curl.exe",
                                    "command_line": "curl.exe https://Host.Example.invalid:8443/x"}]})
        self.assertEqual((ev[0].dst, ev[0].dst_port, ev[0].event), ("Host.Example.invalid", "8443", "process_start"))

    def test_epoch_and_offset_timestamps(self):
        ev, *_ = load({"a.jsonl": [{"time": 1784030400, "host": "H"},
                                   {"time": "2026-07-14T14:00:00+02:00", "host": "H"}]})
        self.assertEqual(ev[0].raw_ts_ms, ev[1].raw_ts_ms)


if __name__ == "__main__":
    unittest.main()
