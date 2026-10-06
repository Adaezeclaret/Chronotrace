import unittest
from helpers import iso, load, write_dir
from chronotrace import skew as sk


def mk(offsets, anchors, extra=None):
    """offsets: {source: seconds ahead}; anchors: list of (corr, true_sec, [sources])."""
    files = {}
    for s, off in offsets.items():
        files[f"{s}.jsonl"] = []
    for corr, t, srcs in anchors:
        for s in srcs:
            files[f"{s}.jsonl"].append({"timestamp": iso(t + offsets[s]), "host": "H", "correlation_id": corr})
    for name, rows in (extra or {}).items():
        files[name] = rows
    return load(files)[0]


class SkewTests(unittest.TestCase):
    def test_recovers_known_offset_and_uses_majority_reference(self):
        ev = mk({"a": 0, "b": 3600, "c": 0}, [("k1", 10, "abc"), ("k2", 50, "abc"), ("k3", 90, "abc")])
        r = sk.infer_skew(ev)
        self.assertEqual(r["sources"]["b"]["offset_seconds"], -3600)
        self.assertEqual(r["sources"]["a"]["offset_seconds"], 0)
        self.assertEqual(r["sources"]["b"]["confidence"], "high")
        self.assertEqual(r["reference_method"], "median-clock")

    def test_outlier_anchor_rejected(self):
        ev = mk({"a": 0, "b": 100}, [("k1", 10, "ab"), ("k2", 50, "ab"), ("k3", 90, "ab")])
        for e in ev:  # corrupt one anchor on b by an hour
            if e.source == "b" and e.corr == "k3":
                e.raw_ts_ms += 3600 * 1000
        r = sk.infer_skew(ev, reference="a")
        self.assertEqual(r["sources"]["b"]["offset_seconds"], -100)
        self.assertEqual(r["pair_estimates"][0]["rejected_anchors"], ["k3"])

    def test_unanchored_source_is_flagged_not_guessed(self):
        ev = mk({"a": 0, "b": 5, "z": 999}, [("k1", 10, "ab"), ("k2", 20, "ab")],
                extra={"z.jsonl": [{"timestamp": iso(1), "host": "H"}]})
        r = sk.infer_skew(ev)
        self.assertEqual(r["sources"]["z"]["status"], "unanchored")
        self.assertEqual(r["sources"]["z"]["offset_seconds"], 0)
        self.assertTrue(any("z" in w for w in r["warnings"]))

    def test_single_anchor_is_low_confidence(self):
        r = sk.infer_skew(mk({"a": 0, "b": 30}, [("k1", 10, "ab")]), reference="a")
        self.assertEqual(r["sources"]["b"]["confidence"], "low")

    def test_reference_override_and_bad_reference(self):
        ev = mk({"a": 0, "b": 60, "c": 0}, [("k1", 10, "abc"), ("k2", 50, "abc")])
        r = sk.infer_skew(ev, reference="b")
        self.assertEqual((r["reference"], r["sources"]["a"]["offset_seconds"]), ("b", 60))
        ev2 = mk({"a": 0, "b": 5}, [("k1", 10, "ab")], extra={"z.jsonl": [{"timestamp": iso(1)}]})
        with self.assertRaises(ValueError):
            sk.infer_skew(ev2, reference="z")

    def test_apply_skew_moves_timestamps(self):
        ev = mk({"a": 0, "b": 60}, [("k1", 10, "ab"), ("k2", 20, "ab")])
        sk.apply_skew(ev, sk.infer_skew(ev, reference="a"))
        b = [e for e in ev if e.source == "b"][0]
        self.assertEqual(b.ts_ms, b.raw_ts_ms - 60000)

    def test_strong_links_beat_a_weak_direct_link(self):
        # a-b has one anchor (weak); a-c and c-b have two each. b must be rated via the strong path.
        ev = mk({"a": 0, "b": 40, "c": 10},
                [("k1", 10, "abc"), ("k2", 30, "ac"), ("k3", 50, "cb")])
        r = sk.infer_skew(ev, reference="a")
        self.assertEqual(r["sources"]["b"]["offset_seconds"], -40)
        self.assertEqual(r["sources"]["b"]["confidence"], "high")


if __name__ == "__main__":
    unittest.main()
