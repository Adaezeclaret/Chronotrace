import csv
import json
import os
import tempfile
import unittest
from helpers import BASE  # noqa: F401  (path bootstrap)
from chronotrace import build, synth
from chronotrace.util import sha256_text


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.inp = os.path.join(cls.tmp.name, "in")
        cls.out = os.path.join(cls.tmp.name, "out")
        synth.make(cls.inp)
        cls.sm = build.run(cls.inp, cls.out, os.path.join(cls.inp, "changes.json"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_expected_findings(self):
        got = sorted((v["rule"], v["status"], v["subject"]) for v in self.sm["verdicts"])
        self.assertEqual(got, [("auth_failure_burst", "ALERT", "192.0.2.88"),
                               ("auth_failure_burst", "REJECTED_BENIGN", "10.77.10.9"),
                               ("staging_exfil_chain", "ALERT", "WKS-DEMO-01"),
                               ("staging_without_entry_point", "REJECTED_BENIGN", "SRV-DEMO-07")])

    def test_skew_recovered_within_two_seconds(self):
        s = self.sm["skew"]["sources"]
        self.assertLessEqual(abs(s["endpoint"]["offset_seconds"] + 22407), 2)
        self.assertLessEqual(abs(s["network"]["offset_seconds"] - 5), 2)
        self.assertLessEqual(abs(s["firewall"]["offset_seconds"] + 12), 2)
        self.assertEqual(s["auth"]["status"], "anchored")
        self.assertIn(self.sm["skew"]["reference"], ("auth", "script"))
        self.assertLessEqual(self.sm["skew"]["cycle_check_max_residual_s"], 2)

    def test_chain_is_twelve_seconds_after_correction(self):
        v = [x for x in self.sm["verdicts"] if x["rule"] == "staging_exfil_chain"][0]
        self.assertTrue(v["start_utc"].startswith("2026-08-19T09:41:1"))
        self.assertTrue(11.0 <= v["facts"]["duration_s"] <= 13.0)

    def test_row_accounting_balances_and_bad_rows_are_visible(self):
        for a in self.sm["row_accounting"].values():
            self.assertEqual(a["raw_rows"], a["loaded"] + a["quarantined"] + a["duplicates"])
        self.assertEqual(self.sm["row_accounting"]["endpoint"]["quarantined"], 4)
        self.assertEqual(self.sm["row_accounting"]["endpoint"]["duplicates"], 1)

    def test_every_evidence_locator_resolves_to_the_raw_line(self):
        rows = list(csv.DictReader(open(os.path.join(self.out, "evidence-index.csv"), encoding="utf-8")))
        self.assertGreater(len(rows), 20)
        for r in rows:
            with open(os.path.join(self.inp, r["raw_file"]), encoding="utf-8") as f:
                line = f.read().split("\n")[int(r["raw_line"]) - 1]
            self.assertEqual(sha256_text(line), r["raw_sha256"], r["claim_id"])

    def test_spray_is_corroborated_by_firewall_and_rated_high_confidence(self):
        v = [x for x in self.sm["verdicts"] if x["rule"] == "auth_failure_burst" and x["status"] == "ALERT"][0]
        self.assertEqual(v["confidence"], "high")
        self.assertEqual({e["source"] for e in v["evidence"]}, {"auth", "firewall"})

    def test_capture_confirms_what_left_and_is_linked_to_the_chain(self):
        import hashlib
        v = [x for x in self.sm["verdicts"] if x["rule"] == "staging_exfil_chain"][0]
        x = v["facts"]["exfil"]
        self.assertEqual((x["status"], x["files"], x["records"]), ("complete", 2, 800))
        self.assertEqual(x["sha256"], hashlib.sha256(synth.exfil_zip()).hexdigest())
        self.assertLessEqual(abs(x["seconds_from_logged_egress"]), 2)
        self.assertIn("packet capture", v["explanation"])
        self.assertIn("T1041", v["facts"]["techniques"])
        self.assertTrue(os.path.exists(os.path.join(self.out, "exfil-analysis.json")))

    def test_exfiltrated_content_is_never_written_to_the_output_folder(self):
        for n in os.listdir(self.out):
            self.assertFalse(n.endswith((".zip", ".csv")) and n not in ("timeline.csv", "evidence-index.csv"), n)
        self.assertNotIn("person1,", open(os.path.join(self.out, "exfil-analysis.json")).read())

    def test_chain_evidence_spans_independent_sources(self):
        v = [x for x in self.sm["verdicts"] if x["rule"] == "staging_exfil_chain"][0]
        self.assertGreaterEqual({e["source"] for e in v["evidence"]}, {"endpoint", "network", "script"})

    def test_two_clean_builds_are_byte_identical(self):
        ok, manifest = build.verify(self.inp, os.path.join(self.inp, "changes.json"))
        self.assertTrue(ok)
        self.assertEqual(manifest, open(os.path.join(self.out, "manifest.sha256")).read())

    def test_manifest_verifies_and_excludes_runtime_metrics(self):
        text = open(os.path.join(self.out, "manifest.sha256")).read()
        self.assertNotIn("run-metrics", text)
        self.assertNotIn("manifest.sha256", text)
        import hashlib
        for line in text.strip().split("\n"):
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256(open(os.path.join(self.out, name), "rb").read()).hexdigest(), digest)

    def test_no_wall_clock_leaks_into_hashed_outputs(self):
        for n in os.listdir(self.out):
            if n in ("run-metrics.json", "manifest.sha256"):
                continue
            self.assertNotIn(tempfile.gettempdir(), open(os.path.join(self.out, n), encoding="utf-8").read())

    def test_viewer_is_self_contained_and_embeds_valid_data(self):
        html = open(os.path.join(self.out, "viewer.html"), encoding="utf-8").read()
        for bad in ('src="http', 'href="http', "@import", "<link", "fetch("):
            self.assertNotIn(bad, html)
        blob = html.split('<script id="data" type="application/json">')[1].split("</script>")[0]
        data = json.loads(blob.replace("<\\/", "</"))
        self.assertEqual([v["id"] for v in data["verdicts"]], [v["id"] for v in self.sm["verdicts"]])
        for v in data["verdicts"]:
            for e in v["evidence"]:
                self.assertIn("raw_time_utc", e)
                self.assertTrue(e["label"])

    def test_viewer_escapes_script_terminator_in_data(self):
        from chronotrace import viewer
        sm = {"verdicts": [{"id": "V-001", "explanation": "x</script><b>"}], "skew": {}, "row_accounting": {}}
        html = viewer.render(sm)
        self.assertEqual(html.count("</script>"), 2)


if __name__ == "__main__":
    unittest.main()
