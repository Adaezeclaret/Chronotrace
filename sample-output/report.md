# ChronoTrace incident report

**Bottom line:** 2 alert(s) raised, 2 look-alike(s) tested and rejected.

## 1. Clock correction

Reference clock: `script` (median-clock). Logs from different systems rarely agree on the time, so each source was aligned using events that appear in more than one log.

| source | offset (s) | status | confidence | meaning |
|---|---|---|---|---|
| auth | 0 | anchored | high | no correction applied |
| endpoint | -22407 | anchored | high | clock runs ahead of the reference by 6h 13m 27s; subtracted |
| firewall | -12 | anchored | high | clock runs ahead of the reference by 12s; subtracted |
| network | 5 | anchored | high | clock runs behind the reference by 5s; added |
| script | 0 | reference | reference | no correction applied |

Independent cycle check: pair estimates agree within 0 s.

## 2. Findings (alerts)

### V-003 - auth_failure_burst - high severity, high confidence

Address 192.0.2.88 failed 14 logins across 5 account(s) starting 2026-08-19 08:05:00 UTC, a pattern consistent with password guessing. It then succeeded as j.okafor, meaning a guess may have worked.

Window: 2026-08-19 08:05:00 UTC to 2026-08-19 10:03:34 UTC. Independent sources: 2. Techniques: T1110.

| stage | time (UTC) | raw locator | sha256 |
|---|---|---|---|
| corroboration | 2026-08-19T08:04:59.630Z | firewall.jsonl:104 | ac2d701d11bc |
| failure | 2026-08-19T08:05:00.000Z | auth.jsonl:133 | 854163fb8b37 |
| failure | 2026-08-19T08:11:08.000Z | auth.jsonl:134 | f87ba43b00b3 |
| failure | 2026-08-19T08:19:56.000Z | auth.jsonl:135 | b161aa8778b6 |
| failure | 2026-08-19T08:27:41.000Z | auth.jsonl:137 | 283f30613aee |
| failure | 2026-08-19T08:34:27.000Z | auth.jsonl:138 | 6331ca59c7aa |
| failure | 2026-08-19T08:43:14.000Z | auth.jsonl:139 | 8b3d1cf10650 |
| failure | 2026-08-19T08:50:15.000Z | auth.jsonl:145 | 117bd43d7d55 |

(+9 more locators in evidence-index.csv)

- Limitation: Only one log source observed this address; add firewall/endpoint logs to corroborate.

### V-004 - staging_exfil_chain - critical severity, high confidence

On WKS-DEMO-01 at 2026-08-19 09:41:11 UTC, a winword document opened a scripting tool (powershell). Within 11s the same computer set up a scheduled task (a trick to keep access after a restart), packed files into a single archive, sent data out to an outside address, and deleted the local copy to hide it (destination: files-sync.example.invalid). This is the classic shape of a malicious document followed by data theft. The packet capture shows what left: a 5,848-byte archive holding 2 file(s) (800 records), and the recovered transfer is complete: nothing is missing.

Window: 2026-08-19 09:41:11 UTC to 2026-08-19 09:41:23 UTC. Independent sources: 4. Techniques: T1566/T1059, T1053.005, T1560, T1041, T1070.004.

| stage | time (UTC) | raw locator | sha256 |
|---|---|---|---|
| initial_access | 2026-08-19T09:41:11.992Z | endpoint.jsonl:577 | 2c20938823fa |
| corroboration | 2026-08-19T09:41:12.374Z | script.jsonl:69 | ac2eed915e7c |
| persistence | 2026-08-19T09:41:13.974Z | endpoint.jsonl:578 | 4aa96c5a6b45 |
| corroboration | 2026-08-19T09:41:14.175Z | script.jsonl:70 | e611ed2f22f1 |
| staging | 2026-08-19T09:41:17.076Z | endpoint.jsonl:579 | 3501ded872a0 |
| egress | 2026-08-19T09:41:21.233Z | endpoint.jsonl:580 | a86e9e40b45a |
| egress | 2026-08-19T09:41:21.560Z | firewall.jsonl:124 | 25c8ab24779c |
| egress | 2026-08-19T09:41:21.672Z | network.jsonl:180 | 182e51cd0247 |

(+1 more locators in evidence-index.csv)

- Limitation: Timing relies on the inferred clock offsets; see skew-report.json.

## 3. What left the network (packet capture)

Capture `capture.pcap` (sha256 `1d3dd870996fbbf0`). Capture timestamps are taken as recorded; this version does not correct the capture clock.

| stream | server | host | bytes sent | archive | completeness |
|---|---|---|---|---|---|
| C1 | 203.0.113.50:8443 | files-sync.example.invalid | 5929 | 5848 B, 2 file(s) | complete |

- C1: byte count matches the declared length, no gaps, archive directory present and every member checksum verifies.

## 4. Alternatives tested and rejected

### V-001 - auth_failure_burst (rejected)

Address 10.77.10.9 failed 40 logins from 2026-08-19 01:10:00 UTC, which looks like password guessing, but it was rejected as an authorised scan: source address and full time span covered by approved change CHG-SCAN-DEMO.

### V-002 - staging_without_entry_point (rejected)

On SRV-DEMO-07 at 2026-08-19 03:00:00 UTC, files were archived and sent to backup.corp.internal. That looks like data theft at first glance, but it was rejected as routine activity: archive was started by a scheduler/service host, not by a user document or script; every destination is internal: backup.corp.internal.

## 5. Data quality

| source | raw rows | loaded | quarantined | duplicates |
|---|---|---|---|---|
| auth | 355 | 355 | 0 | 0 |
| endpoint | 1512 | 1507 | 4 | 1 |
| firewall | 304 | 304 | 0 | 0 |
| network | 403 | 403 | 0 | 0 |
| script | 203 | 203 | 0 | 0 |

Every raw row is loaded, quarantined (with reason) or counted as a duplicate; totals must balance.

