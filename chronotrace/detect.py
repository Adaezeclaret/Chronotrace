"""Detections keyed on process CLASS, parentage, destination and timing (never on literal
command strings or fixture ids), plus explicit benign-lookalike rejection with reasons."""
import ipaddress

from .util import fmt_ms, parse_time_ms

CLASSES = (
    ("office", {"winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "mspub"}),
    ("script", {"powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "powershell_ise"}),
    ("sched", {"schtasks", "at"}),
    ("archive", {"tar", "7z", "7za", "7zg", "zip", "rar", "winrar", "gzip"}),
    ("transfer", {"curl", "wget", "bitsadmin", "scp", "sftp", "ftp"}),
    ("service", {"services", "svchost", "taskeng", "taskhostw", "cron", "crond", "systemd", "backupagent"}),
)
PROC = {"process_start", "process_create", "process", "processcreate"}
NET_EVENTS = {"connection", "network_connection", "proxy", "proxy_request", "upload", "netconn"}
DELETE_EVENTS = {"file_delete", "filedelete"}
# Technique labels reused from my Stage 9 rules (110122, 110111, 110123, 110124).
TECHNIQUES = {"initial_access": "T1566/T1059", "persistence": "T1053.005", "staging": "T1560",
              "egress": "T1041", "cleanup": "T1070.004"}
FAIL = {"fail", "failed", "failure", "auth_fail", "login_failed", "logon_failure", "4625"}
OK = {"success", "succeeded", "login_success", "logon_success", "auth_success", "4624"}
INTERNAL_SUFFIXES = (".internal", ".local", ".corp", ".lan", ".intranet")
# Explicit RFC1918/loopback/link-local ranges: Python's is_private also covers documentation
# ranges (198.51.100.0/24 etc.), which would wrongly treat test-net addresses as internal.
_PRIVATE = [ipaddress.ip_network(n) for n in
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
             "169.254.0.0/16", "fc00::/7", "::1/128")]


def base_name(p):
    if not p:
        return ""
    b = p.strip().replace("\\", "/").split("/")[-1].lower()
    for suf in (".exe", ".com", ".bat"):
        if b.endswith(suf):
            return b[:-len(suf)]
    return b


def cls(p):
    b = base_name(p)
    for name, names in CLASSES:
        if b in names:
            return name
    return "other"


def is_internal(dst):
    d = (dst or "").strip().strip("[]").lower()
    if not d:
        return False
    try:
        ip = ipaddress.ip_address(d)
        return any(ip in n for n in _PRIVATE)
    except ValueError:
        pass
    return "." not in d or d.endswith(INTERNAL_SUFFIXES)


def _is_send(e):
    return cls(e.image) == "transfer" or (e.event in NET_EVENTS and bool(e.dst))


def _is_egress(e):
    return _is_send(e) and bool(e.dst) and not is_internal(e.dst)


def _initial_access(e):
    return e.event in PROC and cls(e.parent) == "office" and cls(e.image) == "script"


def _label(e):
    if e.event in FAIL or e.event in OK:
        return f"{e.event.replace('_', ' ')} as {e.actor or 'unknown'}"
    if e.event in DELETE_EVENTS:
        return f"file deleted by {base_name(e.image) or 'unknown'}"
    if e.event in PROC and e.image:
        par = base_name(e.parent)
        return f"{par} started {base_name(e.image)}" if par else f"{base_name(e.image)} started"
    if e.event == "script_block":
        return "script: " + (e.cmd[:48] or "unknown")
    if e.dst:
        return f"{e.event.replace('_', ' ')} to {e.dst}"
    return e.event or "event"


def _ev(e, stage):
    return {"eid": e.eid, "stage": stage, "source": e.source, "raw_file": e.raw_file,
            "raw_line": e.raw_line, "raw_sha256": e.raw_sha, "time_utc": fmt_ms(e.ts_ms),
            "raw_time_utc": fmt_ms(e.raw_ts_ms), "label": _label(e)}


def _collect(primary, corr_index):
    seen = {}
    for stage, e in primary:
        seen.setdefault(e.eid, (stage, e))
    for _, e in list(primary):
        if e.corr:
            for o in corr_index.get(e.corr, []):
                if o.source != e.source and o.eid not in seen:
                    seen[o.eid] = ("corroboration", o)
    return [_ev(e, s) for s, e in sorted(seen.values(), key=lambda t: t[1].key())]


def match_change(changes, start_ms, end_ms, **fields):
    """An APPROVED change covers the activity only if the whole activity is inside its window
    and at least one identifying field (host, dst, src_ip...) is present and matches."""
    for c in changes:
        if str(c.get("status", "")).upper() != "APPROVED":
            continue
        s, e = parse_time_ms(c.get("starts_at")), parse_time_ms(c.get("ends_at"))
        if s is None or e is None or not (s <= start_ms and end_ms <= e):
            continue
        if not any(c.get(k) for k in fields):
            continue
        if all(not c.get(k) or str(c[k]).lower() == str(v).lower() for k, v in fields.items()):
            return c
    return None


def _verdict(rule, status, severity, subject, start, end, facts, evidence, reasons=None, limitations=None):
    distinct = len({x["source"] for x in evidence})
    return {"rule": rule, "status": status, "severity": severity, "subject": subject,
            "start_ms": start, "end_ms": end, "start_utc": fmt_ms(start), "end_utc": fmt_ms(end),
            "facts": facts, "evidence": evidence, "independent_sources": distinct,
            "confidence": "high" if distinct >= 2 else "medium",
            "reasons": reasons or [], "limitations": limitations or []}


def _by_host(evs):
    out = {}
    for e in evs:
        if e.host:
            out.setdefault(e.host, []).append(e)
    return out


def _chains(evs, corr, win):
    out, used = [], set()
    hosts = _by_host(evs)
    for host in sorted(hosts):
        hevs, covered = hosts[host], -1
        for e in hevs:
            if e.ts_ms < covered or not _initial_access(e):
                continue
            w = [x for x in hevs if e.ts_ms <= x.ts_ms <= e.ts_ms + win]
            st = {"initial_access": [e],
                  "persistence": [x for x in w if cls(x.image) == "sched"],
                  "staging": [x for x in w if cls(x.image) == "archive"],
                  "egress": [x for x in w if _is_egress(x)],
                  "cleanup": [x for x in w if x.event in DELETE_EVENTS]}
            if not (st["staging"] and st["egress"]):
                continue
            prim = [(k, x) for k, v in st.items() for x in v]
            end = max(x.ts_ms for _, x in prim)
            covered = end + 1
            used.update(x.eid for _, x in prim)
            present = [k for k, v in st.items() if v]
            sev = "critical" if len(present) == 5 else "high" if len(present) == 4 else "medium"
            facts = {"entry_parent_class": cls(e.parent), "entry_child_class": cls(e.image),
                     "entry_parent": base_name(e.parent), "entry_child": base_name(e.image),
                     "stages_present": present, "duration_s": round((end - e.ts_ms) / 1000.0, 3),
                     "destinations": sorted({x.dst for x in st["egress"]}),
                     "techniques": [TECHNIQUES[k] for k in present]}
            lim = ["Timing relies on the inferred clock offsets; see skew-report.json."]
            out.append(_verdict("staging_exfil_chain", "ALERT", sev, host, e.ts_ms, end, facts,
                                _collect(prim, corr), limitations=lim))
    return out, used


def _staging(evs, corr, win, used, changes):
    out = []
    hosts = _by_host(evs)
    for host in sorted(hosts):
        hevs, covered = hosts[host], -1
        for e in hevs:
            if e.ts_ms < covered or e.eid in used or cls(e.image) != "archive" or e.event not in PROC:
                continue
            sends = [x for x in hevs if e.ts_ms <= x.ts_ms <= e.ts_ms + win and _is_send(x)]
            if not sends:
                continue
            dsts = sorted({x.dst for x in sends if x.dst})
            ext = [d for d in dsts if not is_internal(d)]
            end = max(x.ts_ms for x in sends + [e])
            covered = end + 1
            svc = cls(e.parent) == "service"
            internal_only = bool(dsts) and not ext
            change = match_change(changes, e.ts_ms, end, host=host, dst=dsts[0] if dsts else "")
            reasons = []
            if svc:
                reasons.append("archive was started by a scheduler/service host, not by a user document or script")
            if internal_only:
                reasons.append("every destination is internal: " + ", ".join(dsts))
            if change:
                reasons.append(f"covered by approved change {change.get('change_id', '?')}")
            benign = bool(change) or (svc and internal_only)
            prim = [("staging", e)] + [("transfer", x) for x in sends]
            facts = {"archive_parent_class": cls(e.parent), "destinations": dsts,
                     "external_destination": bool(ext),
                     "change_id": change.get("change_id") if change else None}
            if benign:
                out.append(_verdict("staging_without_entry_point", "REJECTED_BENIGN", "info", host, e.ts_ms, end,
                                    facts, _collect(prim, corr), reasons=reasons))
            else:
                out.append(_verdict("staging_without_entry_point", "ALERT", "medium" if ext else "low", host,
                                    e.ts_ms, end, facts, _collect(prim, corr), reasons=reasons,
                                    limitations=["No document-based entry point was found; analyst review needed."]))
    return out


def _auth(evs, corr, gap, min_fail, success_win, changes):
    out, by_ip = [], {}
    for e in evs:
        if e.src_ip and (e.event in FAIL or e.event in OK):
            by_ip.setdefault(e.src_ip, []).append(e)
    for ip in sorted(by_ip):
        items = by_ip[ip]
        clusters, cur = [], []
        for f in (x for x in items if x.event in FAIL):
            if cur and f.ts_ms - cur[-1].ts_ms > gap:
                clusters.append(cur)
                cur = []
            cur.append(f)
        if cur:
            clusters.append(cur)
        for c in clusters:
            if len(c) < min_fail:
                continue
            last = c[-1].ts_ms
            succ = [x for x in items if x.event in OK and last <= x.ts_ms <= last + success_win]
            end = succ[0].ts_ms if succ else last
            users = sorted({x.actor for x in c if x.actor})
            facts = {"src_ip": ip, "failures": len(c), "distinct_accounts": len(users),
                     "techniques": ["T1110"], "followed_by_success": bool(succ), "success_account": succ[0].actor if succ else None}
            prim = [("failure", x) for x in c] + ([("success", succ[0])] if succ else [])
            change = match_change(changes, c[0].ts_ms, end, src_ip=ip)
            lim = ["Only one log source observed this address; add firewall/endpoint logs to corroborate."]
            if change:
                facts["change_id"] = change.get("change_id")
                out.append(_verdict("auth_failure_burst", "REJECTED_BENIGN", "info", ip, c[0].ts_ms, end, facts,
                                    _collect(prim, corr),
                                    reasons=[f"source address and full time span covered by approved change "
                                             f"{change.get('change_id', '?')}"]))
            else:
                out.append(_verdict("auth_failure_burst", "ALERT", "high" if succ else "medium", ip,
                                    c[0].ts_ms, end, facts, _collect(prim, corr), limitations=lim))
    return out


def detect_all(events, changes=None, window_s=120, gap_s=1800, min_failures=8, success_s=3600):
    evs = sorted(events, key=lambda e: e.key())
    changes = changes or []
    corr = {}
    for e in evs:
        if e.corr:
            corr.setdefault(e.corr, []).append(e)
    win = int(window_s * 1000)
    chains, used = _chains(evs, corr, win)
    verdicts = chains + _staging(evs, corr, win, used, changes)
    verdicts += _auth(evs, corr, int(gap_s * 1000), min_failures, int(success_s * 1000), changes)
    verdicts.sort(key=lambda v: (v["start_ms"], v["rule"], v["subject"]))
    for i, v in enumerate(verdicts, 1):
        v["id"] = f"V-{i:03d}"
    return verdicts
