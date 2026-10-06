from .util import human_time


def _table(rows, header):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return out


def render(summary):
    v_all, skew, acct = summary["verdicts"], summary["skew"], summary["row_accounting"]
    alerts = [v for v in v_all if v["status"] == "ALERT"]
    rej = [v for v in v_all if v["status"] == "REJECTED_BENIGN"]
    L = ["# ChronoTrace incident report", "",
         f"**Bottom line:** {len(alerts)} alert(s) raised, {len(rej)} look-alike(s) tested and rejected.", ""]
    L += ["## 1. Clock correction", "",
          f"Reference clock: `{skew['reference']}` ({skew['reference_method']}). Logs from different systems "
          "rarely agree on the time, so each source was aligned using events that appear in more than one log.", ""]
    L += _table([[s, o["offset_seconds"], o["status"], o["confidence"], o["description"]]
                 for s, o in sorted(skew["sources"].items())],
                ["source", "offset (s)", "status", "confidence", "meaning"])
    if skew["cycle_check_max_residual_s"] is not None:
        L += ["", f"Independent cycle check: pair estimates agree within {skew['cycle_check_max_residual_s']} s."]
    for w in skew["warnings"]:
        L.append(f"- WARNING: {w}")
    L += ["", "## 2. Findings (alerts)", ""]
    for v in alerts:
        L += [f"### {v['id']} - {v['rule']} - {v['severity']} severity, {v['confidence']} confidence", "",
              v["explanation"], "",
              f"Window: {human_time(v['start_ms'])} to {human_time(v['end_ms'])}. "
              f"Independent sources: {v['independent_sources']}. Techniques: {', '.join(v['facts'].get('techniques', [])) or 'n/a'}.", ""]
        L += _table([[e["stage"], e["time_utc"], f"{e['raw_file']}:{e['raw_line']}", e["raw_sha256"][:12]]
                     for e in v["evidence"][:8]], ["stage", "time (UTC)", "raw locator", "sha256"])
        if len(v["evidence"]) > 8:
            L.append(f"\n(+{len(v['evidence']) - 8} more locators in evidence-index.csv)")
        for lim in v["limitations"]:
            L.append(f"\n- Limitation: {lim}")
        L.append("")
    L += ["## 3. What left the network (packet capture)", ""]
    pcaps = summary.get("pcap", [])
    if not pcaps:
        L.append("No packet capture supplied.")
    for rep in pcaps:
        L.append(f"Capture `{rep['capture']}` (sha256 `{rep['capture_sha256'][:16]}`). Capture timestamps are taken as "
                 "recorded; this version does not correct the capture clock.")
        L.append("")
        rows = []
        for st in rep["streams"]:
            a = st["archive"]
            rows.append([st["stream"], st["server"], (st["http"] or {}).get("host", ""), st["client_payload_bytes"],
                         f"{a['size_bytes']} B, {len(a['members'])} file(s)" if a else "none",
                         st["completeness"]["status"]])
        L += _table(rows, ["stream", "server", "host", "bytes sent", "archive", "completeness"])
        for st in rep["streams"]:
            if st["archive"]:
                L.append(f"\n- {st['stream']}: " + "; ".join(st["completeness"]["reasons"]) + ".")
        for n in rep["notes"]:
            L.append(f"- Note: {n}")
    L += ["", "## 4. Alternatives tested and rejected", ""]
    if not rej:
        L.append("None.")
    for v in rej:
        L += [f"### {v['id']} - {v['rule']} (rejected)", "", v["explanation"], ""]
    L += ["## 5. Data quality", ""]
    L += _table([[s, a["raw_rows"], a["loaded"], a["quarantined"], a["duplicates"]]
                 for s, a in sorted(acct.items())], ["source", "raw rows", "loaded", "quarantined", "duplicates"])
    L += ["", "Every raw row is loaded, quarantined (with reason) or counted as a duplicate; totals must balance.", ""]
    return "\n".join(L) + "\n"
