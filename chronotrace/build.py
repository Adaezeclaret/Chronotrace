import csv
import json
import os
import sys
import tempfile
import time

from . import detect, explain, ingest, pcap, report, skew as skewmod, viewer
from .util import fmt_ms, sha256_file

TIMELINE_COLS = ["event_time_utc", "raw_time_utc", "source", "host", "actor", "event", "image", "parent",
                 "src_ip", "dst", "dst_port", "correlation_id", "raw_file", "raw_line", "raw_sha256"]
UNHASHED = {"manifest.sha256", "run-metrics.json"}


def _peak_mb():
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class PMC(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                            ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

            kernel, psapi = ctypes.windll.kernel32, ctypes.windll.psapi
            kernel.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
            pmc = PMC()
            pmc.cb = ctypes.sizeof(PMC)
            if psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
                return round(pmc.PeakWorkingSetSize / (1024 * 1024), 1)
        except Exception:
            pass
        return None
    try:
        import resource
        kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(kb / (1024 * 1024 if sys.platform == "darwin" else 1024), 1)
    except Exception:  # not available on Windows
        return None


def _dump(path, obj):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _csv(path, header, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def load_changes(path):
    if not path:
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data["changes"] if isinstance(data, dict) else data


def _link_exfil(verdicts, reports):
    """Attach 'what left the network' to a chain verdict when a capture shows an archive going to
    the same host the logs say data was sent to."""
    from .util import parse_time_ms
    for v in verdicts:
        if v["rule"] != "staging_exfil_chain":
            continue
        dests = {d.lower() for d in v["facts"]["destinations"]}
        egress = [parse_time_ms(e["time_utc"]) for e in v["evidence"] if e["stage"] == "egress"]
        for rep in reports:
            for st in rep["streams"]:
                h, a = st["http"], st["archive"]
                if h and a and h["host"] in dests:
                    recs = [m["records"] for m in a["members"] if "records" in m]
                    gap = None if not egress else round((parse_time_ms(st["first_time_utc"]) - min(egress)) / 1000.0, 1)
                    v["facts"]["exfil"] = {"stream": st["stream"], "bytes": a["size_bytes"], "files": len(a["members"]),
                                           "records": sum(recs) if recs else None, "sha256": a["sha256"],
                                           "status": st["completeness"]["status"], "seconds_from_logged_egress": gap}
                    break
            if "exfil" in v["facts"]:
                break


def run(input_dir, out_dir, changes_path=None, reference=None, tolerance_s=30, window_s=120):
    t0 = time.time()
    os.makedirs(out_dir, exist_ok=True)
    events, quarantine, duplicates, acct = ingest.load_dir(input_dir)
    skew = skewmod.infer_skew(events, tolerance_s, reference)
    skewmod.apply_skew(events, skew)
    events.sort(key=lambda e: e.key())
    verdicts = detect.detect_all(events, load_changes(changes_path), window_s=window_s)
    reports = []
    for n in sorted(os.listdir(input_dir)):
        if n.lower().endswith(".pcap"):
            with open(os.path.join(input_dir, n), "rb") as f:
                rep, _blobs = pcap.analyze(f.read(), n)  # payloads stay in memory; nothing is written to disk
            reports.append(rep)
    _link_exfil(verdicts, reports)
    for v in verdicts:
        v["explanation"] = explain.narrate(v)
    summary = {"verdicts": verdicts, "skew": skew, "row_accounting": acct, "pcap": reports}

    _csv(os.path.join(out_dir, "timeline.csv"), TIMELINE_COLS,
         [[fmt_ms(e.ts_ms), fmt_ms(e.raw_ts_ms), e.source, e.host, e.actor, e.event, e.image, e.parent,
           e.src_ip, e.dst, e.dst_port, e.corr, e.raw_file, e.raw_line, e.raw_sha] for e in events])
    _dump(os.path.join(out_dir, "skew-report.json"), skew)
    _dump(os.path.join(out_dir, "verdicts.json"), verdicts)
    _dump(os.path.join(out_dir, "quarantine.json"),
          {"quarantined": sorted(quarantine, key=lambda q: (q["source"], q["raw_line"])),
           "duplicates": sorted(duplicates, key=lambda d: (d["source"], d["raw_line"]))})
    _dump(os.path.join(out_dir, "row-accounting.json"), acct)
    if reports:
        _dump(os.path.join(out_dir, "exfil-analysis.json"), reports)
    _csv(os.path.join(out_dir, "evidence-index.csv"),
         ["claim_id", "verdict_id", "rule", "status", "stage", "source", "raw_file", "raw_line", "raw_sha256"],
         [[f"{v['id']}-E{i:02d}", v["id"], v["rule"], v["status"], e["stage"], e["source"], e["raw_file"],
           e["raw_line"], e["raw_sha256"]] for v in verdicts for i, e in enumerate(v["evidence"], 1)])
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(report.render(summary))
    with open(os.path.join(out_dir, "viewer.html"), "w", encoding="utf-8", newline="\n") as f:
        f.write(viewer.render(summary))
    _dump(os.path.join(out_dir, "run-metrics.json"),
          {"wall_seconds": round(time.time() - t0, 3), "python": sys.version.split()[0],
           "events_loaded": len(events), "peak_memory_mb": _peak_mb()})
    names = sorted(n for n in os.listdir(out_dir) if n not in UNHASHED and os.path.isfile(os.path.join(out_dir, n)))
    with open(os.path.join(out_dir, "manifest.sha256"), "w", encoding="utf-8", newline="\n") as f:
        for n in names:
            f.write(f"{sha256_file(os.path.join(out_dir, n))}  {n}\n")
    return summary


def verify(input_dir, changes_path=None, reference=None):
    """Build twice into separate directories; outputs must be byte-identical."""
    with tempfile.TemporaryDirectory() as tmp:
        a, b = os.path.join(tmp, "a"), os.path.join(tmp, "b")
        run(input_dir, a, changes_path, reference)
        run(input_dir, b, changes_path, reference)
        ma = open(os.path.join(a, "manifest.sha256")).read()
        mb = open(os.path.join(b, "manifest.sha256")).read()
        return ma == mb, ma
