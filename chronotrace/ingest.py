"""Parse JSONL logs of several schema versions into Events. Nothing is silently dropped:
every non-blank line is loaded, quarantined (with reason) or recorded as a duplicate."""
import json
import os
import re
import sys

from .models import Event
from .util import parse_time_ms, sha256_text

TIME_KEYS = ("timestamp", "event_time", "time", "ts", "@timestamp")
FIELD_KEYS = {
    "host": ("host", "device", "hostname", "computer"),
    "actor": ("user", "username", "identity", "actor", "account"),
    "event": ("event", "event_name", "action", "result"),
    "image": ("image", "process", "exe", "process_name"),
    "parent": ("parent_image", "parent", "parent_process"),
    "cmd": ("command_line", "cmdline", "command", "script"),
    "src_ip": ("src_ip", "client_ip", "source_ip"),
    "dst": ("dst", "dst_ip", "destination", "dest"),
    "dst_port": ("dst_port", "port", "dest_port"),
    "corr": ("correlation_id", "corr_id", "anchor_id"),
}
_URL = re.compile(r"https?://([A-Za-z0-9._\-]+|\[[0-9a-fA-F:]+\])(?::(\d+))?", re.I)


def _s(v):
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True)
    return str(v).strip()


def _pick(rec, keys):
    for k in keys:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
    return None


def _flatten(rec):
    """v3 schema nests the payload under 'record' with a top-level time."""
    inner = rec.get("record")
    if isinstance(inner, dict):
        merged = dict(inner)
        for k, v in rec.items():
            if k != "record" and k not in merged:
                merged[k] = v
        return merged
    return rec


def parse_file(path, source, display_name):
    events, quarantine, duplicates = [], [], []
    seen = {}
    total = 0
    with open(path, "rb") as f:
        for n, raw in enumerate(f, 1):
            text = raw.decode("utf-8", "replace").rstrip("\r\n")
            if not text.strip():
                continue
            total += 1
            sha = sha256_text(text)

            def quar(reason):
                quarantine.append({"source": source, "raw_file": display_name, "raw_line": n,
                                   "raw_sha256": sha, "reason": reason})

            try:
                rec = json.loads(text)
            except ValueError:
                quar("malformed_json")
                continue
            if not isinstance(rec, dict):
                quar("not_a_json_object")
                continue
            rec = _flatten(rec)
            ts = parse_time_ms(_pick(rec, TIME_KEYS))
            if ts is None:
                quar("missing_or_unparseable_time")
                continue
            canon = sha256_text(json.dumps(rec, sort_keys=True))
            if canon in seen:
                duplicates.append({"source": source, "raw_file": display_name, "raw_line": n,
                                   "duplicate_of_line": seen[canon]})
                continue
            seen[canon] = n
            vals = {k: _s(_pick(rec, keys)) for k, keys in FIELD_KEYS.items()}
            for k in ("host", "actor", "image", "parent", "src_ip", "dst", "dst_port"):
                vals[k] = sys.intern(vals[k])  # millions of rows repeat the same few values; store each once
            vals["event"] = vals["event"].lower()
            if vals["image"] and not vals["event"]:
                vals["event"] = "process_start"
            if not vals["dst"]:
                m = _URL.search(vals["cmd"])
                if m:
                    vals["dst"] = m.group(1).strip("[]")
                    vals["dst_port"] = vals["dst_port"] or (m.group(2) or "")
            events.append(Event(source=source, raw_file=display_name, raw_line=n, raw_sha=sha,
                                raw_ts_ms=ts, ts_ms=ts, **vals))
    return events, quarantine, duplicates, total


def load_dir(input_dir):
    files = sorted(f for f in os.listdir(input_dir) if f.endswith(".jsonl"))
    if not files:
        raise FileNotFoundError(f"no .jsonl files in {input_dir}")
    events, quarantine, duplicates, acct = [], [], [], {}
    for fn in files:
        src = fn[:-len(".jsonl")]
        ev, q, d, total = parse_file(os.path.join(input_dir, fn), src, fn)
        if total != len(ev) + len(q) + len(d):
            raise RuntimeError(f"row accounting failed for {fn}")
        acct[src] = {"raw_rows": total, "loaded": len(ev), "quarantined": len(q), "duplicates": len(d)}
        events += ev
        quarantine += q
        duplicates += d
    return events, quarantine, duplicates, acct
