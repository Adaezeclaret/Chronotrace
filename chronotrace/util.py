import hashlib
import re
from datetime import datetime, timedelta, timezone

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_FRAC = re.compile(r"\.(\d+)")
_NUM = re.compile(r"-?\d+(\.\d+)?")


def sha256_text(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_time_ms(v):
    """Parse ISO-8601 text or epoch seconds/millis into UTC epoch milliseconds (int). None if invalid."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        x = float(v)
        if x != x or x in (float("inf"), float("-inf")):
            return None
        if abs(x) > 1e11:
            x /= 1000.0
        return int(round(x * 1000))
    if not isinstance(v, str):
        return None
    s = v.strip()
    if not s:
        return None
    if _NUM.fullmatch(s):
        return parse_time_ms(float(s))
    if s[-1] in "Zz":
        s = s[:-1] + "+00:00"
    s = _FRAC.sub(lambda m: "." + (m.group(1) + "000000")[:6], s, count=1)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    d = dt - EPOCH
    return (d.days * 86400 + d.seconds) * 1000 + d.microseconds // 1000


def fmt_ms(ms):
    dt = EPOCH + timedelta(milliseconds=ms)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (dt.microsecond // 1000)


def human_time(ms):
    return fmt_ms(ms)[:19].replace("T", " ") + " UTC"


def human_duration(seconds):
    s = abs(int(seconds))
    d, r = divmod(s, 86400)
    h, r = divmod(r, 3600)
    m, sec = divmod(r, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if d or h:
        parts.append(f"{h}h")
    if d or h or m:
        parts.append(f"{m}m")
    parts.append(f"{sec}s")
    return " ".join(parts)
