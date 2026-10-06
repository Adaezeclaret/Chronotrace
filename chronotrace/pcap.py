"""Pure-standard-library packet-capture analysis: what data actually left the network?

Carries over the idea from my Stage 9 `archive.py` (reassemble TCP flows, order by sequence number,
pull a ZIP out of an HTTP POST body) and removes its scapy dependency. New here: retransmission
and overlap handling, gap detection, sequence wrap-around, and a stated completeness verdict
(Content-Length match + zip directory + CRC check) instead of assuming the transfer was whole.
Members are listed, never extracted to disk."""
import hashlib
import io
import re
import struct
import zipfile
import zlib

from .util import fmt_ms

MAX_TESTZIP_BYTES = 256 * 1024 * 1024


class PcapError(ValueError):
    pass


def read_pcap(data):
    """Classic libpcap only (micro or nanosecond, either byte order)."""
    if len(data) < 24:
        raise PcapError("file too short for a pcap header")
    m = data[:4]
    if m in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end, nano = "<", m[0] == 0x4D
    elif m in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end, nano = ">", m[3] == 0x4D
    else:
        raise PcapError("not a classic pcap file (bad magic number)")
    network = struct.unpack(end + "HHiIII", data[4:24])[5]
    pos, idx, out, notes = 24, 0, [], []
    while pos + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(end + "IIII", data[pos:pos + 16])
        pos += 16
        if pos + incl > len(data):
            notes.append(f"capture truncated inside packet {idx + 1}")
            break
        idx += 1
        ms = sec * 1000 + (frac // 1_000_000 if nano else frac // 1000)
        out.append((idx, ms, data[pos:pos + incl]))
        pos += incl
    if pos < len(data) and not notes:
        notes.append("trailing bytes after the last complete packet")
    return out, network, notes


def _tcp(frame, network):
    if network == 1:
        if len(frame) < 14:
            return None
        eth, off = struct.unpack("!H", frame[12:14])[0], 14
        while eth == 0x8100 and len(frame) >= off + 4:
            eth, off = struct.unpack("!H", frame[off + 2:off + 4])[0], off + 4
        if eth != 0x0800:
            return None
        ip = frame[off:]
    elif network in (12, 14, 101):
        ip = frame
    else:
        return None
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl, proto = (ip[0] & 15) * 4, ip[9]
    if proto != 6 or ihl < 20 or len(ip) < ihl + 20:
        return None
    if struct.unpack("!H", ip[6:8])[0] & 0x3FFF:
        return None  # IP fragment: unsupported, skipped
    total = struct.unpack("!H", ip[2:4])[0]
    body = ip[ihl:total] if ihl <= total <= len(ip) else ip[ihl:]
    if len(body) < 20:
        return None
    sport, dport, seq, _ack, of = struct.unpack("!HHIIH", body[:14])
    doff = (of >> 12) * 4
    if doff < 20 or len(body) < doff:
        return None
    return {"src": ".".join(map(str, ip[12:16])), "dst": ".".join(map(str, ip[16:20])),
            "sport": sport, "dport": dport, "seq": seq, "flags": of & 0x3F, "payload": body[doff:]}


def _reassemble(segs):
    """Rebuild one direction of a TCP flow. Returns (bytes, gaps, retransmits, conflicts, bytes_after_gap)."""
    syn = [s for s in segs if s["flags"] & 0x02]
    pay = [s for s in segs if s["payload"]]
    if not pay:
        return b"", [], 0, 0, 0
    base = (syn[0]["seq"] + 1) & 0xFFFFFFFF if syn else min(s["seq"] for s in pay)
    for s in pay:
        s["rel"] = (s["seq"] - base) & 0xFFFFFFFF
    buf, gaps, retx, conflicts, after = bytearray(), [], 0, 0, 0
    for s in sorted(pay, key=lambda s: (s["rel"], s["idx"])):
        rel, p = s["rel"], s["payload"]
        if gaps:
            after += len(p)
        elif rel > len(buf):
            gaps.append({"offset": len(buf), "length": rel - len(buf)})
            after += len(p)
        elif rel < len(buf):
            retx += 1
            ov = min(len(buf) - rel, len(p))
            if bytes(buf[rel:rel + ov]) != p[:ov]:
                conflicts += 1
            buf += p[ov:]
        else:
            buf += p
    return bytes(buf), gaps, retx, conflicts, after


def _http(stream):
    if not re.match(rb"(GET|POST|PUT|PATCH) ", stream):
        return None, stream
    he = stream.find(b"\r\n\r\n")
    if he == -1:
        return None, stream
    lines = stream[:he].decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    hdr = {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:] if ":" in l)}
    cl = hdr.get("content-length")
    return ({"method": parts[0], "path": parts[1] if len(parts) > 1 else "",
             "host": hdr.get("host", "").split(":")[0].lower(),
             "content_length": int(cl) if cl and cl.isdigit() else None,
             "body_bytes": len(stream) - he - 4}, stream[he + 4:])


def _zip(body):
    start = body.find(b"PK\x03\x04")
    if start < 0:
        return None, None
    z = body[start:]
    facts = {"sha256": hashlib.sha256(z).hexdigest(), "size_bytes": len(z), "opens": False,
             "crc_clean": False, "members": []}
    try:
        zf = zipfile.ZipFile(io.BytesIO(z))
    except (zipfile.BadZipFile, ValueError, OSError):
        return facts, z
    facts["opens"] = True
    try:
        for i in zf.infolist():
            m = {"name": i.filename, "size": i.file_size, "crc32": f"{i.CRC:08x}"}
            if i.filename.lower().endswith(".csv") and i.file_size <= 64 * 1024 * 1024:
                m["records"] = max(0, len(zf.read(i).splitlines()) - 1)  # counted, never written to disk
            facts["members"].append(m)
        if sum(i.file_size for i in zf.infolist()) <= MAX_TESTZIP_BYTES:
            facts["crc_clean"] = zf.testzip() is None
    except (zipfile.BadZipFile, zlib.error, NotImplementedError, RuntimeError, EOFError, ValueError, OSError):
        # A central directory can exist while the data it points to is missing (e.g. one half of a split archive).
        facts["opens"], facts["crc_clean"] = False, False
    return facts, z


def _verdict(gaps, conflicts, http, body_len, arch):
    why = []
    if gaps:
        why.append(f"{len(gaps)} missing byte range(s) in the captured stream")
    if conflicts:
        why.append(f"{conflicts} retransmission(s) disagreed with earlier bytes")
    if http and http["content_length"] is not None:
        if body_len < http["content_length"]:
            why.append(f"received {body_len} of {http['content_length']} declared bytes")
        elif body_len > http["content_length"]:
            why.append("extra bytes after the declared length")
    if arch is None:
        return {"status": "no_archive", "reasons": ["no ZIP signature found in the transferred data"]}
    if not arch["opens"]:
        why.append("archive does not open (central directory missing or damaged)")
    elif not arch["crc_clean"]:
        why.append("archive member checksums do not verify")
    if why:
        return {"status": "incomplete", "reasons": why}
    declared = (http or {}).get("content_length")
    if declared is None:
        return {"status": "unverified", "reasons": ["no Content-Length to compare; archive itself is intact"]}
    return {"status": "complete", "reasons": ["byte count matches the declared length, no gaps, archive "
                                               "directory present and every member checksum verifies"]}


def analyze(data, name="capture.pcap"):
    packets, network, notes = read_pcap(data)
    flows = {}
    for idx, ts, frame in packets:
        s = _tcp(frame, network)
        if s:
            s.update(idx=idx, ts=ts)
            flows.setdefault(tuple(sorted([(s["src"], s["sport"]), (s["dst"], s["dport"])])), []).append(s)
    streams, blobs, bodies = [], {}, []
    for n, key in enumerate(sorted(flows), 1):
        fl = flows[key]
        syn = [s for s in fl if s["flags"] & 0x02 and not s["flags"] & 0x10]
        first = syn[0] if syn else fl[0]
        client = (first["src"], first["sport"])
        server = key[0] if key[1] == client else key[1]
        stream, gaps, retx, conf, after = _reassemble([s for s in fl if (s["src"], s["sport"]) == client])
        http, body = _http(stream)
        arch, zbytes = _zip(body)
        sid = f"C{n}"
        streams.append({"stream": sid, "client": f"{client[0]}:{client[1]}", "server": f"{server[0]}:{server[1]}",
                        "packets": len(fl), "first_packet": min(s["idx"] for s in fl),
                        "first_time_utc": fmt_ms(min(s["ts"] for s in fl)),
                        "client_payload_bytes": len(stream), "retransmitted_segments": retx,
                        "conflicting_retransmissions": conf, "gaps": gaps, "bytes_after_gap": after,
                        "http": http, "archive": arch,
                        "completeness": _verdict(gaps, conf, http, len(body), arch)})
        if zbytes is not None:
            blobs[sid] = zbytes
        if stream:
            bodies.append((min(s["ts"] for s in fl), sid, body, http, bool(gaps)))
    split = None
    if not any(s["archive"] and s["archive"]["opens"] for s in streams) and len(bodies) >= 2:
        bodies.sort(key=lambda b: (b[0], b[1]))
        joined = b"".join(b[2] for b in bodies)
        arch, zbytes = _zip(joined)
        if arch and arch["opens"]:
            declared = [b[3]["content_length"] if b[3] else None for b in bodies]
            ok_len = None not in declared and sum(declared) == len(joined)
            v = _verdict([{"o": 0}] if any(b[4] for b in bodies) else [], 0, None, len(joined), arch)
            if v["status"] == "unverified" and ok_len:
                v = {"status": "complete", "reasons": ["declared lengths of all streams add up to the joined size, "
                                                        "archive directory present and every checksum verifies"]}
            elif v["status"] == "unverified":
                v["reasons"] = ["streams were joined in time order and give an intact archive, but no declared "
                                "lengths confirm that no stream is missing"]
            split = {"streams": [b[1] for b in bodies], "archive": arch, "completeness": v}
            blobs["split"] = zbytes
    return {"capture": name, "capture_sha256": hashlib.sha256(data).hexdigest(), "notes": notes,
            "streams": streams, "split_archive": split}, blobs
