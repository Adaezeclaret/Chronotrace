import argparse
import sys

from . import build, synth


def main(argv=None):
    p = argparse.ArgumentParser(prog="chronotrace")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("synth", help="write deterministic synthetic demo logs")
    s.add_argument("--out", required=True)
    s.add_argument("--scale", type=int, default=1, help="multiply background noise (for benchmarking)")
    for name in ("build", "verify"):
        b = sub.add_parser(name)
        b.add_argument("--input", required=True)
        b.add_argument("--changes")
        b.add_argument("--reference", help="force the reference clock source (default: median clock)")
        if name == "build":
            b.add_argument("--out", required=True)
            b.add_argument("--tolerance", type=float, default=30.0, help="anchor agreement tolerance, seconds")
            b.add_argument("--window", type=float, default=120.0, help="attack-chain window, seconds")
    a = p.parse_args(argv)
    if a.cmd == "synth":
        synth.make(a.out, scale=a.scale)
        print(f"synthetic logs written to {a.out}")
        return 0
    if a.cmd == "build":
        sm = build.run(a.input, a.out, a.changes, a.reference, a.tolerance, a.window)
        al = sum(v["status"] == "ALERT" for v in sm["verdicts"])
        print(f"built {a.out}: {al} alert(s), {len(sm['verdicts']) - al} rejected look-alike(s)")
        return 0
    ok, manifest = build.verify(a.input, a.changes, a.reference)
    print("VERIFY OK: two clean builds are byte-identical" if ok else "VERIFY FAILED: builds differ")
    print(manifest, end="")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
