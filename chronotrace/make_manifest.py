"""Create or check manifest.sha256 for this repository (standard library only).

    python tools/make_manifest.py           write manifest.sha256 (run this LAST, after every other edit)
    python tools/make_manifest.py --check   verify every file against the manifest

The manifest lists the SHA-256 of every file in the repository (sorted, forward-slash paths),
except generated or private folders and the manifest itself. Anyone can re-run --check to
confirm the repository was not altered after it was written."""
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = "manifest.sha256"
SKIP_DIRS = {".git", "__pycache__", "demo", "venv", ".venv", "node_modules"}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def repo_files():
    found = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in files:
            rel = os.path.relpath(os.path.join(base, name), ROOT).replace(os.sep, "/")
            if rel != MANIFEST:
                found.append(rel)
    return sorted(found)


def write():
    files = repo_files()
    with open(os.path.join(ROOT, MANIFEST), "w", encoding="utf-8", newline="\n") as f:
        for rel in files:
            f.write(f"{sha256_file(os.path.join(ROOT, rel))}  {rel}\n")
    print(f"wrote {MANIFEST}: {len(files)} files")
    return 0


def check():
    path = os.path.join(ROOT, MANIFEST)
    if not os.path.exists(path):
        print(f"{MANIFEST} not found; run without --check first")
        return 1
    listed, problems = {}, []
    with open(path, encoding="utf-8") as f:
        for line in f.read().splitlines():
            if line.strip():
                digest, rel = line.split("  ", 1)
                listed[rel] = digest
    for rel, digest in sorted(listed.items()):
        full = os.path.join(ROOT, rel)
        if not os.path.exists(full):
            problems.append(f"MISSING   {rel}")
        elif sha256_file(full) != digest:
            problems.append(f"CHANGED   {rel}")
    for rel in repo_files():
        if rel not in listed:
            problems.append(f"UNLISTED  {rel}")
    for p in problems:
        print(p)
    print(f"CHECK FAILED: {len(problems)} problem(s)" if problems else f"CHECK OK: {len(listed)} files match the manifest")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(check() if "--check" in sys.argv[1:] else write())
