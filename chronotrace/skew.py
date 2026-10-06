"""Infer per-source clock offsets from cross-source anchors (events sharing a correlation_id).

Method: for each pair of sources, collect anchor deltas, reject outliers around the median,
estimate the pair's delta from the inliers, then solve a spanning tree of pair deltas. Extra
(non-tree) pairs are used as an independent cycle check. The reference clock defaults to the
median clock (the majority view); the odd clock out is the skewed one."""
from .util import human_duration


def _median(v):
    n = len(v)
    return v[n // 2] if n % 2 else (v[n // 2 - 1] + v[n // 2]) // 2


def infer_skew(events, tolerance_s=30, reference=None):
    tol = int(tolerance_s * 1000)
    sources = sorted({e.source for e in events})
    first = {}
    for e in events:
        if e.corr:
            d = first.setdefault(e.corr, {})
            if e.source not in d or e.raw_ts_ms < d[e.source]:
                d[e.source] = e.raw_ts_ms
    pairs = {}
    for corr in sorted(first):
        d = first[corr]
        ss = sorted(d)
        for i, a in enumerate(ss):
            for b in ss[i + 1:]:
                pairs.setdefault((a, b), []).append((corr, d[a] - d[b]))
    edges = {}
    for (a, b), lst in sorted(pairs.items()):
        med = _median(sorted(v for _, v in lst))
        inl = [(c, v) for c, v in lst if abs(v - med) <= tol] or list(lst)
        iv = sorted(v for _, v in inl)
        spread = (iv[-1] - iv[0]) / 1000.0
        agree = len(inl) >= 2 and spread <= tolerance_s
        edges[(a, b)] = {
            "a": a, "b": b, "delta_s": int(round(_median(iv) / 1000.0)),
            "anchors": len(lst), "inliers": len(inl), "spread_s": round(spread, 3),
            "rejected_anchors": sorted(c for c, v in lst if abs(v - med) > tol),
            "confidence": "high" if agree else "low"}
    adj = {s: [] for s in sources}
    for ed in edges.values():
        adj[ed["a"]].append((ed["b"], ed))
        adj[ed["b"]].append((ed["a"], ed))
    comps, seen = [], set()
    for s in sources:
        if s in seen:
            continue
        comp, stack = [], [s]
        seen.add(s)
        while stack:
            x = stack.pop()
            comp.append(x)
            for y, _ in adj[x]:
                if y not in seen:
                    seen.add(y)
                    stack.append(y)
        comps.append(sorted(comp))
    main = sorted(comps, key=lambda c: (-len(c), c))[0]
    base = main[0]
    # Prim-style spanning tree that always takes the best-supported link next (high confidence,
    # then most agreeing anchors), so weak single-anchor links are used only when nothing better exists.
    ahead, tree = {base: 0}, set()
    while True:
        cand = [(ed["confidence"] != "high", -ed["inliers"], x, y, ed)
                for x in sorted(ahead) for y, ed in adj[x] if y not in ahead]
        if not cand:
            break
        cand.sort(key=lambda c: c[:4])
        _, _, x, y, ed = cand[0]
        d = ed["delta_s"] if ed["a"] == x else -ed["delta_s"]  # d = ahead_x - ahead_y
        ahead[y] = ahead[x] - d
        tree.add((ed["a"], ed["b"]))
    residuals = [abs(ed["delta_s"] - (ahead[ed["a"]] - ahead[ed["b"]]))
                 for k, ed in sorted(edges.items()) if k not in tree]
    warnings = []
    if reference is not None:
        if reference not in main:
            raise ValueError(f"reference source '{reference}' has no anchors linking it to the other sources")
        ref, method = reference, "user"
    else:
        ref = sorted(main, key=lambda s: (ahead[s], s))[(len(main) - 1) // 2]
        method = "median-clock"
        if len(main) == 2:
            warnings.append("only two anchored sources: no majority, reference chosen arbitrarily; use --reference")
    tadj = {s: [] for s in main}
    for k in tree:
        tadj[k[0]].append((k[1], edges[k]["confidence"]))
        tadj[k[1]].append((k[0], edges[k]["confidence"]))
    path_conf, stack = {ref: "high"}, [ref]
    while stack:  # confidence of a source = weakest link on its tree path to the reference
        x = stack.pop()
        for y, c in sorted(tadj[x]):
            if y not in path_conf:
                path_conf[y] = "high" if path_conf[x] == "high" and c == "high" else "low"
                stack.append(y)
    out = {}
    for s in sources:
        if s not in main:
            out[s] = {"offset_seconds": 0, "status": "unanchored", "confidence": "none"}
            warnings.append(f"source '{s}' has no cross-source anchors; offset assumed 0")
            continue
        off = -(ahead[s] - ahead[ref])
        conf = "reference" if s == ref else path_conf[s]
        if conf == "low":
            warnings.append(f"source '{s}' offset rests on weakly supported anchors")
        out[s] = {"offset_seconds": off, "status": "reference" if s == ref else "anchored", "confidence": conf}
    for s, o in out.items():
        off = o["offset_seconds"]
        if off == 0:
            o["description"] = "no correction applied"
        elif off < 0:
            o["description"] = f"clock runs ahead of the reference by {human_duration(off)}; subtracted"
        else:
            o["description"] = f"clock runs behind the reference by {human_duration(off)}; added"
    if residuals and max(residuals) > tolerance_s:
        warnings.append(f"cycle check disagrees by {max(residuals)}s (> tolerance)")
    return {"reference": ref, "reference_method": method, "tolerance_s": tolerance_s,
            "sources": out, "pair_estimates": [edges[k] for k in sorted(edges)],
            "cycle_check_max_residual_s": max(residuals) if residuals else None,
            "warnings": sorted(set(warnings))}


def apply_skew(events, skew):
    off = {s: o["offset_seconds"] * 1000 for s, o in skew["sources"].items()}
    for e in events:
        e.ts_ms = e.raw_ts_ms + off.get(e.source, 0)
