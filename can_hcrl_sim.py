#!/usr/bin/env python3
"""Response-time analysis (RTA) AND trace-replay simulation of a PQC artifact (ML-KEM-512
public key, 800 B, T_a = 1 s) sent over CAN CC / CAN FD / CAN XL, with the background traffic
taken from a REAL vehicle trace instead of the synthetic set of can_rta_sim.py.

Data source: HCRL Car-Hacking dataset, file normal_run_data.txt (Song, Woo, Kim, 2020), classical
CAN recorded on a real vehicle (~988k frames, ~506 s, 27 IDs). Download:
  https://ocslab.hksecurity.net/Datasets/car-hacking-dataset
The dataset is NOT distributed here; pass its path with --trace (default: ./normal_run_data.txt).

Message set (one message per CAN ID): payload n = most frequent DLC of the ID; period T = median
inter-arrival time of the ID, snapped to the nearest of {0.01,0.02,0.05,0.1,1.0} s only if within 5%;
deadline D = T; priority = real arbitration (lower numeric ID = higher priority, NOT rate-monotonic).
There is NO synthetic bulk frame: the background is only the real messages.

Configurations (artifact = 800 B, T_a = 1 s; arbitration phase 500 kbit/s):
  CC-500k : classical CAN, no data phase; 8 B frames, N = ceil(800/8) = 100, Cf = cc_ctime(8)
  FD-2M   : CAN FD 500k/2M, N = ceil(800/64) = 13 frames of 64 B
  XL-2M   : CAN XL 500k/2M, one 800 B frame
  XL-10M  : CAN XL 500k/10M, one 800 B frame
Positions: high (above all IDs, index 0), mid (index 27//2 = 13, i.e. between sorted positions 12
and 13), low (below all, index 27); same convention as can_rta_sim.scenario().

Assumptions: median periods, D = T; no ISO-TP/segmentation header bytes (frame-count model of the
paper); all fragments of one artifact released at the same instant; background replayed at the
ORIGINAL trace timestamps (relative to the first frame) with the actual DLC of each trace line;
the trace is classical CAN, mapped onto FD/XL frames with the SAME payload (no re-packing, bus
load therefore differs per bus type); artifact releases phi + j*1.0 s, phi = r/runs (20 runs ->
phi = r*0.05 s), j = 0.. while release < last trace timestamp. Fragments of one artifact are FIFO.
Simulator: discrete-event, non-preemptive fixed-priority bus; response = completion - release.
Comparisons use a 1e-9 s tolerance. The trace violates the RTA assumptions (logger jitter, bursts
beyond the median period), so a frame's observed response may exceed its RTA bound; such frames are
COUNTED (columns viol_*), not hidden.

Frame time of classical CAN 2.0A (cc_ctime): worst-case bits = 47 + 8n + floor((34 + 8n - 1)/4),
C = bits / 500e3.

Usage: python3 can_hcrl_sim.py --trace normal_run_data.txt --runs 20 --out results_hcrl.json
"""
import math, heapq, json, csv, argparse, time, sys, os
from collections import Counter, defaultdict, deque
from multiprocessing import Pool

import can_rta_sim as R

TAU = R.TAU_NOM
INF = float("inf")
TOL = 1e-9
SHIFT = 21                      # heap key = (id_index << SHIFT) | frame_index (frames < 2^21)
CONFIGS = [  # name, kind, rdat, art payload, N
    ("CC-500k", "CC", None, 8, 100),
    ("FD-2M", "FD", 2e6, 64, 13),
    ("XL-2M", "XL", 2e6, 800, 1),
    ("XL-10M", "XL", 10e6, 800, 1),
]
POSITIONS = ("high", "mid", "low")
ART_BYTES, ART_T = 800, 1.0


def cc_ctime(n):
    """Worst-case classical CAN 2.0A frame time at 500 kbit/s:
    bits = 47 + 8n + floor((34 + 8n - 1)/4); C = bits / 500e3."""
    bits = 47 + 8*n + (34 + 8*n - 1)//4
    return bits / TAU


def frame_time(kind, n, rdat):
    return cc_ctime(n) if kind == "CC" else R.ctime(kind, n, rdat)


def parse_trace(path):
    ts, ids, dlcs = [], [], []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.split()
            if len(p) < 7 or p[0] != "Timestamp:":
                continue
            ts.append(float(p[1])); ids.append(int(p[3], 16)); dlcs.append(int(p[6]))
    order = sorted(range(len(ts)), key=ts.__getitem__)   # stable; trace should already be sorted
    if order != list(range(len(ts))):
        ts = [ts[i] for i in order]; ids = [ids[i] for i in order]; dlcs = [dlcs[i] for i in order]
    t0 = ts[0]
    rel = [x - t0 for x in ts]
    return rel, ids, dlcs


def median(v):
    v = sorted(v); m = len(v)
    return v[m//2] if m % 2 else 0.5*(v[m//2 - 1] + v[m//2])


def build_set(rel, ids, dlcs):
    """Per-ID message description (sorted by ID) and per-frame ID index."""
    byid = defaultdict(list)
    for i, x in enumerate(ids):
        byid[x].append(i)
    idlist = sorted(byid)
    info = []
    for x in idlist:
        ix = byid[x]
        n = Counter(dlcs[i] for i in ix).most_common(1)[0][0]
        gaps = [rel[b] - rel[a] for a, b in zip(ix, ix[1:])]
        T = median(gaps)
        near = min((0.01, 0.02, 0.05, 0.1, 1.0), key=lambda c: abs(c - T))
        Tr = near if abs(near - T)/near <= 0.05 else T
        info.append(dict(id=x, n=n, T_median=T, T=Tr, count=len(ix)))
    pos = {x: k for k, x in enumerate(idlist)}
    kid = [pos[x] for x in ids]
    return info, kid


# ---------------- analytical part ----------------
def analytic(info, cfg, pos_name):
    name, kind, rdat, apay, N = cfg
    msgs = [dict(T=m["T"], C=frame_time(kind, m["n"], rdat), n=m["n"]) for m in info]
    nb = len(msgs)
    if kind == "XL":
        Cf = R.ctime("XL", ART_BYTES, rdat)
    else:
        Cf = frame_time(kind, apay, rdat)
    art = dict(T=ART_T, N=N, Cf=Cf)
    pos = {"high": 0, "mid": nb//2, "low": nb}[pos_name]
    bound, _ = R.rta(msgs, art, pos)
    base, _ = R.rta(msgs, None, pos)
    D = [m["T"] for m in msgs]
    miss = [k for k in range(nb) if bound[k] > D[k] + TOL]
    miss0 = [k for k in range(nb) if base[k] > D[k] + TOL]
    return dict(msgs=msgs, art=art, pos=pos, bound=bound, base=base, D=D,
                load=sum(m["C"]/m["T"] for m in msgs), miss=miss, miss0=miss0,
                worst_ratio=max(bound[k]/D[k] for k in range(nb)),
                worst_ratio0=max(base[k]/D[k] for k in range(nb)))


# ---------------- simulation ----------------
_G = {}


def _init(rel, kid, dlcs):
    _G["rel"] = rel; _G["kid"] = kid; _G["dlc"] = dlcs
    _G["tabs"] = {}


def _tab(kind, rdat):
    k = (kind, rdat)
    if k not in _G["tabs"]:
        nid = max(_G["kid"]) + 1
        t = [0.0]*(nid*9)
        for i in range(len(_G["kid"])):      # every (id, dlc) combination present in the trace
            key = _G["kid"][i]*9 + _G["dlc"][i]
            if t[key] == 0.0:
                t[key] = frame_time(kind, _G["dlc"][i], rdat)
        key_of = [kk*9 + d for kk, d in zip(_G["kid"], _G["dlc"])]
        _G["tabs"][k] = (t, key_of)
    return _G["tabs"][k]


def simulate(job):
    """One replay run. job = (cfg_index, pos_name or None, phi, run_id, D, B, art_key, Cf, N)"""
    ci, pos_name, phi, rid, D, B, art_key, Cf, N = job
    name, kind, rdat = CONFIGS[ci][:3]
    rel, kid = _G["rel"], _G["kid"]
    tab, key_of = _tab(kind, rdat)
    n = len(rel); t_end = rel[-1]
    use_art = pos_name is not None
    t = 0.0; i = 0; heap = []; push = heapq.heappush; pop = heapq.heappop
    artq = deque(); j = 0
    next_ar = phi if use_art else INF
    miss = viol = 0; miss_ids = set(); maxratio = 0.0
    art_done = []
    while True:
        while i < n and rel[i] <= t:
            push(heap, (kid[i] << SHIFT) | i); i += 1
        while next_ar <= t:
            artq.append([next_ar, N]); j += 1
            next_ar = phi + j*ART_T
            if next_ar >= t_end: next_ar = INF
        if not heap and not artq:
            nxt = rel[i] if i < n else INF
            if next_ar < nxt: nxt = next_ar
            if nxt == INF: break
            t = nxt; continue
        if artq and (not heap or art_key < (heap[0] >> SHIFT)):
            a = artq[0]; t += Cf; a[1] -= 1
            if a[1] == 0:
                art_done.append(t - a[0]); artq.popleft()
        else:
            v = pop(heap); fi = v & ((1 << SHIFT) - 1); k = v >> SHIFT
            t += tab[key_of[fi]]
            r = t - rel[fi]
            rr = r / D[k]
            if rr > maxratio: maxratio = rr
            if r > D[k] + TOL: miss += 1; miss_ids.add(k)
            if r > B[k] + TOL: viol += 1
    return dict(ci=ci, pos=pos_name, rid=rid, miss=miss, miss_ids=sorted(miss_ids),
                maxratio=maxratio, viol=viol, art_done=art_done)


def pct(v, p):
    v = sorted(v)
    return v[min(len(v)-1, int(p*len(v)))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", default="normal_run_data.txt")
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--out", default="results_hcrl.json")
    a = ap.parse_args()
    t0 = time.time()
    rel, ids, dlcs = parse_trace(a.trace)
    info, kid = build_set(rel, ids, dlcs)
    nfr = len(rel)
    print(f"trace: {nfr} frames, {rel[-1]:.3f} s, {len(info)} IDs, DLC counts {dict(Counter(dlcs))}")
    for m in info:
        print(f"  ID {m['id']:04x} n={m['n']} T_median={m['T_median']*1e3:9.4f} ms  T_used={m['T']*1e3:9.4f} ms  frames={m['count']}")

    # analytical + job list
    an = {}
    jobs = []
    for ci, cfg in enumerate(CONFIGS):
        for pn in POSITIONS:
            A = an[(ci, pn)] = analytic(info, cfg, pn)
            art_key = A["pos"] - 0.5
            B = [A["bound"][k] for k in range(len(info))]
            for r in range(a.runs):
                jobs.append((ci, pn, r/a.runs, r, A["D"], B, art_key, A["art"]["Cf"], A["art"]["N"]))
        A0 = analytic(info, cfg, "mid")
        an[(ci, None)] = A0
        jobs.append((ci, None, 0.0, -1, A0["D"], [A0["base"][k] for k in range(len(info))], 0, 0.0, 0))
    jobs.sort(key=lambda j: -(j[1] is not None))
    print(f"{len(jobs)} simulation jobs ({a.runs} runs x 12 scenarios + 4 baselines)", flush=True)
    with Pool(initializer=_init, initargs=(rel, kid, dlcs)) as p:
        res = p.map(simulate, jobs, chunksize=1)
    grp = defaultdict(list)
    for r in res:
        grp[(r["ci"], r["pos"])].append(r)

    rows = []
    for ci, cfg in enumerate(CONFIGS):
        base = grp[(ci, None)][0]
        for pn in POSITIONS:
            A = an[(ci, pn)]; runs = grp[(ci, pn)]
            allart = [x for r in runs for x in r["art_done"]]
            ids_ever = set(k for r in runs for k in r["miss_ids"])
            bound_a = A["bound"]["ART"]
            rows.append(dict(
                config=cfg[0], position=pn, n_msgs=len(info), bg_load=round(A["load"], 4),
                art_frames=A["art"]["N"], art_Cf_ms=A["art"]["Cf"]*1e3,
                bound_art_ms=bound_a*1e3,
                rta_miss_with=len(A["miss"]), rta_miss_base=len(A["miss0"]),
                worst_bound_over_D=A["worst_ratio"], worst_bound_over_D_base=A["worst_ratio0"],
                frames_total=nfr,
                sim_miss_max_run=max(r["miss"] for r in runs), sim_miss_sum=sum(r["miss"] for r in runs),
                sim_miss_base=base["miss"],
                sim_ids_missing=len(ids_ever), sim_ids_missing_base=len(base["miss_ids"]),
                sim_max_resp_over_D=max(r["maxratio"] for r in runs), sim_max_resp_over_D_base=base["maxratio"],
                art_releases=len(allart),
                sim_art_median_ms=median(allart)*1e3, sim_art_p99_ms=pct(allart, 0.99)*1e3,
                sim_art_max_ms=max(allart)*1e3, sim_art_max_over_bound=max(allart)/bound_a,
                art_bound_exceeded=max(allart) > bound_a + TOL,
                viol_rta_max_run=max(r["viol"] for r in runs), viol_rta_sum=sum(r["viol"] for r in runs),
                viol_rta_base=base["viol"], runs=a.runs))
    el = time.time() - t0
    out = dict(trace=os.path.basename(a.trace), frames=nfr, duration_s=rel[-1], runs=a.runs,
               runtime_s=el, messages=info, rows=rows)
    json.dump(out, open(a.out, "w"), indent=1)
    csvp = os.path.splitext(a.out)[0] + ".csv"
    with open(csvp, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

    hdr = ("config pos  load  Cf_ms  bound_ms | RTAmiss w/ base worst_R/D | simMiss max sum base ids | "
           "maxResp/D | art med p99 max (ms) max/bnd | violRTA max sum base")
    print(hdr)
    for r in rows:
        print(f"{r['config']:8s} {r['position']:4s} {r['bg_load']:.3f} {r['art_Cf_ms']:.4f} {r['bound_art_ms']:8.3f} | "
              f"{r['rta_miss_with']:2d} {r['rta_miss_base']:2d} {r['worst_bound_over_D']:.3f} | "
              f"{r['sim_miss_max_run']:6d} {r['sim_miss_sum']:7d} {r['sim_miss_base']:6d} {r['sim_ids_missing']:2d}/{r['sim_ids_missing_base']:2d} | "
              f"{r['sim_max_resp_over_D']:.3f} | {r['sim_art_median_ms']:8.3f} {r['sim_art_p99_ms']:8.3f} {r['sim_art_max_ms']:8.3f} "
              f"{r['sim_art_max_over_bound']:.3f}{'!' if r['art_bound_exceeded'] else ' '} | "
              f"{r['viol_rta_max_run']:6d} {r['viol_rta_sum']:7d} {r['viol_rta_base']:6d}")
    print(f"runtime: {el:.1f} s; wrote {a.out} and {csvp}")


if __name__ == "__main__":
    main()
