#!/usr/bin/env python3
"""Response-time analysis (Tindell/Davis, extended with a fragmented PQC artifact,
Eqs. (1)-(3) of the manuscript) versus a discrete-event simulation of a CAN FD / CAN XL bus.

IMPORTANT: the background traffic is SYNTHETIC (parametrised by bus load); it is not a
measured vehicle trace. The experiment checks that the analytical bound is not
exceeded by the simulation; it does not measure a real bus.

Frame bit counts: CAN FD n>16 B and CAN XL as in Section V-A of the manuscript.
For CAN FD n<=16 B the same structure with a 17-bit CRC (6 fixed stuff bits) is used:
  N_dat = 5 + 8n + 4 + 17 + 6 + s,  s = floor((17+8n)/4) - 4   (reproduces R_i = 0.53 ms of Sec. V-C)
Usage: python3 can_rta_sim.py [--runs 40] [--horizon 5] [--out results.json]
"""
import math, heapq, random, json, argparse
from multiprocessing import Pool

TAU_NOM = 500e3

def fd_bits(n):
    if n > 16:
        s = (21 + 8*n)//4 - 4
        return 34, 5 + 8*n + 4 + 21 + 7 + s
    s = (17 + 8*n)//4 - 4
    return 34, 5 + 8*n + 4 + 17 + 6 + s

def xl_bits(n):
    L = 8*n + 108
    return 37, 3 + L + L//10 + 4

def ctime(kind, n, rdat):
    nn, nd = (fd_bits(n) if kind == "FD" else xl_bits(n))
    return nn/TAU_NOM + nd/rdat

def make_bg(kind, rdat, target_load, seed, bulk_n=64):
    """Synthetic background: 8 B messages, periods drawn from {5,10,20,50,100} ms
    (range cited in Sec. V-A from [69]); rate-monotonic priorities; plus ONE lowest-priority
    bulk frame (T=100 ms; 64 B, or up to 2048 B on CAN XL, to set the blocking term). Messages are added until target_load is reached."""
    rng = random.Random(seed)
    c8 = ctime(kind, 8, rdat); c64 = ctime(kind, bulk_n, rdat)
    msgs = []
    load = c64/0.1
    while load < target_load:
        T = rng.choice([0.005, 0.01, 0.02, 0.05, 0.1])
        msgs.append(dict(T=T, C=c8, n=8)); load += c8/T
    msgs.sort(key=lambda m: m["T"])
    bulk = [dict(T=0.1, C=c64, n=bulk_n)]
    return msgs + bulk, load

def rta(msgs, art, prio_pos, blocking_extra=0.0, tau=1/TAU_NOM):
    """Return (R_bound per message index, artifact completion bound).
    msgs: ordered by priority (index 0 = highest). art: dict(T,Cf,N) placed so that it has
    higher priority than msgs[prio_pos:] and lower than msgs[:prio_pos]."""
    items = []
    for i, m in enumerate(msgs):
        if i == prio_pos and art: items.append(("ART", art))
        items.append(("M", dict(m, idx=i)))
    if prio_pos >= len(msgs) and art: items.append(("ART", art))
    def Cmax_lp(pos):
        c = blocking_extra
        for kind, it in items[pos+1:]:
            c = max(c, it["Cf"] if kind == "ART" else it["C"])
        return c
    res = {}; resB = {}
    for pos, (kind, it) in enumerate(items):
        hp = items[:pos]
        def interf(w):
            s = 0.0
            for k2, h in hp:
                if k2 == "ART": s += math.ceil((w + tau)/h["T"]) * h["N"] * h["Cf"]
                else: s += math.ceil((w + tau)/h["T"]) * h["C"]
            return s
        B = Cmax_lp(pos)
        if kind == "M":
            C, T = it["C"], it["T"]
            t = B + C
            for _ in range(10000):                  # level-i busy period
                tn = B + sum(math.ceil(t/h["T"])*(h["N"]*h["Cf"] if k2=="ART" else h["C"]) for k2, h in hp) + math.ceil(t/T)*C
                if abs(tn - t) < 1e-12: break
                t = tn
            Q = math.ceil(t/T)
            R = 0.0
            for q in range(Q):
                w = B + q*C
                for _ in range(10000):
                    wn = B + q*C + interf(w)
                    if abs(wn - w) < 1e-12: break
                    w = wn
                R = max(R, w + C - q*T)
            res[it["idx"]] = R; resB[it["idx"]] = B
        else:                                         # artifact: N fragments back to back
            N, Cf = it["N"], it["Cf"]
            w = B + (N-1)*Cf
            for _ in range(10000):
                wn = B + (N-1)*Cf + interf(w)
                if abs(wn - w) < 1e-12: break
                w = wn
            res["ART"] = w + Cf
    return res, resB

def simulate(msgs, art, prio_pos, horizon, seed, critical, blocking_extra):
    rng = random.Random(seed)
    items = []
    for i, m in enumerate(msgs):
        if i == prio_pos and art: items.append(("ART", art))
        items.append(("M", dict(m, idx=i)))
    if prio_pos >= len(msgs) and art: items.append(("ART", art))
    arr = []   # (time, prio, seq, item_pos, k)
    seq = 0
    for pos, (kind, it) in enumerate(items):
        T = it["T"]
        off = 1e-9 if critical else rng.uniform(0, T)
        k = 0
        while off + k*T < horizon:
            r = off + k*T
            reps = it["N"] if kind == "ART" else 1
            for f in range(reps):
                arr.append((r, pos, seq, f, k)); seq += 1
            k += 1
    arr.sort()
    t = blocking_extra if critical else 0.0      # critical instant: a max-size lp frame just started
    heap, ai = [], 0
    maxR = {}; art_done = []
    while ai < len(arr) or heap:
        while ai < len(arr) and arr[ai][0] <= t:
            r, pos, sq, f, k = arr[ai]; heapq.heappush(heap, (pos, sq, r, f, k)); ai += 1
        if not heap:
            t = arr[ai][0]; continue
        pos, sq, r, f, k = heapq.heappop(heap)
        kind, it = items[pos]
        C = it["Cf"] if kind == "ART" else it["C"]
        t += C
        if kind == "M":
            maxR[it["idx"]] = max(maxR.get(it["idx"], 0.0), t - r)
        else:
            if f == it["N"] - 1: art_done.append(t - r)
    return maxR, art_done

def scenario(args):
    (kind, rdat, load, art_kind, art_size, art_pos_name, bulk_n, runs, horizon, seed) = args
    msgs, real_load = make_bg(kind, rdat, load, seed, bulk_n)
    nb = len(msgs) - 1
    real_load = sum(m["C"]/m["T"] for m in msgs)
    if kind == "FD":
        N = math.ceil(art_size/64); Cf = ctime("FD", 64, rdat)
    else:
        N = math.ceil(art_size/2048); Cf = ctime("XL", min(art_size, 2048), rdat)
    art = dict(T=1.0, N=N, Cf=Cf)
    pos = {"high": 0, "mid": nb//2, "low": nb}[art_pos_name]   # position among messages
    bound, Bs = rta(msgs, art, pos)
    # simulation: critical instant + random phasing
    simR = {}; art_all = []
    bmax = max(m["C"] for m in msgs)
    m1, a1 = simulate(msgs, art, pos, horizon, seed, True, bmax)
    # critical-instant run: valid only for messages whose own blocking term equals the
    # largest frame on the bus (the virtual blocking frame started at t=0 is then legitimate)
    crit_ok = {k for k in m1 if Bs[k] >= bmax - 1e-12}
    for k in crit_ok: simR[k] = max(simR.get(k, 0), m1[k])
    art_crit = max(a1) if a1 else None
    for r in range(runs):
        m2, a2 = simulate(msgs, art, pos, horizon, seed*1000 + r, False, bmax)
        for k, v in m2.items(): simR[k] = max(simR.get(k, 0), v)
        art_all += a2
    viol = [k for k in simR if simR[k] > bound[k] + 1e-9]
    ratios = [simR[k]/bound[k] for k in simR if bound[k] > 0]
    crit_ratio = max(m1[k]/bound[k] for k in crit_ok)
    art_all.sort()
    q = lambda p: art_all[min(len(art_all)-1, int(p*len(art_all)))] if art_all else None
    # deadline check on analytical bound (D = T)
    dl_bound_miss = [k for k in bound if k != "ART" and bound[k] > msgs[k]["T"]]
    base, _b = rta(msgs, None, pos)
    dl_base = [k for k in base if base[k] > msgs[k]["T"]]
    return dict(kind=kind, rdat=rdat, target_load=load, load=round(real_load, 3), n_msgs=len(msgs),
                art=art_kind, art_bytes=art_size, art_frames=N, art_pos=art_pos_name, bulk_bytes=bulk_n,
                bound_art_ms=bound["ART"]*1e3, sim_art_crit_ms=(art_crit or 0)*1e3,
                sim_art_median_ms=(q(0.5) or 0)*1e3, sim_art_p99_ms=(q(0.99) or 0)*1e3, sim_art_max_ms=(max(art_all) if art_all else 0)*1e3,
                violations=len(viol), crit_ratio=crit_ratio, max_ratio=max(ratios), mean_ratio=sum(ratios)/len(ratios),
                bound_miss_count=len(dl_bound_miss), bound_miss_baseline=len(dl_base), worst_bound_ms=max(v for k, v in bound.items() if k != "ART")*1e3,
                worst_sim_ms=max(simR.values())*1e3, n_checked=len(simR))

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--runs", type=int, default=40)
    ap.add_argument("--horizon", type=float, default=5.0); ap.add_argument("--out", default="results.json")
    a = ap.parse_args()
    jobs = []
    for load in (0.3, 0.5, 0.7):
        for pos in ("high", "mid", "low"):
            jobs.append(("FD", 2e6, load, "ML-KEM-512 pk", 800, pos, 64, a.runs, a.horizon, 7))
            for rdat in (2e6, 10e6):
                for bulk in (64, 2048):
                    jobs.append(("XL", rdat, load, "ML-KEM-512 pk", 800, pos, bulk, a.runs, a.horizon, 7))
    with Pool() as p: out = p.map(scenario, jobs)
    json.dump(out, open(a.out, "w"), indent=1)
    print(len(out), "scenarios; total violations:", sum(o["violations"] for o in out))
