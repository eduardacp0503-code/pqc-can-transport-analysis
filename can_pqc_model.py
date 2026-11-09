#!/usr/bin/env python3
"""Reproducible calculation of Tables 6-8 and the illustrative case (Section V).

Frame model (as stated in Section V-A of the manuscript):
  C = N_nom/R_nom + N_dat/R_dat
  CAN FD, n > 16 payload bytes: N_nom = 30+4 = 34;
      N_dat = 5 + 8n + 4 + 21 + 7 + s,  s = floor((21+8n)/4) - 4
  CAN XL: N_nom = 37; N_dat = 3 + L + floor(L/10) + 4,  L = 8n + 108
  Classical CAN: frame counts only (8 B payload).
Fragments are padded to the maximum payload of CAN FD (64 B).
Run:  python3 can_pqc_model.py
"""
import math

# artifact sizes in bytes: (pub, ciphertext_or_signature)  -- Table 6
ART = {
 "ML-KEM-512": (800, 768), "ML-KEM-768": (1184, 1088), "ML-KEM-1024": (1568, 1568),
 "HQC-128": (2249, 4433), "HQC-192": (4522, 8978), "HQC-256": (7245, 14421),
 "ML-DSA-44": (1312, 2420), "ML-DSA-65": (1952, 3309), "ML-DSA-87": (2592, 4627),
 "FN-DSA-512": (897, 666), "FN-DSA-1024": (1793, 1280),
 "SLH-DSA-128s": (32, 7856), "SLH-DSA-128f": (32, 17088), "SLH-DSA-192s": (48, 16224),
 "ECDSA P-256": (64, 64), "ECDH P-256": (64, 64),
}

def fd_bits(n):
    s = (21 + 8*n)//4 - 4
    return 34, 5 + 8*n + 4 + 21 + 7 + s

def xl_bits(n):
    L = 8*n + 108
    return 37, 3 + L + L//10 + 4

def frame_time(bits, rnom, rdat):
    nn, nd = bits
    return nn/rnom + nd/rdat          # seconds

def frames(size, payload):
    return math.ceil(size/payload)

def fd_artifact_time(size, rdat, rnom=500e3):
    # every fragment padded to 64 B
    return frames(size, 64) * frame_time(fd_bits(64), rnom, rdat)

def xl_artifact_time(size, rdat, rnom=500e3, maxp=2048):
    # frames of up to maxp bytes; last frame carries the remainder
    t, left = 0.0, size
    while left > 0:
        n = min(left, maxp)
        t += frame_time(xl_bits(n), rnom, rdat)
        left -= n
    return t

if __name__ == "__main__":
    print("== Table 6: frame counts (pub / ct-sig) ==")
    for k, (p, c) in ART.items():
        print(f"{k:14s} CC {frames(p,8):4d}/{frames(c,8):4d}  FD {frames(p,64):4d}/{frames(c,64):4d}  XL {frames(p,2048)}/{frames(c,2048)}")
    print("\n== Table 7: bus time ms (FD 0.5/2, XL 0.5/10) ==")
    for k, (p, c) in ART.items():
        print(f"{k:14s} FD {fd_artifact_time(p,2e6)*1e3:6.2f}/{fd_artifact_time(c,2e6)*1e3:6.2f}   XL {xl_artifact_time(p,10e6)*1e3:5.2f}/{xl_artifact_time(c,10e6)*1e3:5.2f}")
    print("\n== Table 8 (top) ==")
    for name, sz in (("ML-KEM-512 pk",800),("ML-KEM-512 ct",768),("FN-DSA-512 sig",666)):
        print(name, [round(fd_artifact_time(sz,r*1e6)*1e3,2) for r in (2,5,8)],
              [round(xl_artifact_time(sz,r*1e6)*1e3,2) for r in (2,5,10)])
    print("== Table 8 (bottom): blocking frame ==")
    print("64B", [round(frame_time(fd_bits(64),500e3,r*1e6)*1e3,2) for r in (2,5,8)],
          [round(frame_time(xl_bits(64),500e3,r*1e6)*1e3,2) for r in (2,5,10)])
    for n in (256,512,1024,2048):
        print(n, [round(frame_time(xl_bits(n),500e3,r*1e6)*1e3,2) for r in (2,5,10)])


def illustrative_case():
    """Reproduces the numbers of the illustrative case of Section V-C (one artifact,
    idle bus otherwise, m_i = 8 B, T_i = D_i = 10 ms, arbitration 500 kbit/s)."""
    def fd8(r): return frame_time((34, 5+64+4+17+6+((17+64)//4-4)), 500e3, r)   # 8 B CAN FD, CRC-17
    def xl8(r): return frame_time(xl_bits(8), 500e3, r)
    out = {}
    # (i) artifact (ML-KEM-512 public key, 800 B) at higher priority than m_i; blocking by one 64 B frame
    out["i_FD"] = [round((frame_time(fd_bits(64),500e3,r*1e6)*(1+13) + fd8(r*1e6))*1e3, 2) for r in (2, 5, 8)]
    out["i_XL"] = [round((frame_time(xl_bits(64),500e3,r*1e6) + frame_time(xl_bits(800),500e3,r*1e6) + xl8(r*1e6))*1e3, 2) for r in (2, 5, 10)]
    # (ii) artifact at lower priority: blocking only
    out["ii_FD64"] = [round((frame_time(fd_bits(64),500e3,r*1e6) + fd8(r*1e6))*1e3, 2) for r in (2, 5, 8)]
    out["ii_XL2048"] = [round((frame_time(xl_bits(2048),500e3,r*1e6) + xl8(r*1e6))*1e3, 2) for r in (2, 5, 10)]
    out["ii_XL800"] = [round((frame_time(xl_bits(800),500e3,r*1e6) + xl8(r*1e6))*1e3, 2) for r in (2, 5, 10)]
    out["ii_XL256_2M"] = round((frame_time(xl_bits(256),500e3,2e6) + xl8(2e6))*1e3, 2)
    out["ii_XL1024_2M"] = round((frame_time(xl_bits(1024),500e3,2e6) + xl8(2e6))*1e3, 2)
    return out

def classic_can_calibration():
    """Idle-bus lower bound for the measured exchanges of the corpus on classical CAN
    (8 B frames, 135 bits each with worst-case stuffing, Davis et al. [72])."""
    bits = 135
    r = {}
    r["Ravi_20.5KB_500k_s"] = [math.ceil(20500/8)*bits/500e3, math.ceil(20.5*1024/8)*bits/500e3]
    for lvl, msgs, meas in ((1,198,0.108),(3,286,0.158),(5,394,0.222)):
        lb = msgs*bits/1e6
        r[f"Smith_level{lvl}"] = (lb, meas, meas/lb)
    return r

if __name__ == "__main__":
    print("\n== illustrative case ==", illustrative_case())
    print("== classical-CAN calibration ==", classic_can_calibration())
