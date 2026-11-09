Reproducibility package (standard library only, Python 3)

Paper: E. C. Pissolatto and F. Hessel, "Post-Quantum Cryptography for In-Vehicle
Networks: A Systematic Review and a CAN FD/CAN XL Transport Analysis", IEEE Access
(revised manuscript Access-2026-52896).

  python3 can_pqc_model.py
      -> Tables 9-11 (frame counts, bus time, rate sweep), illustrative case (Sec. V-C),
         classic-CAN comparison (Sec. V-D)
  python3 -I can_rta_sim.py --runs 100 --horizon 5 --out results.json
      -> Table 13 (45 scenarios, fixed seeds); results.csv is the same data (Sec. V-E)

Note on numbering: the printed headers of can_pqc_model.py ("Table 6", "Table 7",
"Table 8") follow an earlier draft; they correspond to Tables 9, 10 and 11 of the
revised manuscript. "Table 15" in earlier notes corresponds to Table 13.

Traffic is synthetic (see Sec. V-E); no result comes from a physical bus.
License: MIT.
