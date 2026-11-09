Reproducibility package (standard library only, Python 3)
  python3 can_pqc_model.py              -> Tables 6-8, illustrative case (Sec. V-C), classic-CAN comparison (Sec. V-D)
  python3 -I can_rta_sim.py --runs 100 --horizon 5 --out results.json   -> Table 15 (45 scenarios, fixed seeds); results.csv is the same data
Traffic is synthetic (see Sec. V-E); no result comes from a physical bus.
