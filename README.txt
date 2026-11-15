Reproducibility package (standard library only, Python 3) - release v1.1

  python3 can_pqc_model.py              -> frame counts and bus times (Tables 10-12), illustrative case (Sec. V-C), classical-CAN comparison (Sec. V-D)
  python3 -I can_rta_sim.py --runs 100 --horizon 5 --out results.json   -> Table 14 (45 scenarios, synthetic traffic, fixed seeds); results.csv is the same data
  python3 can_hcrl_sim.py --trace normal_run_data.txt --runs 20 --out results_hcrl.json   -> Table 15 (replay of a recorded vehicle trace); results_hcrl.csv is the same data

can_hcrl_sim.py needs the attack-free trace "normal_run_data.txt" of the HCRL Car-Hacking dataset
(Song, Woo and Kim, Vehicular Communications 21, 100198, 2020), which is not redistributed here:
https://ocslab.hksecurity.net/Datasets/car-hacking-dataset
Run it from this folder (it imports can_rta_sim.py).

Traffic in can_rta_sim.py is synthetic; can_hcrl_sim.py replays a recorded classical-CAN trace
mapped onto CAN FD and CAN XL frames. No result comes from a physical CAN FD or CAN XL bus.

v1.1 adds can_hcrl_sim.py, results_hcrl.json and results_hcrl.csv; the v1.0 files are unchanged.
