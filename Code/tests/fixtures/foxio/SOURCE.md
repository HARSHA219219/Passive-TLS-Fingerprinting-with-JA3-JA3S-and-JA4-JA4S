Test captures (`*.pcap`, `*.pcapng`) and expected outputs (`*.snap`) copied unmodified from
FoxIO's JA4+ repository, fetched 2026-11-06:

- pcaps: https://github.com/FoxIO-LLC/ja4/tree/main/pcap
- expected output of FoxIO's own implementation: https://github.com/FoxIO-LLC/ja4/tree/main/rust/ja4/src/snapshots
  (`ja4__insta@<pcap>.snap`, renamed here to `<pcap>.snap`)

JA4 is BSD 3-Clause; JA4S and other JA4+ methods are under the FoxIO License 1.1 (academic use permitted).
Used by `tests/test_published.py` and `experiments/run_experiments.py`.
