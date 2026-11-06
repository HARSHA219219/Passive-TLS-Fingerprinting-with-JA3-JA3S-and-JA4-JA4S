"""Reproduce every result in results/ from the committed captures and reference data.

    python experiments/run_experiments.py            # writes results/*.csv, *.png, SUMMARY.md

Inputs (all in the repository):
  captures/train_v2.pcap + train_v2_manifest.json   -> builds the reference DB (learn)
  data/published_references.json                    -> published, cited fingerprints
  captures/test_v2.pcap  + test_v2_manifest.json    -> held-out evaluation
  tests/fixtures/foxio/*                            -> FoxIO published expected output

Evaluation protocol
  * Ground truth: each ClientHello to the manifest SNI inside a client's [start, end] run window
    (+-1 s) gets that client's label (clients run one at a time).
  * A prediction is correct only if the verdict is a single identification (status agree /
    ja4_only / ja3_only) naming the true client. UNKNOWN, ambiguous and conflict are never correct.
  * Accuracy / recall / F1 are reported over the 9 clients that are in the DB. The client that is
    deliberately NOT in the DB is scored as "correctly rejected" when the verdict is UNKNOWN.
    Spoofed connections are reported separately (they measure evasion, not accuracy), but they
    DO count against the precision of the label they were mistaken for.
"""
from __future__ import annotations

import csv
import os
import sys
import time
import tracemalloc
from collections import Counter, defaultdict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from tlsfp.capture import events_from_pcap  # noqa: E402
from tlsfp.cli import _load_manifest, _match_manifest  # noqa: E402
from tlsfp.db import FingerprintDB  # noqa: E402
from tlsfp.fingerprints import client_fingerprint, server_fingerprint  # noqa: E402
from tlsfp.reference import check_vectors, compare_foxio  # noqa: E402
from tlsfp.tls_parser import parse_client_hello, parse_server_hello  # noqa: E402

CAP = os.path.join(ROOT, "captures")
OUT = os.path.join(ROOT, "results")
TRAIN, TRAIN_M = os.path.join(CAP, "train_v2.pcap"), os.path.join(CAP, "train_v2_manifest.json")
TEST, TEST_M = os.path.join(CAP, "test_v2.pcap"), os.path.join(CAP, "test_v2_manifest.json")
PUBLISHED = os.path.join(ROOT, "data", "published_references.json")
MODES = {"JA4+JA3": (True, True), "JA3 only": (False, True), "JA4 only": (True, False)}


def write_csv(name: str, rows: list[dict]) -> None:
    path = os.path.join(OUT, name)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"  wrote results/{name} ({len(rows)} rows)")


def build_db() -> FingerprintDB:
    db = FingerprintDB(":memory:")
    runs = _load_manifest(TRAIN_M)
    for ev in events_from_pcap(TRAIN):
        if ev.is_client and (r := _match_manifest(ev, runs, 1.0)):
            db.add("ja4", ev.fp.ja4, r["label"], r.get("category", "unknown"), "learned", ev.fp.ja4_r)
            db.add("ja3", ev.fp.ja3, r["label"], r.get("category", "unknown"), "learned", ev.fp.ja3_full)
    db.import_json(PUBLISHED)
    return db


# ------------------------------------------------------------------ A. validation
def exp_validation() -> dict:
    rows = check_vectors(PUBLISHED)
    fox = os.path.join(ROOT, "tests", "fixtures", "foxio")
    for snap in sorted(f for f in os.listdir(fox) if f.endswith(".snap")):
        rows += compare_foxio(os.path.join(fox, snap[:-5]), os.path.join(fox, snap))
    for r in rows:
        r["reference"] = "FoxIO published expected output" if r["source"].endswith(
            (".pcap", ".pcapng")) else r["source"]
    try:                                    # independent implementation: Wireshark/tshark
        from tlsfp.validate import validate
        for pcap in (TRAIN, TEST):
            st = validate(pcap)["stats"]
            for k in ("ja3", "ja3s", "ja4"):
                ok, n = st[k]
                extra = st["ja4_grease_sigalg"] if k == "ja4" else 0
                rows.append({"source": os.path.basename(pcap), "flow": f"{n} hellos",
                             "algorithm": k.upper(), "expected": f"tshark {ok}/{n} exact",
                             "ours": f"+{extra} equal after removing tshark's GREASE sigalg" if extra else "",
                             "result": "pass" if ok + extra == n else "FAIL",
                             "reference": "Wireshark/tshark 4.6 independent implementation"})
    except Exception as e:                  # tshark not installed
        print(f"  (tshark cross-check skipped: {e})")
    write_csv("fingerprint_validation.csv", rows)
    summary = defaultdict(Counter)
    for r in rows:
        if "hellos" in r["flow"]:           # tshark aggregate rows
            continue
        summary[r["algorithm"]]["pass" if r["result"] == "pass" else
                                "explained" if r["result"].startswith("explained") else "FAIL"] += 1
    return summary


# ------------------------------------------------------------------ B/C/D. identification
def exp_identification(db: FingerprintDB) -> dict:
    runs = _load_manifest(TEST_M)
    conns, rows = [], []
    for ev in events_from_pcap(TEST):
        if ev.is_client and (r := _match_manifest(ev, runs, 1.0)):
            conns.append((ev, r))
    for ev, r in conns:
        row = {"time": f"{ev.ts:.3f}", "client_flow": f"{ev.flow[0]}:{ev.flow[1]}",
               "server": f"{ev.flow[2]}:{ev.flow[3]}", "sni": ev.sni,
               "ground_truth": r["label"], "truth_category": r.get("category", ""),
               "ja3": ev.fp.ja3, "ja4": ev.fp.ja4}
        for mode, (use4, use3) in MODES.items():
            m = db.identify(ev.fp.ja4 if use4 else None, ev.fp.ja3 if use3 else None)
            row[f"{mode} status"] = m.status
            row[f"{mode} verdict"] = m.label
            row[f"{mode} correct"] = int(m.identified and m.labels == [r["label"]])
        rows.append(row)
    write_csv("client_identification_results.csv", rows)

    known = [r for r in rows if r["truth_category"] not in ("spoof", "unknown")]
    labels = sorted({r["ground_truth"] for r in known})
    comparison, per_class = [], []
    for mode in MODES:
        n = len(known)
        corr = sum(r[f"{mode} correct"] for r in known)
        st = Counter(r[f"{mode} status"] for r in known)
        unk = [r for r in rows if r["truth_category"] == "unknown"]
        spoof = [r for r in rows if r["truth_category"] == "spoof"]
        f1s = []
        for lab in labels:
            tp = sum(1 for r in known if r["ground_truth"] == lab and r[f"{mode} correct"])
            pred = sum(1 for r in rows if r[f"{mode} verdict"] == lab)
            actual = sum(1 for r in known if r["ground_truth"] == lab)
            p = tp / pred if pred else 0.0
            rc = tp / actual if actual else 0.0
            f1 = 2 * p * rc / (p + rc) if p + rc else 0.0
            f1s.append(f1)
            per_class.append({"mode": mode, "client": lab, "connections": actual, "true_positive": tp,
                              "predicted_as_this": pred, "precision": round(p, 3),
                              "recall": round(rc, 3), "f1": round(f1, 3)})
        comparison.append({
            "mode": mode, "known_client_connections": n, "correct": corr,
            "accuracy": round(corr / n, 3), "macro_f1": round(sum(f1s) / len(f1s), 3),
            "unknown_verdicts": st["unknown"], "ambiguous": st["ambiguous"],
            "conflict": st["conflict"],
            "unknown_client_correctly_rejected": f"{sum(r[f'{mode} status'] == 'unknown' for r in unk)}/{len(unk)}",
            "spoofs_accepted_as_target": f"{sum(r[f'{mode} verdict'] == 'Google Chrome' for r in spoof)}/{len(spoof)}",
        })
    write_csv("per_client_metrics.csv", per_class)

    # stability across repeated connections (train + test, by ground truth)
    stab = defaultdict(lambda: {"n": 0, "ja3": set(), "ja4": set()})
    for pcap, man in ((TRAIN, TRAIN_M), (TEST, TEST_M)):
        rr = _load_manifest(man)
        for ev in events_from_pcap(pcap):
            if ev.is_client and (r := _match_manifest(ev, rr, 1.0)) and r.get("category") != "spoof":
                s = stab[r["label"]]
                s["n"] += 1
                s["ja3"].add(ev.fp.ja3)
                s["ja4"].add(ev.fp.ja4)
    stability = [{"client": k, "connections": v["n"], "distinct_ja3": len(v["ja3"]),
                  "distinct_ja4": len(v["ja4"]),
                  "ja3_repeat_rate": round(1 - (len(v["ja3"]) - 1) / max(v["n"] - 1, 1), 3),
                  "ja4_repeat_rate": round(1 - (len(v["ja4"]) - 1) / max(v["n"] - 1, 1), 3)}
                 for k, v in sorted(stab.items())]
    write_csv("ja3_vs_ja4_comparison.csv", comparison)
    write_csv("fingerprint_stability.csv", stability)

    spoof_rows = []
    for r in rows:
        if r["truth_category"] != "spoof":
            continue
        spoof_rows.append({"ground_truth": r["ground_truth"], "client_flow": r["client_flow"],
                           "ja3": r["ja3"], "ja4": r["ja4"],
                           **{f"{m} verdict": r[f"{m} verdict"] for m in MODES},
                           "combined_status": r["JA4+JA3 status"],
                           "fooled_combined": int(r["JA4+JA3 verdict"] == "Google Chrome")})
    write_csv("spoofing_results.csv", spoof_rows)

    # confusion matrix for the combined mode (all test connections)
    preds = sorted({r["JA4+JA3 verdict"] for r in rows})
    truths = sorted({r["ground_truth"] for r in rows})
    cm = [{"ground_truth \\ predicted": t,
           **{p: sum(1 for r in rows if r["ground_truth"] == t and r["JA4+JA3 verdict"] == p)
              for p in preds}} for t in truths]
    write_csv("confusion_matrix_combined.csv", cm)
    return {"rows": rows, "comparison": comparison, "stability": stability, "spoof": spoof_rows,
            "cm": (truths, preds, cm), "db": db}


# ------------------------------------------------------------------ server side
def exp_server(db: FingerprintDB) -> list[dict]:
    clients = {}
    runs = _load_manifest(TEST_M)
    agg = defaultdict(lambda: {"n": 0, "clients": set(), "ja3s_full": ""})
    for ev in events_from_pcap(TEST):
        if ev.is_client:
            r = _match_manifest(ev, runs, 1.0)
            clients[ev.flow] = (ev.sni or "-", r["label"] if r else "(background)")
            continue
        src, sport, dst, dport = ev.flow
        sni, who = clients.get((dst, dport, src, sport), ("-", "(unpaired)"))
        if sni == "-":
            continue
        key = (sni, ev.fp.ja3s, ev.fp.ja4s)
        agg[key]["n"] += 1
        agg[key]["clients"].add(who)
        agg[key]["ja3s_full"] = ev.fp.ja3s_full
    rows = []
    for (sni, ja3s, ja4s), v in sorted(agg.items(), key=lambda x: (x[0][0], -x[1]["n"])):
        m = db.identify(ja4s, ja3s, client=False)
        rows.append({"server_sni": sni, "ja3s": ja3s, "ja3s_full": v["ja3s_full"], "ja4s": ja4s,
                     "server_hellos": v["n"], "client_labels": "; ".join(sorted(v["clients"])),
                     "db_status": m.status, "db_verdict": m.label, "db_category": m.category})
    write_csv("server_fingerprint_results.csv", rows)
    return rows


# ------------------------------------------------------------------ E. performance
def exp_performance() -> list[dict]:
    from tlsfp.tls_parser import extract_first_handshake
    from scapy.all import PcapReader
    rows = []
    # 1) end-to-end offline processing: read pcap + decode + reassemble + parse + fingerprint
    with PcapReader(TEST) as rd:
        npk = sum(1 for _ in rd)
    t0 = time.perf_counter()
    hellos = list(events_from_pcap(TEST))
    dt = time.perf_counter() - t0
    size = os.path.getsize(TEST)
    rows.append({"measurement": "offline pcap pipeline (Scapy read+decode+reassembly+parse+fingerprint)",
                 "input": f"test_v2.pcap, {npk} packets, {size / 1e6:.1f} MB, {len(hellos)} hellos",
                 "value": round(npk / dt), "unit": "packets/s",
                 "notes": f"{dt:.2f} s total; Scapy packet decoding dominates"})
    tracemalloc.start()
    sum(1 for _ in events_from_pcap(TEST))
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rows.append({"measurement": "peak Python memory, offline pipeline", "input": "test_v2.pcap",
                 "value": round(peak / 1e6, 1), "unit": "MB", "notes": "tracemalloc"})
    # 2) parse + fingerprint only (no packet I/O)
    from tlsfp.builder import HelloSpec, build_client_hello
    raw = [extract_first_handshake(build_client_hello(HelloSpec(
        ciphers=list(range(0x1301, 0x1304)) + [0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8],
        extensions=[0, 0x17, 0xFF01, 0x0A, 0x0B, 0x23, 0x10, 0x05, 0x0D, 0x12, 0x33, 0x2D, 0x2B, 0x1B],
        groups=[0x1D, 0x17, 0x18], point_formats=[0], alpn=[b"h2", b"http/1.1"],
        supported_versions=[0x0304, 0x0303], sni="www.example.com")))[1]]
    ch_objs = [e.hello for e in hellos if e.is_client]
    sh_objs = [e.hello for e in hellos if not e.is_client]
    N = 2000
    t0 = time.perf_counter()
    for _ in range(N):
        parse_client_hello(raw[0])
    t_parse = (time.perf_counter() - t0) / N
    t0 = time.perf_counter()
    for i in range(N):
        client_fingerprint(ch_objs[i % len(ch_objs)])
    t_fp = (time.perf_counter() - t0) / N
    t0 = time.perf_counter()
    for i in range(N):
        server_fingerprint(sh_objs[i % len(sh_objs)])
    t_sfp = (time.perf_counter() - t0) / N
    db = build_db()
    fps = [client_fingerprint(e) for e in ch_objs]
    t0 = time.perf_counter()
    for i in range(N):
        f = fps[i % len(fps)]
        db.identify(f.ja4, f.ja3)
    t_id = (time.perf_counter() - t0) / N
    for name, val in (("ClientHello parse", t_parse), ("JA3+JA4 computation", t_fp),
                      ("JA3S+JA4S computation", t_sfp), ("DB lookup + identify (SQLite)", t_id)):
        rows.append({"measurement": name, "input": f"mean of {N} runs",
                     "value": round(val * 1e6, 1), "unit": "microseconds",
                     "notes": f"~{round(1 / val):,} per second on one core" if val > 0 else ""})
    write_csv("performance_results.csv", rows)
    return rows


# ------------------------------------------------------------------ charts
def charts(ident: dict) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("  (matplotlib not installed: charts skipped)")
        return
    ink, muted, grid = "#1f2328", "#59636e", "#d0d7de"
    c3, c4, cc = "#d1495b", "#2e86ab", "#3d9970"
    plt.rcParams.update({"font.size": 10, "axes.edgecolor": grid, "axes.labelcolor": ink,
                         "xtick.color": muted, "ytick.color": muted, "axes.spines.top": False,
                         "axes.spines.right": False})

    # 1. accuracy per mode
    comp = ident["comparison"]
    fig, ax = plt.subplots(figsize=(6, 3.4))
    names = [c["mode"] for c in comp]
    vals = [100 * c["accuracy"] for c in comp]
    bars = ax.bar(names, vals, color=[cc, c3, c4], width=0.55)
    for b, c in zip(bars, comp):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1.5,
                f"{c['correct']}/{c['known_client_connections']}", ha="center", color=ink)
    ax.set_ylim(0, 110)
    ax.set_ylabel("correctly identified (%)")
    ax.set_title("Held-out identification accuracy, 9 known clients", loc="left", color=ink)
    ax.yaxis.grid(True, color=grid)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "chart_accuracy_by_method.png"), dpi=150, bbox_inches="tight")
    plt.close(fig)

    # 2. stability
    st = ident["stability"]
    fig, ax = plt.subplots(figsize=(8, 3.8))
    y = range(len(st))
    ax.barh([i + 0.2 for i in y], [s["distinct_ja3"] for s in st], height=0.4, color=c3, label="distinct JA3")
    ax.barh([i - 0.2 for i in y], [s["distinct_ja4"] for s in st], height=0.4, color=c4, label="distinct JA4")
    ax.set_yticks(list(y), [f"{s['client']} (n={s['connections']})" for s in st])
    ax.invert_yaxis()
    ax.set_xlabel("distinct fingerprints over repeated connections (lower = more stable)")
    ax.set_title("JA3 vs JA4 stability across repeated connections", loc="left", color=ink)
    ax.legend(frameon=False, loc="lower right")
    ax.xaxis.grid(True, color=grid)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "chart_fingerprint_stability.png"), dpi=150, bbox_inches="tight")
    plt.close(fig)

    # 3. confusion matrix
    truths, preds, cm = ident["cm"]
    import numpy as np
    mat = np.array([[row[p] for p in preds] for row in cm])
    fig, ax = plt.subplots(figsize=(9, 6))
    ax.imshow(mat, cmap="Blues")
    ax.set_xticks(range(len(preds)), [p[:28] for p in preds], rotation=40, ha="right", fontsize=8)
    ax.set_yticks(range(len(truths)), [t[:45] for t in truths], fontsize=8)
    for i in range(len(truths)):
        for j in range(len(preds)):
            if mat[i, j]:
                ax.text(j, i, mat[i, j], ha="center", va="center",
                        color="white" if mat[i, j] > mat.max() / 2 else ink, fontsize=8)
    ax.set_xlabel("verdict (JA4+JA3)")
    ax.set_ylabel("ground truth")
    ax.set_title("Confusion matrix, held-out test capture", loc="left", color=ink)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "chart_confusion_matrix.png"), dpi=150, bbox_inches="tight")
    plt.close(fig)

    # 4. spoofing / unknown outcome per mode
    fig, ax = plt.subplots(figsize=(6.5, 3.4))
    x = range(len(comp))
    sp = [int(c["spoofs_accepted_as_target"].split("/")[0]) for c in comp]
    tot = int(comp[0]["spoofs_accepted_as_target"].split("/")[1])
    ax.bar(x, sp, color=c3, width=0.55)
    for i, v in enumerate(sp):
        ax.text(i, v + 0.2, f"{v}/{tot}", ha="center", color=ink)
    ax.set_xticks(list(x), [c["mode"] for c in comp])
    ax.set_ylim(0, tot + 2)
    ax.set_ylabel("spoofed connections accepted as Chrome")
    ax.set_title("Evasion: a 150-line script impersonating Chrome", loc="left", color=ink)
    ax.yaxis.grid(True, color=grid)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "chart_spoofing.png"), dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  wrote 4 charts")


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    print("[A] fingerprint validation")
    val = exp_validation()
    print("[B-D] identification, JA3 vs JA4, stability, spoofing")
    db = build_db()
    ident = exp_identification(db)
    print("[S] server fingerprints")
    srv = exp_server(db)
    print("[E] performance")
    perf = exp_performance()
    charts(ident)

    lines = ["# Results summary", "",
             "Generated by `python experiments/run_experiments.py` from the committed captures.", "",
             "## A. Fingerprint validation against published / independent references", "",
             "| Algorithm | pass | explained difference | FAIL |", "|---|---:|---:|---:|"]
    for alg in ("JA3", "JA3S", "JA4", "JA4S"):
        c = val.get(alg, Counter())
        lines.append(f"| {alg} | {c['pass']} | {c['explained']} | {c['FAIL']} |")
    lines += ["", "Plus the Wireshark/tshark cross-check rows in `fingerprint_validation.csv`.", "",
              "## B/C. Identification on the held-out capture", "",
              "| Method | Known-client accuracy | Macro F1 | Unknown client rejected | Spoofs accepted as Chrome |",
              "|---|---:|---:|---:|---:|"]
    for c in ident["comparison"]:
        lines.append(f"| {c['mode']} | {c['correct']}/{c['known_client_connections']} = "
                     f"{100 * c['accuracy']:.1f}% | {c['macro_f1']:.3f} | "
                     f"{c['unknown_client_correctly_rejected']} | {c['spoofs_accepted_as_target']} |")
    lines += ["", "## Stability (train + test)", "", "| Client | Connections | Distinct JA3 | Distinct JA4 |",
              "|---|---:|---:|---:|"]
    for s in ident["stability"]:
        lines.append(f"| {s['client']} | {s['connections']} | {s['distinct_ja3']} | {s['distinct_ja4']} |")
    lines += ["", "## Server side (JA3S / JA4S)", "",
              "| Server SNI | JA4S | ServerHellos | DB verdict |", "|---|---|---:|---|"]
    for r in srv:
        lines.append(f"| {r['server_sni']} | `{r['ja4s']}` | {r['server_hellos']} | "
                     f"{r['db_verdict']} [{r['db_status']}] |")
    lines += ["", "## Performance", "", "| Measurement | Value |", "|---|---|"]
    for r in perf:
        lines.append(f"| {r['measurement']} | {r['value']} {r['unit']} |")
    with open(os.path.join(OUT, "SUMMARY.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("  wrote results/SUMMARY.md")


if __name__ == "__main__":
    main()
