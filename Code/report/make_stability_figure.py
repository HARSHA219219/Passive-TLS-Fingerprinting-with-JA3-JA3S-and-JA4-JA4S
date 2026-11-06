"""Compact one-column version of the stability chart for the report
(data: results/fingerprint_stability.csv, produced by experiments/run_experiments.py)."""
import csv
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "results", "fingerprint_stability.csv")
OUT = os.path.join(HERE, "fig_stability.png")
SHORT = {"Google Chrome": "Chrome", "Microsoft Edge": "Edge", "Mozilla Firefox": "Firefox",
         "curl (Windows/Schannel)": "curl", "PowerShell Invoke-WebRequest (.NET)": "PowerShell",
         "Python urllib (OpenSSL)": "urllib", "Python requests (OpenSSL)": "requests",
         "Custom Python script (TLS1.2, 3 ciphers)": "custom script",
         "Handcrafted raw TLS client": "raw client"}
rows = [r for r in csv.DictReader(open(SRC, encoding="utf-8")) if r["client"] in SHORT]
order = list(SHORT)
rows.sort(key=lambda r: order.index(r["client"]))
labels = [f"{SHORT[r['client']]} ({r['connections']})" for r in rows]
ja3 = [int(r["distinct_ja3"]) for r in rows]
ja4 = [int(r["distinct_ja4"]) for r in rows]

plt.rcParams.update({"font.size": 7, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.edgecolor": "#d0d7de", "xtick.color": "#57606a", "ytick.color": "#1f2328"})
fig, ax = plt.subplots(figsize=(3.4, 2.3))
y = range(len(rows))
ax.barh([i - 0.2 for i in y], ja3, height=0.38, color="#d1495b", label="distinct JA3")
ax.barh([i + 0.2 for i in y], ja4, height=0.38, color="#2e86ab", label="distinct JA4")
for i, (a, b) in enumerate(zip(ja3, ja4)):
    ax.text(a + 0.4, i - 0.2, str(a), va="center", fontsize=6, color="#1f2328")
    ax.text(b + 0.4, i + 0.2, str(b), va="center", fontsize=6, color="#1f2328")
ax.set_yticks(list(y), labels)
ax.invert_yaxis()
ax.set_xlabel("distinct fingerprints (client, connections)", fontsize=7)
ax.xaxis.grid(True, color="#eaeef2")
ax.set_axisbelow(True)
ax.legend(frameon=False, loc="lower right", fontsize=6.5)
fig.savefig(OUT, dpi=300, bbox_inches="tight", pad_inches=0.02)
print("wrote", OUT)
