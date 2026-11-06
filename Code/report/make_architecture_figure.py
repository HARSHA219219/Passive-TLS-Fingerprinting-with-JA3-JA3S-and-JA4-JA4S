"""Draw the architecture figure used in the project report (report/fig_architecture.png).
Sized for one column of the two-column report."""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fig_architecture.png")
INK, MUTED, EDGE = "#1f2328", "#57606a", "#8c959f"
FILL = {"src": "#eef4fb", "core": "#eaf5ee", "db": "#fdf3e6", "out": "#f3eefb"}

W, H, X, GAP = 2.45, 0.72, 0.05, 0.30
names = [  # top to bottom
    ("src", "Traffic sources", "browsers, curl, Python, custom clients"),
    ("cap", "Packet capture (capture.py)", "Scapy + Npcap/libpcap, live or pcap"),
    ("tcp", "TCP reassembly (flows.py)", "reorder, retransmit, any port, IPv4/6"),
    ("tls", "Hello parser (tls_parser.py)", "ClientHello / ServerHello, GREASE"),
    ("fp", "Fingerprints (fingerprints.py)", "JA3, JA3S, JA4, JA4S"),
    ("id", "Identification (db.py)", "agree / ja4_only / ja3_only /\nambiguous / conflict / unknown"),
    ("out", "Output (cli.py, experiments/)", "live, analyze, report, CSV + charts"),
]
kind = {"src": "src", "out": "out"}
fig, ax = plt.subplots(figsize=(3.5, 5.9))
top = len(names) * (H + GAP)
ax.set_xlim(0, 3.5)
ax.set_ylim(0, top)
ax.axis("off")
pos = {}
for i, (k, t, s) in enumerate(names):
    y = top - (i + 1) * (H + GAP) + GAP / 2
    h = H
    pass
    ax.add_patch(FancyBboxPatch((X, y), W, h, boxstyle="round,pad=0.01,rounding_size=0.05",
                                fc=FILL[kind.get(k, "core")], ec=EDGE, lw=0.8))
    ax.text(X + W / 2, y + h - 0.17, t, ha="center", va="center", fontsize=7.2, weight="bold", color=INK)
    ax.text(X + W / 2, y + (h - 0.3) / 2, s, ha="center", va="center", fontsize=6.2, color=MUTED,
            linespacing=1.2)
    pos[k] = (X, y, W, h)

# reference DB beside the identification box
x0, y0, w0, h0 = pos["id"]
dbx, dbw = 2.66, 0.82
ax.add_patch(FancyBboxPatch((dbx, y0 - 0.1), dbw, h0 + 0.2, boxstyle="round,pad=0.01,rounding_size=0.05",
                            fc=FILL["db"], ec=EDGE, lw=0.8))
ax.text(dbx + dbw / 2, y0 + h0 - 0.08, "Reference DB\n(SQLite)", ha="center", va="center", fontsize=6.2,
        weight="bold", color=INK, linespacing=1.1)
ax.text(dbx + dbw / 2, y0 + h0 / 2 - 0.2, "9 learned\n+ 16 published\n(with source)", ha="center",
        va="center", fontsize=5.6, color=MUTED, linespacing=1.15)

labels = {"src": "packets (passive copy)", "cap": "ts, 4-tuple, seq, payload", "tcp": "first handshake msg",
          "tls": "parsed fields", "fp": "client + server hashes", "id": "verdict, status, provenance"}
keys = [k for k, _, _ in names]
for a, b in zip(keys, keys[1:]):
    xa, ya, wa, ha = pos[a]
    xb, yb, wb, hb = pos[b]
    ax.add_patch(FancyArrowPatch((xa + wa / 2, ya), (xb + wb / 2, yb + hb), arrowstyle="-|>",
                                 mutation_scale=8, lw=0.9, color=INK))
    ax.text(xa + wa / 2 + 0.06, (ya + yb + hb) / 2, labels[a], fontsize=5.6, color=MUTED, va="center")
ax.add_patch(FancyArrowPatch((dbx, y0 + h0 * 0.72), (x0 + w0, y0 + h0 * 0.72), arrowstyle="-|>",
                             mutation_scale=8, lw=0.9, color=INK))
ax.add_patch(FancyArrowPatch((x0 + w0, y0 + h0 * 0.28), (dbx, y0 + h0 * 0.28), arrowstyle="-|>",
                             mutation_scale=8, lw=0.9, color=INK))
fig.savefig(OUT, dpi=300, bbox_inches="tight", pad_inches=0.02)
print("wrote", OUT)
