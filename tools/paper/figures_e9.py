"""Figures for the E9 manuscript, from the registered run's result files (reproducible).

    python tools/paper/figures_e9.py --results experiments/e9_release_replay/results/run-39047161461 --out paper/figures
"""
import argparse
import csv
import json
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

INK, INK2, GRID, SURF = "#0b0b0b", "#52514e", "#e4e3df", "#ffffff"
PASS, REVIEW, FAIL = "#0ca30c", "#eda100", "#d03b3b"
BLUE, ORANGE = "#2a78d6", "#eb6834"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": INK2, "axes.labelcolor": INK,
                     "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
                     "savefig.dpi": 600, "savefig.bbox": "tight", "figure.facecolor": SURF})
GATES = [("gate_none", "No gate"), ("gate_naive_kev", "Naive KEV gate"), ("gate_cvss7", "CVSS ≥ 7 gate"),
         ("gate_crasme_v1_2", "CRA-SME v1.2")]


def save(fig, out, name):
    for ext in ("png", "tiff"):
        fig.savefig(out / f"{name}.{ext}", **({"pil_kwargs": {"compression": "tiff_lzw"}} if ext == "tiff" else {}))
    plt.close(fig)


def fig_pipeline(out):
    fig, ax = plt.subplots(figsize=(7.2, 2.5))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 34)
    ax.axis("off")
    boxes = [(1, "Releases", "20 products\n144 releases\n2024Q4–2026Q3"),
             (21, "Inventories", "lockfile at\nrelease commit;\nCI resolution; Syft"),
             (41, "Time travel", "OSV, KEV and\nfix dates ≤\nrelease date"),
             (61, "Gates", "none, naive KEV,\nCVSS ≥ 7,\nCRA-SME v1.2"),
             (81, "Outcomes", "H9a–H9f, 95% CIs;\nOpenCRA probes;\nvalidation")]
    for x, title, body in boxes:
        ax.add_patch(FancyBboxPatch((x, 6), 15.5, 22, boxstyle="round,pad=0.4,rounding_size=1.5",
                                    fc="#f3f6fb", ec=BLUE, lw=1.0))
        ax.text(x + 7.75, 24.6, title, ha="center", va="center", fontsize=9, weight="bold", color=INK)
        ax.text(x + 7.75, 14.5, body, ha="center", va="center", fontsize=6.7, color=INK2, linespacing=1.35)
    for x in (17.6, 37.6, 57.6, 77.6):
        ax.annotate("", xy=(x + 2.6, 17), xytext=(x, 17), arrowprops=dict(arrowstyle="-|>", color=INK2, lw=1))
    ax.text(50, 1.5, "Pre-registered (10.5281/zenodo.23438234) · data frozen and cached with timestamps · "
            "offline re-run reproduces all result tables byte for byte", ha="center", fontsize=7, color=INK2)
    save(fig, out, "Figure1_pipeline")


def fig_gates(M, out):
    fig, ax = plt.subplots(figsize=(7.2, 2.6))
    n = len(M)
    for i, (g, label) in enumerate(reversed(GATES)):
        y = i
        left = 0
        for dec, col, hatch in (("PASS", PASS, None), ("REVIEW_REQUIRED", REVIEW, "////"), ("FAIL", FAIL, None)):
            k = sum(m[g] == dec for m in M)
            if not k:
                continue
            ax.barh(y, k, left=left, height=0.62, color=col, edgecolor=SURF, linewidth=2, hatch=hatch)
            name = {"REVIEW_REQUIRED": "REVIEW"}.get(dec, dec)
            ax.text(left + k / 2, y, f"{name} {k}", ha="center", va="center", fontsize=8,
                    color="#000000" if dec == "REVIEW_REQUIRED" else "#ffffff", weight="bold")
            left += k
    ax.set_yticks(range(len(GATES)))
    ax.set_yticklabels([lab for _, lab in reversed(GATES)])
    ax.set_xlim(0, n)
    ax.set_xlabel(f"Releases (n = {n})")
    ax.xaxis.grid(True, color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    save(fig, out, "Figure2_gate_decisions")


def fig_h9a(A, out):
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.6), sharey=True)
    for ax, key, title in ((axes[0], "strict", "Empty or invalid inventory (n = 5)"),
                           (axes[1], "declared", "Declared unassessable or incomplete (n = 25)")):
        for i, (g, label) in enumerate(GATES):
            d = A["H9a"][key][g]
            col = BLUE if g == "gate_crasme_v1_2" else "#9aa3ad"
            ax.bar(i, d["p"], width=0.62, color=col, edgecolor=SURF, linewidth=2)
            lo, hi = d["wilson95"]
            ax.errorbar(i, d["p"], yerr=[[d["p"] - lo], [hi - d["p"]]], fmt="none", ecolor=INK, capsize=3, lw=0.9)
            ax.text(i, hi + 0.04, f'{d["k"]}/{d["n"]}', ha="center", fontsize=8, color=INK)
        ax.set_xticks(range(len(GATES)))
        ax.set_xticklabels([lab.replace(" gate", "\ngate").replace("CRA-SME ", "CRA-SME\n") for _, lab in GATES], fontsize=7.4)
        ax.set_title(title, fontsize=8.6, color=INK)
        ax.set_ylim(0, 1.18)
        ax.yaxis.grid(True, color=GRID, lw=0.6)
        ax.set_axisbelow(True)
    axes[0].set_ylabel("Share of releases\ngiven PASS (95% Wilson CI)")
    save(fig, out, "Figure3_silent_pass")


def fig_drift(D, lock_products, out):
    j = [float(r["jaccard"]) for r in D if r["product_id"] in lock_products and r["jaccard"] not in ("", "None")]
    fig, ax = plt.subplots(figsize=(3.5, 2.6))
    ax.hist(j, bins=[i / 20 for i in range(21)], color=BLUE, edgecolor=SURF, linewidth=1.5)
    med = statistics.median(j)
    ax.axvline(0.9, color=INK2, lw=1, ls="--")
    ax.text(0.91, ax.get_ylim()[1] * 0.80, "0.9", ha="left", fontsize=7.5, color=INK2)
    ax.axvline(med, color=ORANGE, lw=1.6)
    ax.text(med + 0.015, ax.get_ylim()[1] * 0.92, f"median {med:.2f}", fontsize=7.5, color=INK)
    ax.set_xlabel("Jaccard similarity of consecutive releases")
    ax.set_ylabel(f"Transitions (n = {len(j)})")
    ax.yaxis.grid(True, color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    save(fig, out, "Figure4_drift")


def fig_exposure(X, out):
    units = {}
    for x in X:
        units.setdefault((x["product_id"], x["vuln_id"], x["package"]), x)
    d = sorted(int(u["days_published_to_fixed_release"]) for u in units.values() if u["days_published_to_fixed_release"] != "")
    n = len(d)
    fig, ax = plt.subplots(figsize=(3.5, 2.6))
    ax.step(d, [(i + 1) / n for i in range(n)], where="post", color=BLUE, lw=2)
    med = statistics.median(d)
    ax.axvline(30, color=INK2, lw=1, ls="--")
    ax.text(32, 0.06, "30 days", fontsize=7.5, color=INK2)
    ax.axvline(med, color=ORANGE, lw=1.6)
    ax.text(med + 8, 0.42, f"median {med:.0f} d", fontsize=7.5, color=INK)
    ax.set_xlim(0, min(400, d[-1]))
    ax.set_ylim(0, 1.0)
    ax.set_xlabel("Days from disclosure to first sampled\nrelease without the vulnerable version")
    ax.set_ylabel(f"Cumulative share (n = {n})")
    ax.yaxis.grid(True, color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    save(fig, out, "Figure5_exposure")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    R, out = Path(a.results), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    M = list(csv.DictReader(open(R / "release_metrics.csv")))
    D = list(csv.DictReader(open(R / "drift.csv")))
    X = list(csv.DictReader(open(R / "exposure.csv")))
    A = json.loads((R / "ANALYSIS.json").read_text())
    lock = {m["product_id"] for m in M if m["inventory_status"] == "lockfile"}
    fig_pipeline(out)
    fig_gates(M, out)
    fig_h9a(A, out)
    fig_drift(D, lock, out)
    fig_exposure(X, out)
    print("figures ->", out)


if __name__ == "__main__":
    main()
