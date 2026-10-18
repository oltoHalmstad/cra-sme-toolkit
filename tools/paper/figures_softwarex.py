"""Figures for the SoftwareX software article (architecture, decision pipeline, seeded-fault verification).

    python tools/paper/figures_softwarex.py --out paper/softwarex/figures
"""
import argparse
import csv
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
INK, INK2, GRID, SURF = "#0b0b0b", "#52514e", "#e4e3df", "#ffffff"
BLUE, ORANGE, GREY = "#2a78d6", "#eb6834", "#9aa3ad"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": INK2, "xtick.color": INK2,
                     "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
                     "savefig.dpi": 600, "savefig.bbox": "tight", "figure.facecolor": SURF})


def box(ax, x, y, w, h, title, body, fc="#f3f6fb", ec=BLUE, tfs=8.2, bfs=6.6, mono=True):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.25,rounding_size=1.0", fc=fc, ec=ec, lw=1.0))
    ax.text(x + w / 2, y + h - 2.2, title, ha="center", va="top", fontsize=tfs, weight="bold", color=INK)
    if body:
        ax.text(x + w / 2, y + h - 6.0, body, ha="center", va="top", fontsize=bfs, color=INK2, linespacing=1.3,
                family="DejaVu Sans Mono" if mono else "DejaVu Sans")


def arrow(ax, x0, y0, x1, y1):
    ax.annotate("", xy=(x1, y1), xytext=(x0, y0), arrowprops=dict(arrowstyle="-|>", color=INK2, lw=1))


def save(fig, out, name):
    fig.savefig(out / f"{name}.png")
    fig.savefig(out / f"{name}.tiff", pil_kwargs={"compression": "tiff_lzw"})
    plt.close(fig)


def fig_architecture(out):
    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 62)
    ax.axis("off")
    # inputs
    ax.text(10, 60, "Inputs", ha="center", fontsize=8.5, weight="bold", color=INK2)
    box(ax, 0.5, 39, 19, 19, "Release evidence", "CycloneDX SBOM\nscanner output\n(Trivy/Grype/OSV)\nscan-status.json\nevidence files")
    box(ax, 0.5, 18, 19, 19, "Knowledge", "CISA KEV snapshot\nOSV advisories\nVEX / triage\nregistry data")
    box(ax, 0.5, 0.5, 19, 15.5, "Policy", "policy.yaml\nobligation\ncatalogue (CSV)")
    # core
    ax.add_patch(FancyBboxPatch((25, 0.5), 47, 57.5, boxstyle="round,pad=0.3,rounding_size=1.5", fc="#fbfbfa", ec=INK2, lw=0.8, ls="--"))
    ax.text(48.5, 60, "crasme (Python package)", ha="center", fontsize=8.5, weight="bold", color=INK2)
    box(ax, 27, 43, 20, 13, "Evidence", "scanstatus\nprovenance\ntraceability")
    box(ax, 50, 43, 20, 13, "Inventory", "sbom · vulns\ncompleteness")
    box(ax, 27, 24, 43, 16, "Release-decision engine (gate)", "PASS / REVIEW_REQUIRED / FAIL\n65 reason codes · fail-safe\nlegal_conformity = NOT_DETERMINED_BY_TOOL",
        fc="#fdf0e9", ec=ORANGE)
    box(ax, 27, 2.5, 20, 18.5, "Research", "replay (time travel)\nmutation (faults)\nvalidation (κ)")
    box(ax, 50, 2.5, 20, 18.5, "Analysis", "risk · stats\nagreement\nreporting clocks")
    # outputs
    ax.text(88, 60, "Outputs", ha="center", fontsize=8.5, weight="bold", color=INK2)
    box(ax, 77, 39, 22, 19, "Decision record", "decision.json\nreasons + refs\ninput digests\nbundle digest")
    box(ax, 77, 18, 22, 19, "Workflows", "crasme-gate CLI\nGitHub Actions\n(SHA-pinned)")
    box(ax, 77, 0.5, 22, 15.5, "Studies", "E1–E9 protocols\n8 notebooks")
    for y in (48, 27, 8):
        arrow(ax, 20, y, 26.5, y if y != 8 else 27)
    arrow(ax, 37, 43, 37, 40.3)
    arrow(ax, 60, 43, 60, 40.3)
    arrow(ax, 70.5, 32, 76.5, 46)
    arrow(ax, 70.5, 30, 76.5, 27)
    arrow(ax, 70.5, 10, 76.5, 8)
    save(fig, out, "Figure1_architecture")


def fig_pipeline(out):
    fig, ax = plt.subplots(figsize=(7.2, 2.9))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 40)
    ax.axis("off")
    steps = [("1 Bind", "product, version,\nbuild SHA, digest"), ("2 Integrity", "manifest hashes;\ntampering → FAIL"),
             ("3 Scans", "completed, valid,\nfresh; else REVIEW"), ("4 Findings", "KEV + VEX;\nuntriaged → REVIEW"),
             ("5 Obligations", "in force, mapped,\nevidenced, approved")]
    for i, (t, b) in enumerate(steps):
        x = 1 + i * 19.8
        box(ax, x, 18, 17.5, 19, t, b, tfs=8, bfs=6.4, mono=False)
        if i < 4:
            arrow(ax, x + 17.7, 27.5, x + 19.6, 27.5)
    verdicts = [("PASS", "#0ca30c", "every check satisfied →\neligible for human review"),
                ("REVIEW_REQUIRED", "#eda100", "missing, stale, unverified,\nor needs a decision"),
                ("FAIL", "#d03b3b", "tampered evidence, affected\nKEV, failed obligation")]
    for i, (v, c, d) in enumerate(verdicts):
        x = 6 + i * 31
        ax.add_patch(FancyBboxPatch((x, 1), 26, 12, boxstyle="round,pad=0.25,rounding_size=1.0", fc=SURF, ec=c, lw=1.6))
        ax.text(x + 13, 10.3, v, ha="center", fontsize=8, weight="bold", color=INK)
        ax.text(x + 13, 6.6, d, ha="center", va="top", fontsize=6.4, color=INK2, linespacing=1.25)
    ax.text(50, 15.3, "verdict = most severe reason; every reason carries a code and references", ha="center", fontsize=6.8, color=INK2)
    save(fig, out, "Figure2_decision_pipeline")


def fig_mutation(out):
    rows = list(csv.DictReader(open(ROOT / "experiments/e4_e7_gate_mutation/results.csv")))
    agg = defaultdict(lambda: [0, 0, 0])
    for r in rows:
        a = agg[r["category"]]
        a[0] += 1
        a[1] += r["false_green"] == "True"
        a[2] += r["legacy_v11_false_green"] == "True"
    cats = sorted(agg, key=lambda c: -agg[c][0])
    fig, ax = plt.subplots(figsize=(7.2, 2.6))
    w = 0.38
    for i, c in enumerate(cats):
        n, v12, v11 = agg[c]
        ax.bar(i - w / 2, v11 / n, w, color=GREY, edgecolor=SURF, lw=1.5, label="legacy gate (v1.1)" if i == 0 else None)
        ax.bar(i + w / 2, v12 / n, w, color=BLUE, edgecolor=SURF, lw=1.5, label="CRA-SME engine (v1.2+)" if i == 0 else None)
        ax.text(i - w / 2, v11 / n + 0.03, f"{v11}/{n}", ha="center", fontsize=6.8, color=INK)
        ax.text(i + w / 2, v12 / n + 0.03, f"{v12}/{n}", ha="center", fontsize=6.8, color=INK)
    ax.set_xticks(range(len(cats)))
    ax.set_xticklabels(cats, fontsize=7.6)
    ax.set_ylim(0, 1.18)
    ax.set_ylabel("Share of faults\ngiven a false PASS")
    ax.yaxis.grid(True, color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=7.4, ncol=2, loc="upper center", bbox_to_anchor=(0.5, 1.18))
    save(fig, out, "Figure3_seeded_faults")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    o = Path(a.out)
    o.mkdir(parents=True, exist_ok=True)
    fig_architecture(o)
    fig_pipeline(o)
    fig_mutation(o)
    print("figures ->", o)
