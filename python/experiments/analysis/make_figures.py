import csv
from collections import OrderedDict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
FIGS = ROOT / "figures"

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["DejaVu Serif"],
    "mathtext.fontset": "dejavuserif",
    "font.size": 8,
    "axes.labelsize": 8,
    "legend.fontsize": 7,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
})


def exp01():
    fields = ["timestamp_utc", "commit_hash", "os", "cpu", "target_time_seconds", "run_id", "actual_solve_time_seconds"]
    groups = OrderedDict()
    with open(DATA / "exp01_results.csv", newline="", encoding="utf-8") as fp:
        for row in csv.DictReader(fp, fieldnames=fields): groups.setdefault(int(row["target_time_seconds"]), []).append(float(row["actual_solve_time_seconds"]))

    targets = np.array(list(groups))
    means = np.array([np.mean(v) for v in groups.values()])
    sds = np.array([np.std(v, ddof=1) for v in groups.values()])

    fig, ax = plt.subplots(figsize=(3.4, 2.5))
    ax.plot(targets, targets, "--", color="0.35", lw=1.0, label="Solve time = configured duration")
    for t, values in groups.items():
        ax.scatter([t] * len(values), values, s=9, color="#1f77b4", alpha=0.3, edgecolors="none", zorder=2)
    ax.errorbar(targets, means, yerr=sds, fmt="o-", color="#1f77b4", ms=3.5, lw=1.2, capsize=2.5, zorder=3, label=r"Measured (mean $\pm$1 SD, 10 runs)")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log", base=2)
    ticks = [1, 2, 4, 8, 16]
    ax.set_xticks(ticks, [str(t) for t in ticks])
    ax.set_yticks(ticks, [str(t) for t in ticks])
    ax.minorticks_off()
    ax.set_xlabel("Configured lock duration (s)")
    ax.set_ylabel("Measured solve time (s)")
    ax.grid(True, ls=":", lw=0.6, color="0.75")
    ax.legend(loc="upper left", frameon=True)
    fig.tight_layout(pad=0.3)
    fig.savefig(FIGS / "exp01_lock_duration_scaling.pdf")
    plt.close(fig)


def exp03():
    with open(DATA / "exp03_raw_results.csv", newline="", encoding="utf-8") as fp:
        data = list(csv.DictReader(fp))
    ks = sorted({int(r["k"]) for r in data})
    js = sorted({int(r["shares_used"]) for r in data})
    returned = np.zeros((len(ks), len(js)))
    correct = np.zeros((len(ks), len(js)))
    for r in data:
        i, j = ks.index(int(r["k"])), js.index(int(r["shares_used"]))
        returned[i, j] = r["success"] == "True"
        correct[i, j] = r["matches_original"] == "True"

    cmap = matplotlib.colors.ListedColormap(["#f2f2f2", "#2a7f62"])
    fig, axes = plt.subplots(2, 1, figsize=(3.4, 2.6), sharex=True)
    panels = [
        (axes[0], returned, "(a) reconstruct() returned a key without error"),
        (axes[1], correct, "(b) Returned key equals the original key"),
    ]
    for ax, grid, title in panels:
        ax.imshow(grid, cmap=cmap, vmin=0, vmax=1, aspect="auto")
        for i in range(len(ks)):
            for j in range(len(js)):
                ax.text(j, i, "yes" if grid[i, j] else "no", ha="center", va="center", fontsize=5.5, color="white" if grid[i, j] else "0.35")
            jb = js.index(ks[i]) - 0.5
            ax.plot([jb, jb], [i - 0.5, i + 0.5], color="#c0392b", lw=1.4)
        ax.set_yticks(range(len(ks)), [f"k={k}" for k in ks])
        ax.set_xticks(range(len(js)), [str(j) for j in js])
        ax.set_xticks(np.arange(-0.5, len(js)), minor=True)
        ax.set_yticks(np.arange(-0.5, len(ks)), minor=True)
        ax.grid(which="minor", color="white", lw=0.8)
        ax.tick_params(which="minor", length=0)
        ax.set_title(title, fontsize=7.5, loc="left", pad=3)
    axes[1].set_xlabel("Number of shares supplied, $j$ (first $j$ of $n=10$)")
    fig.tight_layout(pad=0.3, h_pad=0.6)
    fig.savefig(FIGS / "exp03_threshold_reconstruction.pdf")
    plt.close(fig)


if __name__ == "__main__":
    exp01()
    exp03()
    print("wrote figures/exp01_lock_duration_scaling.pdf and "
          "figures/exp03_threshold_reconstruction.pdf")
