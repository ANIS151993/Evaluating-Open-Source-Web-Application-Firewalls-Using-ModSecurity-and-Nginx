#!/usr/bin/env python3
"""
Builds the six chart images used on the project website (docs/assets/charts/):
distribution plot, pie chart, violin plot, heatmap, pair plot, joint plot.

Data provenance (no fabricated numbers):
  - Pie chart, pair plot, joint plot: the paper's own published tables
    (Table II attack composition; Table VI/VII latency & resource figures),
    reproduced verbatim from main.tex.
  - Distribution plot, violin plot, heatmap: this repository's OWN lab run
    (results/chart-data/*.json), captured earlier in this session by
    actually running scripts/load_test.py and scripts/run_attacks.py against
    the live Docker stack. These are a live-lab benchmark, not a replay of
    the paper's original data-collection run -- labeled as such in captions.

Palette: dataviz skill reference palette (references/palette.md).
"""
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import numpy as np
import pandas as pd
import seaborn as sns

HERE = Path(__file__).parent
LAB = HERE.parent
OUT = LAB.parent / "docs" / "assets" / "charts"
OUT.mkdir(parents=True, exist_ok=True)
CHART_DATA = LAB / "results" / "chart-data"

# --- palette (light mode, from the dataviz skill reference palette) --------
BLUE = "#2a78d6"
ORANGE = "#eb6834"
AQUA = "#1baf7a"
YELLOW = "#eda100"
MAGENTA = "#e87ba4"
GREEN = "#008300"
VIOLET = "#4a3aa7"
RED = "#e34948"
CATEGORICAL = [BLUE, ORANGE, AQUA, YELLOW, MAGENTA, VIOLET, RED, GREEN]

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"

sns.set_theme(style="whitegrid", rc={
    "axes.facecolor": SURFACE,
    "figure.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "axes.edgecolor": GRID,
    "grid.color": GRID,
    "text.color": INK,
    "axes.labelcolor": INK,
    "xtick.color": INK2,
    "ytick.color": INK2,
    "font.family": "sans-serif",
})

DPI = 180


def save(fig, name):
    fig.savefig(OUT / name, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {OUT / name}")


# ============================================================================
# 1. PIE CHART -- Table II: Malicious Traffic Composition (paper, verbatim)
# ============================================================================
def pie_chart():
    labels = ["SQL Injection", "Cross-Site\nScripting", "Local File\nInclusion",
              "Remote Code\nExecution", "SSRF", "Path\nTraversal"]
    counts = [3600, 2400, 1200, 800, 600, 600]  # Table II, main.tex
    colors = CATEGORICAL[:6]

    fig, ax = plt.subplots(figsize=(6.4, 6.4))
    wedges, _, autotexts = ax.pie(
        counts, colors=colors, startangle=90, counterclock=False,
        autopct=lambda p: f"{p:.0f}%", pctdistance=0.78,
        wedgeprops=dict(width=0.42, edgecolor=SURFACE, linewidth=2),
        textprops=dict(color=INK, fontsize=10, fontweight="bold"),
    )
    ax.legend(wedges, [f"{l.replace(chr(10),' ')} ({c:,})" for l, c in zip(labels, counts)],
               loc="center left", bbox_to_anchor=(1.02, 0.5), frameon=False, fontsize=10)
    ax.set_title("Malicious Traffic Composition (9,200 requests)\nTable II, paper", fontsize=12, pad=14)
    save(fig, "pie_attack_composition.png")


# ============================================================================
# 2. PAIR PLOT -- Table VI/VII: RPS, latency, CPU, memory (paper, verbatim)
# ============================================================================
def pair_plot():
    df = pd.DataFrame({
        "RPS": [100, 500, 1000, 2500, 5000],
        "Median Latency (ms)": [18.7, 23.8, 35.2, 44.1, 54.8],   # +WAF, Table VI
        "P99 Latency (ms)": [36.4, 52.1, 82.6, 112.7, 149.2],     # +WAF, Table VI
    })
    # CPU/Mem only published at 1,000 and 5,000 RPS (Table VII); interpolate
    # the 500/2500 points linearly purely for this 5-point overview chart --
    # noted in the caption, not presented as separately measured rows.
    cpu = np.interp(df["RPS"], [1000, 5000], [37, 82])
    mem = np.interp(df["RPS"], [1000, 5000], [512, 680])
    df["CPU (%)"] = np.round(cpu, 1)
    df["Memory (MB)"] = np.round(mem, 0)

    g = sns.pairplot(
        df, vars=["Median Latency (ms)", "P99 Latency (ms)", "CPU (%)", "Memory (MB)"],
        corner=True, plot_kws=dict(s=90, color=BLUE, edgecolor=SURFACE, linewidth=1),
        diag_kws=dict(color=BLUE, fill=True, alpha=0.5),
    )
    g.figure.set_size_inches(8, 8)
    for ax in g.axes.flatten():
        if ax is not None:
            ax.set_facecolor(SURFACE)
            ax.grid(color=GRID, linewidth=0.6)
    g.figure.suptitle("WAF-Enabled Scaling Behavior Across Load Levels\n(Tables VI-VII, paper; CPU/Mem interpolated between published points)",
                       y=1.02, fontsize=11)
    g.figure.savefig(OUT / "pairplot_scaling.png", dpi=DPI, bbox_inches="tight")
    plt.close(g.figure)
    print(f"wrote {OUT / 'pairplot_scaling.png'}")


# ============================================================================
# 3. JOINT PLOT -- CPU utilization vs. request rate + linear fit (paper, Fig.10)
# ============================================================================
def joint_plot():
    rps = np.array([1000, 2500, 5000])
    cpu = np.array([37, 55, 82])  # Fig. 10 data points, main.tex

    g = sns.jointplot(x=rps, y=cpu, kind="scatter", height=6.4,
                       color=BLUE, marginal_kws=dict(bins=6, fill=True))
    x_line = np.linspace(0, 5500, 100)
    y_line = 8.2 + 0.0147 * x_line  # Eq. (1), main.tex
    g.ax_joint.plot(x_line, y_line, color=ORANGE, linewidth=2, linestyle="--",
                     label="Linear fit ($R^2=0.987$)")
    g.ax_joint.scatter(rps, cpu, color=BLUE, s=110, zorder=5, edgecolor=SURFACE, linewidth=1.5)
    g.ax_joint.set_xlabel("Request Rate (RPS)")
    g.ax_joint.set_ylabel("CPU Utilization (%)")
    g.ax_joint.legend(frameon=False, loc="upper left")
    g.ax_joint.set_facecolor(SURFACE)
    g.figure.suptitle("CPU Utilization vs. Request Rate (Eq. 1, Fig. 10 of the paper)", y=1.02, fontsize=11)
    g.figure.savefig(OUT / "jointplot_cpu_scaling.png", dpi=DPI, bbox_inches="tight")
    plt.close(g.figure)
    print(f"wrote {OUT / 'jointplot_cpu_scaling.png'}")


# ============================================================================
# 4. DISTRIBUTION PLOT -- real per-request latency samples from THIS repo's lab
# ============================================================================
def dist_plot():
    raw_baseline = json.loads((CHART_DATA / "raw_baseline_c10.json").read_text())
    raw_waf = json.loads((CHART_DATA / "raw_waf_c10.json").read_text())

    fig, ax = plt.subplots(figsize=(8, 5))
    sns.histplot(raw_baseline, color=CATEGORICAL[0], label="Baseline (no WAF)",
                 kde=True, stat="density", alpha=0.45, ax=ax, edgecolor=SURFACE)
    sns.histplot(raw_waf, color=CATEGORICAL[1], label="WAF enabled",
                 kde=True, stat="density", alpha=0.45, ax=ax, edgecolor=SURFACE)
    ax.set_xlabel("Request latency (ms)")
    ax.set_ylabel("Density")
    ax.set_title("Live Lab Benchmark: Request Latency Distribution (concurrency=10)\n"
                  "Measured in this repo's own Docker lab -- not the paper's original dataset", fontsize=11)
    ax.legend(frameon=False)
    save(fig, "distplot_latency.png")


# ============================================================================
# 5. VIOLIN PLOT -- real per-request latencies, baseline vs WAF, two concurrency levels
# ============================================================================
def violin_plot():
    rows = []
    for c in (10, 30):
        for target, label in (("baseline", "Baseline"), ("waf", "+WAF")):
            data = json.loads((CHART_DATA / f"raw_{target}_c{c}.json").read_text())
            for v in data:
                rows.append({"Concurrency": c, "Configuration": label, "Latency (ms)": v})
    df = pd.DataFrame(rows)

    fig, ax = plt.subplots(figsize=(8, 5.5))
    sns.violinplot(data=df, x="Concurrency", y="Latency (ms)", hue="Configuration",
                    split=True, inner="quartile", palette=[CATEGORICAL[0], CATEGORICAL[1]], ax=ax)
    ax.set_title("Live Lab Benchmark: Latency Distribution by Concurrency\n"
                  "Measured in this repo's own Docker lab -- not the paper's original dataset", fontsize=11)
    ax.legend(frameon=False, title=None)
    save(fig, "violinplot_latency.png")


# ============================================================================
# 6. HEATMAP -- real audit-log rule hits x attack category, from THIS repo's lab
# ============================================================================
def heatmap():
    log_path = CHART_DATA / "waf_raw_for_charts.log"
    text = log_path.read_text(errors="ignore")

    counts = defaultdict(Counter)
    for line in text.splitlines():
        idx = line.find('{"transaction"')
        if idx == -1:
            continue
        try:
            tx = json.loads(line[idx:])
        except json.JSONDecodeError:
            continue
        transaction = tx.get("transaction", {})
        headers = transaction.get("request", {}).get("headers", {})
        category = headers.get("X-Test-Category")
        if not category:
            continue
        for m in transaction.get("messages", []):
            rule_id = m.get("details", {}).get("ruleId")
            if rule_id:
                counts[category][rule_id] += 1

    df = pd.DataFrame(counts).fillna(0).astype(int)
    # keep the rules with the most total hits so the matrix stays readable
    top_rules = df.sum(axis=1).sort_values(ascending=False).head(12).index
    df = df.loc[top_rules]
    df = df[sorted(df.columns)]

    fig, ax = plt.subplots(figsize=(7.5, 6.5))
    cmap = sns.light_palette(BLUE, as_cmap=True)
    sns.heatmap(df, annot=True, fmt="d", cmap=cmap, linewidths=1, linecolor=SURFACE,
                cbar_kws={"label": "Rule hits"}, ax=ax)
    ax.set_xlabel("Attack category (this repo's lab corpus)")
    ax.set_ylabel("CRS rule ID")
    ax.set_title("Live Lab Benchmark: CRS Rule Hits by Attack Category\n"
                  "Measured in this repo's own Docker lab -- not the paper's original dataset", fontsize=11)
    save(fig, "heatmap_rules_by_category.png")


if __name__ == "__main__":
    pie_chart()
    pair_plot()
    joint_plot()
    dist_plot()
    violin_plot()
    heatmap()
