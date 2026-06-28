"""Build every figure in the paper from results/*.json.

Run after experiments/run_all.py.  Writes paper/figures/*.{pdf,png}.  Pure
matplotlib; no seaborn, no network.
"""

from __future__ import annotations

import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(__file__)
RESULTS = os.path.join(HERE, "..", "results")
FIGS = os.path.join(HERE, "..", "paper", "figures")

TEAL = "#0d9488"
CORAL = "#ef4444"
SLATE = "#334155"
AMBER = "#d97706"
INDIGO = "#4f46e5"

plt.rcParams.update({
    "font.size": 10, "axes.titlesize": 11, "axes.spines.top": False,
    "axes.spines.right": False, "figure.dpi": 120, "savefig.bbox": "tight",
})


def load(name):
    with open(os.path.join(RESULTS, name)) as f:
        return json.load(f)


def save(fig, name):
    os.makedirs(FIGS, exist_ok=True)
    fig.savefig(os.path.join(FIGS, name + ".pdf"))
    fig.savefig(os.path.join(FIGS, name + ".png"), dpi=150)
    plt.close(fig)


def fig_frontier():
    d = load("safety_utility.json")
    s = d["summary"]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9.2, 3.6))

    # (a) the safety/utility plane
    order = [("noshield", CORAL, "o"), ("block", AMBER, "s"), ("reins", TEAL, "*")]
    for r, c, m in order:
        x = 1 - s[r]["asr_mean"]                 # safety = 1 - ASR
        y = s[r]["cup_mean"]
        ax1.scatter([x], [y], s=260 if m == "*" else 150, c=c, marker=m,
                    edgecolors="k", linewidths=0.6, zorder=3, label=r)
        ax1.annotate(r, (x, y), textcoords="offset points", xytext=(8, 6),
                     fontsize=9)
    ax1.set_xlabel("safety  (1 - attack success rate)")
    ax1.set_ylabel("utility  (Completion-under-Policy)")
    ax1.set_title("(a) safety/utility plane")
    ax1.set_xlim(-0.05, 1.08); ax1.set_ylim(-0.05, 1.12)
    ax1.axhspan(0.9, 1.12, 0.9, 1.0, color=TEAL, alpha=0.07)
    ax1.text(0.55, 1.05, "ideal", color=TEAL, fontsize=8)

    # (b) capability-richness ladder (all at ASR 0)
    fr = d["frontier"]
    labels = [p["label"].replace(" (", "\n(") for p in fr]
    vals = [p["cup_mean"] for p in fr]
    errs = [p["cup_std"] for p in fr]
    ax2.bar(range(len(fr)), vals, yerr=errs, color=[AMBER, AMBER, INDIGO, TEAL],
            edgecolor="k", linewidth=0.5, capsize=3)
    ax2.set_xticks(range(len(fr)))
    ax2.set_xticklabels(labels, fontsize=7.5, rotation=12)
    ax2.set_ylabel("Completion-under-Policy")
    ax2.set_title("(b) utility vs capability richness  (ASR $=0$ throughout)")
    ax2.set_ylim(0, 1.1)
    save(fig, "frontier")


def fig_blocktax():
    d = load("safety_utility.json")
    bt = d["by_benign_type"]
    types = ["benign_compliant", "benign_forgot_authorize", "benign_forgot_audit"]
    labels = ["compliant", "forgot\nauthorize", "forgot\naudit"]
    import numpy as np
    x = np.arange(len(types)); w = 0.38
    fig, ax = plt.subplots(figsize=(5.4, 3.4))
    ax.bar(x - w/2, [bt["block"][t]["cup_mean"] for t in types], w, label="block",
           color=AMBER, edgecolor="k", linewidth=0.5)
    ax.bar(x + w/2, [bt["reins"][t]["cup_mean"] for t in types], w, label="REINS",
           color=TEAL, edgecolor="k", linewidth=0.5)
    ax.set_xticks(x); ax.set_xticklabels(labels)
    ax.set_ylabel("Completion-under-Policy"); ax.set_ylim(0, 1.1)
    ax.set_title("Where the block tax falls (benign tasks)")
    ax.legend(frameon=False)
    save(fig, "blocktax")


def fig_soundness():
    d = load("soundness.json")
    confs = [("full\n(shieldable)", d["shieldable_full"], TEAL),
             ("gaps +\nescalation", d["gaps_with_escalation"], INDIGO),
             ("gaps, no\nescalation", d["nonshieldable_no_escalation"], CORAL)]
    fig, ax = plt.subplots(figsize=(5.0, 3.4))
    xs = range(len(confs))
    ax.bar(xs, [c[1]["soundness_rate_mean"] for c in confs],
           yerr=[c[1].get("soundness_rate_std", 0) for c in confs],
           color=[c[2] for c in confs], edgecolor="k", linewidth=0.5, capsize=3)
    ax.set_xticks(list(xs)); ax.set_xticklabels([c[0] for c in confs])
    ax.set_ylabel("fraction of sessions sound"); ax.set_ylim(0, 1.12)
    ax.set_title("Soundness vs. shieldability")
    for i, c in enumerate(confs):
        ax.text(i, c[1]["soundness_rate_mean"] + 0.02,
                f"{c[1]['soundness_rate_mean']:.2f}", ha="center", fontsize=8)
    save(fig, "soundness")


def fig_minimality():
    d = load("transparency.json")
    bars = [("certified-\nminimal\n(per-step)", d["certified_minimal_rate"], TEAL),
            ("per-step =\nglobal opt", d["per_step_vs_global_agreement"], INDIGO),
            ("identity on\ncompliant", 1 - d["transparency_intervention_rate_compliant_mean"],
             AMBER)]
    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    xs = range(len(bars))
    ax.bar(xs, [b[1] for b in bars], color=[b[2] for b in bars], edgecolor="k",
           linewidth=0.5)
    ax.set_xticks(list(xs)); ax.set_xticklabels([b[0] for b in bars], fontsize=8.5)
    ax.set_ylabel("rate"); ax.set_ylim(0, 1.12)
    ax.set_title("Transparency & minimal intervention")
    for i, b in enumerate(bars):
        ax.text(i, b[1] + 0.02, f"{b[1]:.3f}", ha="center", fontsize=8)
    save(fig, "minimality")


def fig_certificate():
    d = load("certificate.json")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9.0, 3.4))
    tr = d["tamper_detection_rate"]
    names = list(tr.keys())
    ax1.barh(range(len(names)), [tr[n] for n in names], color=TEAL, edgecolor="k",
             linewidth=0.5)
    ax1.set_yticks(range(len(names)))
    ax1.set_yticklabels([n.replace("_", " ") for n in names], fontsize=8.5)
    ax1.set_xlim(0, 1.1); ax1.set_xlabel("detection rate")
    ax1.set_title("(a) tamper detection")
    sc = d["verify_scaling"]
    ax2.plot([p["entries"] for p in sc], [p["verify_us"] for p in sc], "o-",
             color=INDIGO)
    ax2.set_xlabel("ledger entries"); ax2.set_ylabel("verification time ($\\mu$s)")
    ax2.set_title("(b) verification is linear")
    save(fig, "certificate")


def fig_systems():
    d = load("systems.json")
    sc = d["latency_vs_constraints"]
    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    ax.plot([p["constraints"] for p in sc], [p["median_us"] for p in sc], "o-",
            color=TEAL)
    ax.set_xlabel("number of policy constraints")
    ax.set_ylabel("median shield-step latency ($\\mu$s)")
    ax.set_title("Shield-step latency vs. policy size")
    lat = d["latency"]
    ax.text(0.04, 0.92, f"deployed policy: {lat['median_us']:.1f} $\\mu$s median, "
            f"{lat['candidate_set_mean']:.0f} candidates/step",
            transform=ax.transAxes, fontsize=8, va="top")
    ax.set_ylim(0, max(p["median_us"] for p in sc) * 1.25)
    save(fig, "systems")


def fig_robustness():
    d = load("robustness.json")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9.0, 3.4))
    cur = d["adaptive_exfiltration_curve"]
    att = [p["attempted"] for p in cur]
    ax1.plot(att, att, "--", color=SLATE, label="no shield (= attempted)")
    ax1.plot(att, [p["executed"] for p in cur], "o-", color=TEAL,
             label="REINS (executed)")
    ax1.axhline(d["export_budget"], color=CORAL, lw=1, ls=":",
                label=f"budget = {d['export_budget']}")
    ax1.set_xlabel("exfiltration attempts"); ax1.set_ylabel("external sends executed")
    ax1.set_title("(a) damage is bounded"); ax1.legend(frameon=False, fontsize=8)
    abl = d["capability_ablation"]
    order = ["full", "no_insert", "no_insert_no_escalation", "block"]
    labels = ["full", "no\ninsert", "no insert,\nno escal.", "block"]
    cols = [TEAL, INDIGO, CORAL, AMBER]
    ax2.bar(range(len(order)), [abl[k]["cup_mean"] for k in order], color=cols,
            edgecolor="k", linewidth=0.5)
    ax2.set_xticks(range(len(order))); ax2.set_xticklabels(labels, fontsize=8)
    ax2.set_ylabel("benign CuP"); ax2.set_ylim(0, 1.1)
    ax2.set_title("(b) only as good as its capabilities")
    save(fig, "robustness")


def main():
    fig_frontier(); fig_blocktax(); fig_soundness(); fig_minimality()
    fig_certificate(); fig_systems(); fig_robustness()
    print("figures written to", os.path.abspath(FIGS))


if __name__ == "__main__":
    main()
