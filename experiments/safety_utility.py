"""E1: the safety/utility frontier.

The headline result.  On one synthetic suite I measure, for three regimes,
attack success rate (ASR; lower better, on attack tasks) and Completion-under-
Policy (CuP; higher better, on benign tasks).  ``noshield`` is unsafe but
complete; ``block`` is safe but pays a large utility tax on benign tasks that
omit a required prerequisite; ``reins`` is safe *and* keeps utility, dominating
the frontier.  I also sweep capability richness to trace the frontier REINS
moves along at fixed (zero) ASR.
"""

from __future__ import annotations

import json
import os
from statistics import mean, pstdev

from _common import (default_policy, default_adapter, full_caps, block_caps,
                     make_suite, run_noshield, run_shield, cup, attack_harm,
                     goal_done)
from reinskit import Capabilities, CostModel, Action

SEEDS = list(range(12))
HERE = os.path.dirname(__file__)
RESULTS = os.path.join(HERE, "..", "results")


def _eval_regime(run_fn, tasks):
    benign = [t for t in tasks if t.kind == "benign"]
    attack = [t for t in tasks if t.kind == "attack"]
    cup_rate = mean(1.0 if cup(t, run_fn(t)) else 0.0 for t in benign)
    asr = mean(1.0 if attack_harm(t, run_fn(t)) else 0.0 for t in attack)
    return cup_rate, asr


def _caps_variants():
    """Capability ladders for the frontier sweep (all keep ASR = 0)."""
    archive = {"delete_all": [Action.of("archive")]}
    audit = {"audit_log": Action.of("audit_log")}
    authz = {"authorize": Action.of("authorize")}
    return {
        "block (suppress only)": Capabilities(escalation=True),
        "+substitute": Capabilities(substitutions=archive, escalation=True),
        "+insert-authorize": Capabilities(substitutions=archive,
                                          insertables=dict(authz), escalation=True),
        "+insert-audit (full)": Capabilities(substitutions=archive,
                                             insertables={**authz, **audit},
                                             escalation=True),
    }


def main():
    policy = default_policy()
    adapter = default_adapter()

    regimes = {
        "noshield": lambda t: run_noshield(policy, adapter, t),
        "block": lambda t: run_shield(policy, block_caps(), adapter, t),
        "reins": lambda t: run_shield(policy, full_caps(), adapter, t),
    }

    per_regime = {r: {"cup": [], "asr": []} for r in regimes}
    # per benign-task-type CuP, to expose *where* the block tax falls
    bt_types = ["benign_compliant", "benign_forgot_authorize", "benign_forgot_audit"]
    by_type = {r: {bt: [] for bt in bt_types} for r in regimes}

    for seed in SEEDS:
        tasks = make_suite(seed, n_each=20)
        for r, fn in regimes.items():
            c, a = _eval_regime(fn, tasks)
            per_regime[r]["cup"].append(c)
            per_regime[r]["asr"].append(a)
            for bt in bt_types:
                sub = [t for t in tasks if t.name == bt]
                if sub:
                    by_type[r][bt].append(
                        mean(1.0 if cup(t, fn(t)) else 0.0 for t in sub))

    summary = {r: {"cup_mean": mean(per_regime[r]["cup"]),
                   "cup_std": pstdev(per_regime[r]["cup"]),
                   "asr_mean": mean(per_regime[r]["asr"]),
                   "asr_std": pstdev(per_regime[r]["asr"])}
               for r in regimes}
    by_type_summary = {r: {bt: {"cup_mean": mean(by_type[r][bt]),
                                "cup_std": pstdev(by_type[r][bt])}
                           for bt in bt_types} for r in regimes}

    # capability-richness frontier sweep (CuP at fixed ASR=0)
    frontier = []
    for label, caps in _caps_variants().items():
        cups, asrs = [], []
        for seed in SEEDS:
            tasks = make_suite(seed, n_each=20)
            c, a = _eval_regime(lambda t: run_shield(policy, caps, adapter, t), tasks)
            cups.append(c); asrs.append(a)
        frontier.append({"label": label, "cup_mean": mean(cups),
                         "cup_std": pstdev(cups), "asr_mean": mean(asrs)})

    out = {"seeds": SEEDS, "summary": summary, "by_benign_type": by_type_summary,
           "frontier": frontier}
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "safety_utility.json"), "w") as f:
        json.dump(out, f, indent=2)

    print("E1 safety/utility:")
    for r in regimes:
        s = summary[r]
        print(f"  {r:9s}  CuP={s['cup_mean']:.3f}+-{s['cup_std']:.3f}  "
              f"ASR={s['asr_mean']:.3f}+-{s['asr_std']:.3f}")
    print("  frontier (CuP @ ASR=0):")
    for p in frontier:
        print(f"    {p['label']:24s} CuP={p['cup_mean']:.3f}  ASR={p['asr_mean']:.3f}")
    return out


if __name__ == "__main__":
    main()
