"""E3: transparency and minimal intervention.

Transparency: on already-compliant streams the shield is the identity (zero
interventions).  Minimal intervention: on a large fuzz, every committed edit is
checked against a brute-force per-step oracle (the least-cost safe enactable
edit), the *certified-minimal rate*, which the certificate's minimality check
re-derives independently.  I additionally run a *global* exhaustive optimiser on
short trajectories to measure how often the per-step (myopic) optimum coincides
with the whole-trajectory optimum.
"""

from __future__ import annotations

import itertools
import json
import os
import random
from statistics import mean, pstdev

from _common import (default_policy, default_adapter, full_caps, make_suite,
                     run_shield)
from reinskit import Action, Shield

SEEDS = list(range(12))
HERE = os.path.dirname(__file__)
RESULTS = os.path.join(HERE, "..", "results")

TOOLS = ["read_record", "send_email", "transfer_funds", "delete_all", "process",
         "authorize", "audit_log", "respond"]


def random_trajectory(rng, length):
    out = []
    for _ in range(length):
        n = rng.choice(TOOLS)
        args = {"to": "a@partner.com"} if n == "send_email" else (
            {"to": "acct"} if n == "transfer_funds" else {})
        out.append(Action.of(n, args))
    return out


def oracle_step(shield, caps, action):
    best = None
    for e in caps.candidate_edits(action):
        seq = [shield._events_of(a) for a in e.output_actions(action)]
        if shield.guard.simulate(seq):
            c = caps.costs.cost(e)
            best = c if best is None else min(best, c)
    return best


def global_optimum(policy, caps, adapter, actions, init_bound=None):
    """Least-total-cost sound edit *sequence* over the whole trajectory, by
    branch-and-bound (allow-first ordering + prune once the partial cost reaches
    the best complete solution found).  Remaining-cost lower bound is 0, so any
    partial cost >= best is pruned.  Tractable for the short trajectories used
    here; returns None if no sound sequence exists."""
    from reinskit import BehaviorGuard

    best = [float("inf") if init_bound is None else init_bound]
    cand = [sorted(caps.candidate_edits(a), key=caps.costs.cost) for a in actions]

    def rec(i, guard, acc):
        if acc >= best[0]:
            return
        if i == len(actions):
            best[0] = acc
            return
        for e in cand[i]:
            ec = caps.costs.cost(e)
            if acc + ec >= best[0]:
                break                               # sorted: the rest cost more
            seq = [adapter.events_of(a) for a in e.output_actions(actions[i])]
            if not guard.simulate(seq):
                continue
            g2 = guard.clone()
            for ev in seq:
                g2.step(ev)
            rec(i + 1, g2, acc + ec)

    rec(0, BehaviorGuard(policy), 0.0)
    return None if best[0] == float("inf") else best[0]


def greedy_total(policy, caps, adapter, actions):
    sh = Shield(policy, caps, adapter=adapter)
    return sum(sh.decide(a).cost for a in actions)


def main():
    policy = default_policy()
    adapter = default_adapter()
    caps = full_caps()

    # transparency: intervention rate on compliant vs full suite
    compliant_rate, suite_rate = [], []
    for s in SEEDS:
        tasks = make_suite(s, n_each=20)
        comp = [t for t in tasks if t.name == "benign_compliant"]
        interv_comp = 0
        steps_comp = 0
        for t in comp:
            o = run_shield(policy, caps, adapter, t)
            interv_comp += o.interventions
            steps_comp += len(t.actions)
        compliant_rate.append(interv_comp / max(1, steps_comp))

    # minimal intervention: per-step certified-minimal rate over a fuzz
    matched, total = 0, 0
    rng = random.Random(0)
    for s in SEEDS:
        r = random.Random(1000 + s)
        for _ in range(60):
            sh = Shield(policy, caps, adapter=adapter)
            for a in random_trajectory(r, r.randint(3, 20)):
                exp = oracle_step(sh, caps, a)
                dec = sh.decide(a)
                total += 1
                if dec.cost == exp:
                    matched += 1
    certified_minimal = matched / total

    # per-step vs global optimum on short trajectories (branch-and-bound)
    g_match, g_total, max_gap = 0, 0, 0.0
    for s in SEEDS:
        r = random.Random(5000 + s)
        for _ in range(40):
            acts = random_trajectory(r, r.randint(2, 6))
            gtot = greedy_total(policy, caps, adapter, acts)
            gopt = global_optimum(policy, caps, adapter, acts, init_bound=gtot + 1e-6)
            if gopt is None:
                continue
            g_total += 1
            if abs(gtot - gopt) < 1e-9:
                g_match += 1
            max_gap = max(max_gap, gtot - gopt)

    out = {
        "seeds": SEEDS,
        "transparency_intervention_rate_compliant_mean": mean(compliant_rate),
        "transparency_intervention_rate_compliant_std": pstdev(compliant_rate),
        "certified_minimal_rate": certified_minimal,
        "n_steps_checked": total,
        "per_step_vs_global_agreement": g_match / max(1, g_total),
        "n_trajectories_global": g_total,
        "max_total_cost_gap": max_gap,
    }
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "transparency.json"), "w") as f:
        json.dump(out, f, indent=2)

    print("E3 transparency / minimal intervention:")
    print(f"  intervention rate on compliant streams: "
          f"{out['transparency_intervention_rate_compliant_mean']:.3f} (identity)")
    print(f"  certified-minimal rate (vs per-step oracle): {certified_minimal:.4f} "
          f"over {total} steps")
    print(f"  per-step == global optimum on short trajectories: "
          f"{out['per_step_vs_global_agreement']:.4f} ({g_total} traj), "
          f"max gap {max_gap:.1f}")
    return out


if __name__ == "__main__":
    main()
