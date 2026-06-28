"""E2: soundness and shieldability.

Empirical confirmation of the soundness theorem: on a large fuzz of adversarial
trajectories, a shieldable deployment's shielded sessions are *always* sound
(no monitor ever violated), with zero enforcement failures.  I also confirm the
static ``is_shieldable`` check predicts when soundness can be guaranteed without
halting: a deployment that cannot insert a required audit and has no escalation
channel does suffer enforcement failures, exactly as the check warns.
"""

from __future__ import annotations

import json
import os
import random
from statistics import mean, pstdev

from _common import default_policy, default_adapter, full_caps
from reinskit import (Policy, response, Action, AdapterConfig, ToolCallAdapter,
                      Capabilities, Shield, is_shieldable)

SEEDS = list(range(12))
N_TRAJ = 200
HERE = os.path.dirname(__file__)
RESULTS = os.path.join(HERE, "..", "results")

TOOLS = ["read_record", "send_email", "transfer_funds", "delete_all", "process",
         "authorize", "audit_log", "respond", "ssh_exfil"]


def random_trajectory(rng, length):
    acts = []
    for _ in range(length):
        name = rng.choice(TOOLS)
        args = {"to": rng.choice(["a@partner.com", "internal"])} if name == "send_email" else \
               ({"to": "acct"} if name == "transfer_funds" else {})
        acts.append(Action.of(name, args))
    return acts


def fuzz(policy, caps, adapter, seed):
    rng = random.Random(seed)
    sound = 0
    failures = 0
    for _ in range(N_TRAJ):
        sh = Shield(policy, caps, adapter=adapter)
        for a in random_trajectory(rng, rng.randint(3, 25)):
            dec = sh.decide(a)
            if dec.enforcement_failed:
                failures += 1
        if sh.session_sound:
            sound += 1
    return sound / N_TRAJ, failures


def main():
    policy = default_policy()
    adapter = default_adapter()

    # 1) shieldable deployment -> always sound, zero failures
    reins_sound, reins_fail = [], []
    for s in SEEDS:
        sr, nf = fuzz(policy, full_caps(), adapter, s)
        reins_sound.append(sr); reins_fail.append(nf)

    # 2) non-shieldable deployment (no insertable audit, no escalation)
    bad_caps = Capabilities(substitutions={"delete_all": [Action.of("archive")]},
                            insertables={"authorize": Action.of("authorize")},
                            escalation=False)
    ok_bad, gaps = is_shieldable(policy, bad_caps)
    bad_sound, bad_fail = [], []
    for s in SEEDS:
        sr, nf = fuzz(policy, bad_caps, adapter, s)
        bad_sound.append(sr); bad_fail.append(nf)

    # 3) same gaps, but with escalation -> defer keeps it sound (trivial guarantee)
    esc_caps = Capabilities(substitutions={"delete_all": [Action.of("archive")]},
                            insertables={"authorize": Action.of("authorize")},
                            escalation=True)
    esc_sound = []
    for s in SEEDS:
        sr, _ = fuzz(policy, esc_caps, adapter, s)
        esc_sound.append(sr)

    out = {
        "seeds": SEEDS, "n_trajectories_per_seed": N_TRAJ,
        "shieldable_full": {
            "is_shieldable": is_shieldable(policy, full_caps())[0],
            "soundness_rate_mean": mean(reins_sound), "soundness_rate_std": pstdev(reins_sound),
            "enforcement_failures_total": sum(reins_fail),
        },
        "nonshieldable_no_escalation": {
            "is_shieldable": ok_bad, "shieldability_gaps": gaps,
            "soundness_rate_mean": mean(bad_sound), "soundness_rate_std": pstdev(bad_sound),
            "enforcement_failures_total": sum(bad_fail),
        },
        "gaps_with_escalation": {
            "soundness_rate_mean": mean(esc_sound), "soundness_rate_std": pstdev(esc_sound),
        },
    }
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "soundness.json"), "w") as f:
        json.dump(out, f, indent=2)

    print("E2 soundness:")
    print(f"  full caps (shieldable={out['shieldable_full']['is_shieldable']}): "
          f"soundness={out['shieldable_full']['soundness_rate_mean']:.3f}, "
          f"failures={out['shieldable_full']['enforcement_failures_total']}")
    print(f"  non-shieldable, no escalation (is_shieldable={ok_bad}): "
          f"soundness={out['nonshieldable_no_escalation']['soundness_rate_mean']:.3f}, "
          f"failures={out['nonshieldable_no_escalation']['enforcement_failures_total']}")
    print(f"  same gaps + escalation: soundness="
          f"{out['gaps_with_escalation']['soundness_rate_mean']:.3f}")
    return out


if __name__ == "__main__":
    main()
