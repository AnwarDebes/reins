"""E5: systems characterisation.

Per-step shield latency, the size of the per-step candidate-edit search, the
monitor memory footprint (constant in trajectory length), the certificate size
per entry, and how shield latency scales with the number of constraints.  All on
a single CPU; latencies are wall-clock ``perf_counter`` medians.
"""

from __future__ import annotations

import json
import os
import platform
import random
import statistics
from time import perf_counter

from _common import default_policy, default_adapter, full_caps
from reinskit import (Policy, always, never, bounded_count, response, precedence,
                      Action, AdapterConfig, ToolCallAdapter, Capabilities, Shield,
                      ShieldEngine)

HERE = os.path.dirname(__file__)
RESULTS = os.path.join(HERE, "..", "results")

TOOLS = ["read_record", "send_email", "transfer_funds", "delete_all", "process",
         "authorize", "audit_log", "respond"]


def rand_action(rng):
    n = rng.choice(TOOLS)
    args = {"to": "a@partner.com"} if n == "send_email" else (
        {"to": "acct"} if n == "transfer_funds" else {})
    return Action.of(n, args)


def measure_latency(policy, caps, adapter, n=20000):
    rng = random.Random(0)
    actions = [rand_action(rng) for _ in range(n)]
    sh = Shield(policy, caps, adapter=adapter)
    # candidate-set size
    csizes = [len(caps.candidate_edits(a)) for a in actions[:500]]
    lat = []
    for a in actions:
        if sh._step > 4000:                       # keep monitor windows bounded
            sh = Shield(policy, caps, adapter=adapter)
        t0 = perf_counter()
        sh.decide(a)
        lat.append((perf_counter() - t0) * 1e6)
    lat.sort()
    return {
        "median_us": statistics.median(lat),
        "mean_us": statistics.fmean(lat),
        "p99_us": lat[int(0.99 * len(lat))],
        "candidate_set_mean": statistics.fmean(csizes),
    }


def main():
    policy, adapter, caps = default_policy(), default_adapter(), full_caps()

    latency = measure_latency(policy, caps, adapter)

    # monitor memory (constant in trajectory length)
    from reinskit import BehaviorGuard
    g = BehaviorGuard(policy)
    mem_before = g.memory_bytes
    rng = random.Random(1)
    for _ in range(5000):
        g.step(adapter.events_of(rand_action(rng)))
    mem_after = g.memory_bytes
    constant_memory = (mem_before == mem_after)

    # certificate size per entry
    KEY = b"k" * 32
    eng = ShieldEngine("sz", policy, caps, adapter, key=KEY)
    rng = random.Random(2)
    for _ in range(200):
        eng.observe_action(rand_action(rng))
    cert = eng.seal()
    led = eng.ledger.to_dict()
    led_bytes = len(json.dumps(led).encode())
    cert_bytes = len(json.dumps(cert.to_dict()).encode())
    per_entry = led_bytes / max(1, len(led["entries"]))

    # latency vs number of constraints
    scaling = []
    for k in (1, 5, 10, 20, 40):
        cons = []
        for i in range(k):
            cons.append(bounded_count(f"e{i}", 2, 50))
        pol = Policy("scale", cons)
        lat = measure_latency(pol, caps, adapter, n=4000)
        scaling.append({"constraints": k, "median_us": lat["median_us"]})

    out = {
        "host": platform.platform(), "python": platform.python_version(),
        "latency": latency,
        "monitor_memory_bytes": mem_after, "constant_memory": constant_memory,
        "ledger_bytes_per_entry": per_entry, "certificate_bytes": cert_bytes,
        "latency_vs_constraints": scaling,
    }
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "systems.json"), "w") as f:
        json.dump(out, f, indent=2)

    print("E5 systems:")
    print(f"  shield step: median {latency['median_us']:.1f} us, "
          f"p99 {latency['p99_us']:.1f} us, "
          f"candidates {latency['candidate_set_mean']:.1f}")
    print(f"  monitor memory {mem_after} B (constant={constant_memory})")
    print(f"  ledger {per_entry:.0f} B/entry; certificate {cert_bytes} B")
    return out


if __name__ == "__main__":
    main()
