"""E4: the intervention certificate: tamper-evidence and minimality audit.

I seal shielded sessions and (1) apply six tamper classes plus a key-less
forgery, confirming every one is detected; (2) confirm the model-free minimality
re-verification catches both *under*-restriction (an unsafe action let through)
and *over*-restriction (a blocked action a cheaper safe edit would have allowed)
in validly-signed logs; and (3) measure verification latency and its scaling.
"""

from __future__ import annotations

import copy
import json
import os
import random
from statistics import mean
from time import perf_counter

from _common import default_policy, default_adapter, full_caps, make_suite
from reinskit import (Action, ShieldEngine, ShieldCertificate, verify_shield)
from reinskit.ledger import (LedgerEntry, merkle_root, GENESIS, sha256_hex,
                             canonical, ShieldCertificate as Cert)

KEY = b"reins-experiment-key-32-bytes!!!"
SEEDS = list(range(12))
HERE = os.path.dirname(__file__)
RESULTS = os.path.join(HERE, "..", "results")


def sealed_session(seed):
    policy, adapter, caps = default_policy(), default_adapter(), full_caps()
    eng = ShieldEngine(f"s{seed}", policy, caps, adapter, key=KEY)
    rng = random.Random(seed)
    tasks = make_suite(seed, n_each=2)
    for t in tasks:
        for a in t.actions:
            eng.observe_action(a)
    return eng, eng.seal()


def reseal(entries, action_events, summary, policy, caps):
    objs = [LedgerEntry(**e) if isinstance(e, dict) else e for e in entries]
    prev = GENESIS
    for o in objs:
        o.signature = None
        o.compute_hash(prev)
        o.sign(KEY)
        prev = o.entry_hash
    cert = Cert(session_id="s", policy=policy.to_dict(), capabilities=caps.to_dict(),
                action_events=action_events, n_entries=len(objs), chain_head=prev,
                merkle_root=merkle_root([o.entry_hash for o in objs]), summary=summary)
    cert.sign(KEY)
    led = {"session_id": "s", "policy": policy.to_dict(),
           "capabilities": caps.to_dict(), "entries": [vars(o) for o in objs]}
    return led, cert


def main():
    policy, adapter, caps = default_policy(), default_adapter(), full_caps()

    # 1) structural tamper classes
    tamper_classes = ["event_flip", "edit_flip", "delete", "insert", "reorder",
                      "forge_no_key"]
    detected = {t: 0 for t in tamper_classes}
    trials = 0
    for seed in SEEDS:
        eng, cert = sealed_session(seed)
        base = eng.ledger.to_dict()
        if len(base["entries"]) < 4:
            continue
        trials += 1
        # honest log verifies
        assert verify_shield(copy.deepcopy(base), cert, key=KEY)[0]
        def with_events(E):                       # first entry that has an event
            return next((j for j, e in enumerate(E)
                         if e["payload"]["output_events"]
                         and e["payload"]["output_events"][0]), 0)

        for tc in tamper_classes:
            led = copy.deepcopy(base)
            E = led["entries"]
            if tc == "event_flip":
                i = with_events(E)
                k = next(iter(E[i]["payload"]["output_events"][0]))
                E[i]["payload"]["output_events"][0][k] ^= 1
            elif tc == "edit_flip":
                i = min(2, len(E) - 1)             # set a genuinely different kind
                cur = E[i]["payload"]["edit"]["kind"]
                E[i]["payload"]["edit"]["kind"] = "suppress" if cur != "suppress" else "allow"
            elif tc == "delete":
                del E[min(2, len(E) - 1)]
            elif tc == "insert":
                E.insert(min(2, len(E) - 1), copy.deepcopy(E[0]))
            elif tc == "reorder":
                # swap two entries with *different* hashes (a real reordering)
                j = next((k for k in range(1, len(E))
                          if E[k]["entry_hash"] != E[0]["entry_hash"]), 1)
                E[0], E[j] = E[j], E[0]
            elif tc == "forge_no_key":
                i = with_events(E)
                k = next(iter(E[i]["payload"]["output_events"][0]))
                E[i]["payload"]["output_events"][0][k] ^= 1
                prev = GENESIS
                for e in E:                       # attacker recomputes the chain
                    body = {"index": e["index"], "payload": e["payload"], "prev_hash": prev}
                    e["prev_hash"] = prev
                    e["entry_hash"] = sha256_hex(canonical(body))
                    prev = e["entry_hash"]
            ok, _ = verify_shield(led, cert, key=KEY)
            detected[tc] += 0 if ok else 1

    tamper_rate = {t: detected[t] / max(1, trials) for t in tamper_classes}

    # 2) minimality audit: over- and under-restriction in validly-signed logs
    over_caught = under_caught = mm_trials = 0
    for seed in SEEDS:
        eng, cert = sealed_session(seed)
        base = eng.ledger.to_dict()
        # find a substitute entry to rewrite as a suppress (over-restriction)
        for idx, e in enumerate(base["entries"]):
            if e["payload"]["edit"]["kind"] == "substitute":
                mm_trials += 1
                led = copy.deepcopy(base)
                p = led["entries"][idx]["payload"]
                p["edit"] = {"kind": "suppress", "prefix": [], "substitute": None}
                noop = Action.of("noop")
                p["output"] = [noop.to_dict()]; p["output_sigs"] = [noop.signature()]
                p["output_events"] = [{"within_scope": 1}]
                led2, cert2 = reseal(led["entries"], cert.action_events, cert.summary,
                                     policy, caps)
                ok, info = verify_shield(led2, cert2, key=KEY)
                if info["chain_ok"] and info["sig_ok"] and not info["minimality_ok"]:
                    over_caught += 1
                break
        # under-restriction: rewrite a non-allow entry as allow of the raw action
        for idx, e in enumerate(base["entries"]):
            if e["payload"]["edit"]["kind"] != "allow":
                led = copy.deepcopy(base)
                p = led["entries"][idx]["payload"]
                inp = Action.from_dict(p["input"])
                p["edit"] = {"kind": "allow", "prefix": [], "substitute": None}
                p["output"] = [inp.to_dict()]; p["output_sigs"] = [inp.signature()]
                p["output_events"] = [cert.action_events.get(inp.signature(),
                                      p["output_events"][0] if p["output_events"] else {})]
                led2, cert2 = reseal(led["entries"], cert.action_events, cert.summary,
                                     policy, caps)
                ok, info = verify_shield(led2, cert2, key=KEY)
                if not ok:
                    under_caught += 1
                break

    # 3) verification latency + scaling
    eng, cert = sealed_session(0)
    led = eng.ledger.to_dict()
    t0 = perf_counter()
    for _ in range(50):
        verify_shield(led, cert, key=KEY)
    verify_us = (perf_counter() - t0) / 50 * 1e6
    n_entries = len(led["entries"])

    scaling = []
    for mult in (1, 2, 4, 8):
        policy2, adapter2, caps2 = default_policy(), default_adapter(), full_caps()
        eng2 = ShieldEngine("big", policy2, caps2, adapter2, key=KEY)
        rng = random.Random(7)
        for _ in range(mult):
            for t in make_suite(rng.randint(0, 99), n_each=2):
                for a in t.actions:
                    eng2.observe_action(a)
        c2 = eng2.seal(); l2 = eng2.ledger.to_dict()
        t0 = perf_counter()
        verify_shield(l2, c2, key=KEY)
        scaling.append({"entries": len(l2["entries"]),
                        "verify_us": (perf_counter() - t0) * 1e6})

    out = {
        "seeds": SEEDS, "tamper_trials": trials,
        "tamper_detection_rate": tamper_rate,
        "tamper_overall_rate": mean(tamper_rate.values()),
        "minimality_over_restriction_caught_rate": over_caught / max(1, mm_trials),
        "minimality_under_restriction_caught": under_caught,
        "minimality_trials": mm_trials,
        "verify_us_per_session": verify_us, "verify_session_entries": n_entries,
        "verify_scaling": scaling,
    }
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "certificate.json"), "w") as f:
        json.dump(out, f, indent=2)

    print("E4 certificate:")
    print(f"  tamper detection (6 classes + forgery): {out['tamper_overall_rate']:.3f} "
          f"over {trials} sessions")
    print(f"  over-restriction caught: {out['minimality_over_restriction_caught_rate']:.3f}; "
          f"under-restriction caught: {under_caught}/{mm_trials}")
    print(f"  verify {verify_us:.0f} us / session ({n_entries} entries)")
    return out


if __name__ == "__main__":
    main()
