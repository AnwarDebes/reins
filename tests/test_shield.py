"""The shield's three guarantees (transparency, soundness, minimal intervention)
and the per-family repair behaviours, validated against a brute-force oracle.
"""

import itertools
import pytest

from reinskit import (Policy, always, never, bounded_count, response, precedence,
                      Action, AdapterConfig, ToolCallAdapter, Capabilities, CostModel,
                      Shield)
from reinskit.edits import ALLOW, SUPPRESS, SUBSTITUTE, DEFER


# ---- a reusable deployment ---- #
def make(policy, escalation=True, with_caps=True):
    cfg = AdapterConfig(
        capabilities={
            "read_record": ["read", "sensitive_read"],
            "send_email": ["export"],
            "transfer_funds": ["transfer"],
            "delete_all": ["delete_all"],
            "archive": ["write"],
            "audit_log": ["audit_log"],
            "authorize": ["authorize"],
            "noop": [],
        },
        scope_allowlist=["read_record", "send_email", "transfer_funds", "archive",
                         "audit_log", "authorize", "noop"],
    )
    adapter = ToolCallAdapter(cfg)
    if with_caps:
        caps = Capabilities(
            substitutions={"delete_all": [Action.of("archive")]},
            insertables={"audit_log": Action.of("audit_log"),
                         "authorize": Action.of("authorize")},
            escalation=escalation,
        )
    else:
        caps = Capabilities(escalation=escalation)   # block-everything regime
    return Shield(policy, caps, adapter=adapter), caps, adapter


def oracle_min_cost(shield, caps, action):
    """Least cost over enactable edits that keep the *current* guard safe."""
    best = None
    for e in caps.candidate_edits(action):
        seq = [shield._events_of(a) for a in e.output_actions(action)]
        if shield.guard.simulate(seq):
            c = caps.costs.cost(e)
            best = c if best is None else min(best, c)
    return best


POLICY = Policy("data", [
    always("within_scope"),
    never("delete_all"),
    bounded_count("export", 2, 50),
    response("sensitive_read", "audit_log", 3),
    precedence("authorize", "transfer"),
])


def test_transparency_identity_on_benign():
    """A trajectory that never risks a monitor must be passed through untouched."""
    shield, caps, adapter = make(POLICY)
    benign = [Action.of("read_record", {"id": 1}),
              Action.of("audit_log"),                 # discharge obligation in time
              Action.of("send_email", {"to": "a@x.com"}),
              Action.of("authorize"),
              Action.of("transfer_funds", {"to": "acct"})]
    for a in benign:
        dec = shield.decide(a)
        assert dec.edit.kind == ALLOW and not dec.edit.prefix, dec.explain()
        assert not dec.intervened
    assert shield.session_sound


def test_soundness_on_adversarial():
    shield, caps, adapter = make(POLICY)
    attack = [Action.of("read_record", {"id": 1}),
              Action.of("send_email", {"to": "a@x.com"}),
              Action.of("send_email", {"to": "b@x.com"}),
              Action.of("transfer_funds", {"to": "acct"}),   # no prior authorize
              Action.of("delete_all"),
              Action.of("send_email", {"to": "c@x.com"})]     # over budget
    for a in attack:
        dec = shield.decide(a)
        assert dec.sound, dec.explain()
    assert shield.session_sound


@pytest.mark.parametrize("seed", range(8))
def test_minimal_intervention_matches_oracle(seed):
    """Every committed edit equals the least-cost safe enactable edit."""
    import random
    rng = random.Random(seed)
    tools = ["read_record", "send_email", "transfer_funds", "delete_all",
             "authorize", "audit_log"]
    shield, caps, adapter = make(POLICY)
    for _ in range(40):
        name = rng.choice(tools)
        args = {"to": rng.choice(["a@x.com", "internal"])} if name == "send_email" else {}
        action = Action.of(name, args)
        expected = oracle_min_cost(shield, caps, action)
        dec = shield.decide(action)
        assert dec.cost == expected, (name, dec.cost, expected)


def test_precedence_inserts_prerequisite():
    pol = Policy("p", [precedence("authorize", "transfer")])
    shield, caps, adapter = make(pol)
    dec = shield.decide(Action.of("transfer_funds", {"to": "acct"}))
    assert dec.edit.kind == ALLOW and any(a.name == "authorize" for a in dec.edit.prefix)
    assert shield.session_sound


def test_response_inserts_audit_at_deadline():
    pol = Policy("p", [response("sensitive_read", "audit_log", 2)])
    shield, caps, adapter = make(pol)
    shield.decide(Action.of("read_record", {"id": 1}))           # step0: obligation
    shield.decide(Action.of("send_email", {"to": "x@x.com"}))    # step1
    shield.decide(Action.of("send_email", {"to": "y@x.com"}))    # step2 (still ok)
    dec = shield.decide(Action.of("send_email", {"to": "z@x.com"}))  # step3: would expire
    assert any(a.name == "audit_log" for a in dec.edit.prefix), dec.explain()
    assert shield.session_sound


def test_never_substitutes_when_possible():
    pol = Policy("p", [never("delete_all")])
    shield, caps, adapter = make(pol)
    dec = shield.decide(Action.of("delete_all"))
    assert dec.edit.kind == SUBSTITUTE and dec.edit.substitute.name == "archive"


def test_never_suppresses_without_substitute():
    pol = Policy("p", [never("delete_all")])
    shield, caps, adapter = make(pol, with_caps=False)   # no substitutions
    dec = shield.decide(Action.of("delete_all"))
    assert dec.edit.kind == SUPPRESS


def test_bounded_count_suppresses_excess():
    pol = Policy("p", [bounded_count("export", 1, 10)])
    shield, caps, adapter = make(pol)
    shield.decide(Action.of("send_email", {"to": "a@x.com"}))    # 1 ok
    dec = shield.decide(Action.of("send_email", {"to": "b@x.com"}))  # 2 -> over
    assert dec.edit.kind in (SUPPRESS, DEFER)
    assert shield.session_sound


def test_defer_when_response_not_insertable_but_escalation():
    """Non-shieldable Response + escalation: the shield halts (defer) and stays
    sound, the trivial Schneider-truncation guarantee."""
    pol = Policy("p", [response("sensitive_read", "audit_log", 2)])
    cfg = AdapterConfig(capabilities={"read_record": ["sensitive_read"], "noop": []},
                        scope_allowlist=[])
    caps = Capabilities(insertables={}, escalation=True)   # cannot insert audit_log
    shield = Shield(pol, caps, adapter=ToolCallAdapter(cfg))
    shield.decide(Action.of("read_record", {"id": 1}))         # step0: obligation
    shield.decide(Action.of("read_record", {"id": 2}))         # step1
    shield.decide(Action.of("read_record", {"id": 3}))         # step2 (still ok)
    dec = shield.decide(Action.of("read_record", {"id": 4}))   # step3: obligation expiring
    assert dec.edit.kind == DEFER and dec.escalated
    assert shield.session_sound


def test_enforcement_failure_is_honest_without_escalation():
    """Non-shieldable Response and no escalation: no safe edit exists; the shield
    flags an enforcement failure rather than silently claiming success."""
    pol = Policy("p", [response("sensitive_read", "audit_log", 1)])
    cfg = AdapterConfig(capabilities={"read_record": ["sensitive_read"], "noop": []},
                        scope_allowlist=[])
    caps = Capabilities(insertables={}, escalation=False)
    shield = Shield(pol, caps, adapter=ToolCallAdapter(cfg))
    shield.decide(Action.of("read_record", {"id": 1}))         # step0: obligation (d=1)
    shield.decide(Action.of("read_record", {"id": 2}))         # step1 (still ok)
    dec = shield.decide(Action.of("read_record", {"id": 3}))   # step2: expires, no safe edit
    assert dec.enforcement_failed
    assert not shield.session_sound
