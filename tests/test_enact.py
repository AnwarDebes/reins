"""Enactability: candidate-edit enumeration, cost ordering, shieldability."""

from reinskit import (Policy, always, never, bounded_count, response, precedence,
                      Action, Capabilities, CostModel, is_shieldable, utility_gaps)
from reinskit.edits import ALLOW, SUPPRESS, SUBSTITUTE, DEFER


def test_candidate_edits_include_floor():
    caps = Capabilities(escalation=True)
    kinds = {e.kind for e in caps.candidate_edits(Action.of("foo"))}
    assert {ALLOW, SUPPRESS, DEFER} <= kinds


def test_candidate_edits_include_substitutes_and_inserts():
    caps = Capabilities(
        substitutions={"delete_all": [Action.of("archive")]},
        insertables={"authorize": Action.of("authorize"),
                     "audit_log": Action.of("audit_log")},
    )
    edits = caps.candidate_edits(Action.of("delete_all"))
    assert any(e.kind == SUBSTITUTE and e.substitute.name == "archive" for e in edits)
    # an insert prefix containing the authorize prerequisite is offered
    assert any("authorize" in [a.name for a in e.prefix] for e in edits)


def test_cost_ordering_default():
    c = CostModel()
    assert c.allow < c.insert < c.substitute < c.suppress < c.defer


def test_cost_insert_scales_with_prefix():
    caps = Capabilities(insertables={"authorize": Action.of("authorize")})
    from reinskit.edits import Edit
    one = Edit(ALLOW, prefix=(Action.of("authorize"),))
    assert caps.costs.cost(one) == caps.costs.allow + caps.costs.insert


def test_is_shieldable_response_needs_insertable():
    pol = Policy("p", [response("read", "audit", 3)])
    # without audit insertable -> not shieldable
    ok, gaps = is_shieldable(pol, Capabilities())
    assert not ok and gaps
    # with audit insertable -> shieldable
    ok, gaps = is_shieldable(pol, Capabilities(insertables={"audit": Action.of("audit_log")}))
    assert ok and not gaps


def test_never_count_precedence_shieldable_by_suppress():
    # Never / BoundedCount / Precedence are dischargeable by SUPPRESS alone.
    pol = Policy("p", [never("delete"), bounded_count("x", 1, 5), precedence("a", "b")])
    ok, gaps = is_shieldable(pol, Capabilities(insertables={}))
    assert ok and not gaps


def test_always_shieldable_only_if_idle_raised_or_insertable():
    # always(within_scope) is idle-raised -> shieldable by suppress
    ok, _ = is_shieldable(Policy("p", [always("within_scope")]), Capabilities(insertables={}))
    assert ok
    # always(authenticated) is NOT idle-raised -> needs an insertable producer
    pol = Policy("p", [always("authenticated")])
    ok, gaps = is_shieldable(pol, Capabilities(insertables={}))
    assert not ok and gaps
    ok2, _ = is_shieldable(pol, Capabilities(insertables={"authenticated": Action.of("login")}))
    assert ok2


def test_insert_budget_check():
    # three Response obligations, all insertable, but max_inserts=2 -> flagged
    pol = Policy("p", [response("t1", "r1", 1), response("t2", "r2", 1),
                       response("t3", "r3", 1)])
    caps = Capabilities(insertables={"r1": Action.of("a1"), "r2": Action.of("a2"),
                                     "r3": Action.of("a3")}, max_inserts=2)
    ok, gaps = is_shieldable(pol, caps)
    assert not ok and any("budget" in g for g in gaps)
    # raising the budget closes it
    caps.max_inserts = 3
    assert is_shieldable(pol, caps)[0]


def test_utility_gaps_precedence_without_insertable_first():
    pol = Policy("p", [precedence("authorize", "transfer")])
    gaps = utility_gaps(pol, Capabilities(insertables={}))
    assert gaps and "authorize" in gaps[0]
    # provide the prerequisite -> gap closes
    assert not utility_gaps(pol, Capabilities(insertables={"authorize": Action.of("authorize")}))


def test_capabilities_roundtrip():
    caps = Capabilities(
        substitutions={"delete_all": [Action.of("archive", {"soft": True})]},
        insertables={"authorize": Action.of("authorize")},
        escalation=False, max_inserts=1, costs=CostModel(suppress=9.0),
    )
    caps2 = Capabilities.from_dict(caps.to_dict())
    assert caps2.escalation is False and caps2.max_inserts == 1
    assert caps2.costs.suppress == 9.0
    assert caps2.substitutions["delete_all"][0].name == "archive"
    assert caps2.insertables["authorize"].name == "authorize"
