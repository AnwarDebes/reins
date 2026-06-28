"""Monitors, plus the two capabilities the shield depends on: side-effect-free
``would_violate`` (must agree with ``update``) and ``clone`` (must be independent
of the original)."""

import pytest

from reinskit.ltl import Always, Never, BoundedCount, Response, Precedence, Monitor


ALL_FACTORIES = [
    lambda: Always("p"),
    lambda: Never("e"),
    lambda: BoundedCount("x", 2, 4),
    lambda: Response("t", "r", 3),
    lambda: Precedence("a", "b"),
]


def _events_universe(keys):
    """All 2^len(keys) Boolean assignments over keys."""
    import itertools
    for bits in itertools.product([False, True], repeat=len(keys)):
        yield dict(zip(keys, bits))


def test_basic_semantics():
    assert Always("p")._update({"p": True}) is True
    assert Always("p")._update({"p": False}) is False
    assert Never("e")._update({"e": True}) is False
    assert Precedence("a", "b")._update({"b": True}) is False
    pr = Precedence("a", "b")
    assert pr._update({"a": True}) is True
    assert pr._update({"b": True}) is True


def test_bounded_count_window():
    m = BoundedCount("x", max_count=2, window=3)
    assert m.update({"x": True})       # 1
    assert m.update({"x": True})       # 2
    assert not m.update({"x": True})   # 3 in window -> violated
    # slide the window: after enough non-x steps the count recovers
    m.update({"x": False})
    m.update({"x": False})
    assert m.ok


def test_response_deadline():
    m = Response("t", "r", deadline=2)
    assert m.update({"t": True})       # obligation created
    assert m.update({})                # 1 step late, still ok
    assert m.update({})                # 2 steps, still ok
    assert not m.update({})            # 3rd step -> expired


def test_response_discharge():
    m = Response("t", "r", deadline=2)
    m.update({"t": True})
    assert m.update({"r": True})       # discharged in time
    assert m.update({})                # no outstanding obligation
    assert m.ok


@pytest.mark.parametrize("factory", ALL_FACTORIES)
def test_would_violate_matches_update(factory):
    """The side-effect-free peek must equal what update would report, for every
    monitor, on a range of states reached by random-ish event prefixes."""
    keys = sorted({"p", "e", "x", "t", "r", "a", "b"})
    # drive the monitor through a prefix, then check peek == update on each event
    prefixes = [[], [{"t": True}], [{"a": True}], [{"x": True}, {"x": True}],
                [{"t": True}, {}], [{"b": True}]]
    for prefix in prefixes:
        m = factory()
        for ev in prefix:
            m.update(ev)
        for ev in _events_universe(keys):
            predicted = not m.would_violate(ev)
            actual = m.clone()._update(ev)
            assert predicted == actual, (factory, prefix, ev, predicted, actual)


@pytest.mark.parametrize("factory", ALL_FACTORIES)
def test_clone_is_independent(factory):
    m = factory()
    m.update({"t": True, "x": True, "a": True})
    c = m.clone()
    # advancing the clone must not change the original
    before = m.spec, m.ever_violated
    for _ in range(5):
        c.update({"x": True})
    assert (m.spec, m.ever_violated) == before


@pytest.mark.parametrize("factory", ALL_FACTORIES)
def test_spec_roundtrip(factory):
    m = factory()
    m2 = Monitor.from_spec(m.spec)
    assert m2.spec == m.spec
