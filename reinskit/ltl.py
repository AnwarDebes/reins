"""Online, bounded-memory monitors for finite-trace temporal safety policies.

REINS reuses the curated bounded fragment of finite-trace LTL (LTLf) introduced
in TRACE, because the *enforcement* layer is only as deployable as the monitors
it shields against.  Each monitor consumes a stream of Boolean *events* (one dict
per agent step) and maintains a verdict incrementally, in memory **constant in
the trajectory length**:

    Always(p)                  invariant            G p
    Never(e)                   absence              G !e
    BoundedCount(e, k, w)      rate / count bound   "<= k occurrences of e per w steps"
    Response(t, r, d)          bounded response     G (t -> F_{<= d} r)
    Precedence(a, b)           precedence / latch   !b W a   (b only after a)

Safety semantics: a violation is **latched**: a finite bad prefix can never be
undone.  Two capabilities beyond TRACE's monitors are what the shield needs and
this module adds:

  * ``clone()``: a cheap deep copy of a monitor's mutable state, so the repair
    planner can *simulate* a candidate edit against the live monitor bank without
    committing to it (the shield's per-step search in :mod:`reinskit.shield`);
  * ``would_violate(events)``: a side-effect-free one-step lookahead, used both
    by the planner and to make the "imminent violation" notion precise.

Both are exact: ``would_violate`` agrees with ``update`` on the verdict, and
``clone`` followed by ``update`` is observationally identical to ``update`` on
the original.  These properties are tested in ``tests/test_ltl.py``.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class Violation:
    monitor: str
    step: int
    detail: str


class Monitor:
    """Base class.  Subclasses implement ``_update``, ``_peek`` and ``spec``."""

    def __init__(self, name: str):
        self.name = name
        self.ever_violated = False
        self.ok = True
        self.violations: List[Violation] = []
        self._step = -1

    # ---- serialisation ---- #
    @property
    def spec(self) -> dict:
        raise NotImplementedError

    @staticmethod
    def from_spec(spec: dict) -> "Monitor":
        return _REGISTRY[spec["kind"]]._from_spec(spec)

    @classmethod
    def _from_spec(cls, spec: dict) -> "Monitor":
        raise NotImplementedError

    # ---- streaming ---- #
    def reset(self) -> None:
        self.ever_violated = False
        self.ok = True
        self.violations = []
        self._step = -1
        self._reset_state()

    def _reset_state(self) -> None:
        pass

    def clone(self) -> "Monitor":
        """Fast copy of the monitor (state included) for what-if simulation.

        The shield clones the whole bank once per candidate edit, so this is on
        the hot path; the small mutable state is copied by hand rather than paying
        ``copy.deepcopy``.  ``violations`` is shallow-copied (its ``Violation``
        records are never mutated in place)."""
        c = self.__class__.__new__(self.__class__)
        c.__dict__.update(self.__dict__)
        c.violations = list(self.violations)
        buf = self.__dict__.get("_buf")
        if buf is not None:
            c._buf = deque(buf, maxlen=self.window)
        pend = self.__dict__.get("_pending")
        if pend is not None:
            c._pending = deque(pend)
        return c

    def update(self, events: Dict[str, bool], step: Optional[int] = None) -> bool:
        """Advance one step.  Returns the instantaneous ``ok`` after this step."""
        self._step = step if step is not None else self._step + 1
        ok_now = self._update(events)
        self.ok = ok_now
        if not ok_now and not self.ever_violated:
            self.ever_violated = True
        if not ok_now:
            self.violations.append(Violation(self.name, self._step, self._detail(events)))
        return ok_now

    def would_violate(self, events: Dict[str, bool]) -> bool:
        """Side-effect-free: would consuming ``events`` next violate this monitor?"""
        return not self._peek(events)

    def _update(self, events: Dict[str, bool]) -> bool:
        raise NotImplementedError

    def _peek(self, events: Dict[str, bool]) -> bool:
        """Default: clone and run one step (exact but allocates).  Subclasses may
        override with an allocation-free computation."""
        return self.clone()._update(events)

    def _detail(self, events: Dict[str, bool]) -> str:
        return ""

    @property
    def memory_bytes(self) -> int:
        return 64


# ---------------------------------------------------------------------- #
class Always(Monitor):
    """G p: predicate ``p`` must hold at every step."""

    def __init__(self, pred: str, name: Optional[str] = None):
        super().__init__(name or f"always({pred})")
        self.pred = pred

    @property
    def spec(self):
        return {"kind": "always", "name": self.name, "pred": self.pred}

    @classmethod
    def _from_spec(cls, spec):
        return cls(spec["pred"], name=spec.get("name"))

    def _update(self, events):
        return bool(events.get(self.pred, False))

    def _peek(self, events):
        return bool(events.get(self.pred, False))

    def _detail(self, events):
        return f"predicate '{self.pred}' false"


class Never(Monitor):
    """G !e: event ``e`` must never occur."""

    def __init__(self, event: str, name: Optional[str] = None):
        super().__init__(name or f"never({event})")
        self.event = event

    @property
    def spec(self):
        return {"kind": "never", "name": self.name, "event": self.event}

    @classmethod
    def _from_spec(cls, spec):
        return cls(spec["event"], name=spec.get("name"))

    def _update(self, events):
        return not bool(events.get(self.event, False))

    def _peek(self, events):
        return not bool(events.get(self.event, False))

    def _detail(self, events):
        return f"forbidden event '{self.event}' occurred"


class BoundedCount(Monitor):
    """At most ``max_count`` occurrences of ``event`` in any sliding window of
    ``window`` steps.  Memory O(window); catches slow-roll abuse."""

    def __init__(self, event: str, max_count: int, window: int, name: Optional[str] = None):
        super().__init__(name or f"count_le({event},{max_count},{window})")
        self.event = event
        self.max_count = int(max_count)
        self.window = int(window)
        self._buf: deque = deque(maxlen=self.window)
        self._count = 0

    @property
    def spec(self):
        return {"kind": "bounded_count", "name": self.name, "event": self.event,
                "max_count": self.max_count, "window": self.window}

    @classmethod
    def _from_spec(cls, spec):
        return cls(spec["event"], spec["max_count"], spec["window"], name=spec.get("name"))

    def _reset_state(self):
        self._buf = deque(maxlen=self.window)
        self._count = 0

    def _update(self, events):
        v = 1 if events.get(self.event, False) else 0
        if len(self._buf) == self.window:
            self._count -= self._buf[0]
        self._buf.append(v)
        self._count += v
        return self._count <= self.max_count

    def _peek(self, events):
        v = 1 if events.get(self.event, False) else 0
        evict = self._buf[0] if len(self._buf) == self.window else 0
        return (self._count - evict + v) <= self.max_count

    def _detail(self, events):
        return f"{self._count} occurrences of '{self.event}' in window {self.window} (> {self.max_count})"

    @property
    def memory_bytes(self):
        return 64 + self.window


class Response(Monitor):
    """Bounded response: G (trigger -> F_{<= deadline} response).  Memory O(deadline).
    Models obligations such as 'every sensitive read followed by an audit log'."""

    def __init__(self, trigger: str, response: str, deadline: int, name: Optional[str] = None):
        super().__init__(name or f"response({trigger}->{response},{deadline})")
        self.trigger = trigger
        self.response = response
        self.deadline = int(deadline)
        self._pending: deque = deque()

    @property
    def spec(self):
        return {"kind": "response", "name": self.name, "trigger": self.trigger,
                "response": self.response, "deadline": self.deadline}

    @classmethod
    def _from_spec(cls, spec):
        return cls(spec["trigger"], spec["response"], spec["deadline"], name=spec.get("name"))

    def _reset_state(self):
        self._pending = deque()

    def _update(self, events):
        responded = bool(events.get(self.response, False))
        if responded and self._pending:
            self._pending.popleft()
        expired = False
        new_pending = deque()
        for rem in self._pending:
            rem -= 1
            if rem < 0:
                expired = True
            else:
                new_pending.append(rem)
        self._pending = new_pending
        if events.get(self.trigger, False):
            self._pending.append(self.deadline)
        return not expired

    def _peek(self, events):
        responded = bool(events.get(self.response, False))
        pend = list(self._pending)
        if responded and pend:
            pend.pop(0)
        for rem in pend:
            if rem - 1 < 0:
                return False
        return True

    def obligation_due(self, events: Dict[str, bool]) -> bool:
        """True iff an outstanding obligation expires *this* step unless ``response``
        fires, i.e. the shield must ensure ``response`` now to stay safe."""
        return self.would_violate(events)

    def _detail(self, events):
        return f"'{self.trigger}' not answered by '{self.response}' within {self.deadline} steps"

    @property
    def memory_bytes(self):
        return 64 + 4 * (self.deadline + 1)


class Precedence(Monitor):
    """!second W first: ``second`` may only occur once ``first`` has occurred."""

    def __init__(self, first: str, second: str, name: Optional[str] = None):
        super().__init__(name or f"precedence({first}<{second})")
        self.first = first
        self.second = second
        self._seen_first = False

    @property
    def spec(self):
        return {"kind": "precedence", "name": self.name, "first": self.first, "second": self.second}

    @classmethod
    def _from_spec(cls, spec):
        return cls(spec["first"], spec["second"], name=spec.get("name"))

    def _reset_state(self):
        self._seen_first = False

    def _update(self, events):
        if events.get(self.first, False):
            self._seen_first = True
        if events.get(self.second, False) and not self._seen_first:
            return False
        return True

    def _peek(self, events):
        seen = self._seen_first or bool(events.get(self.first, False))
        if events.get(self.second, False) and not seen:
            return False
        return True

    def _detail(self, events):
        return f"'{self.second}' occurred before '{self.first}'"


_REGISTRY = {
    "always": Always,
    "never": Never,
    "bounded_count": BoundedCount,
    "response": Response,
    "precedence": Precedence,
}
