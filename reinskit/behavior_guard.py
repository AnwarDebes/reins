"""Online temporal monitor bank, with what-if simulation for the shield.

The behaviour guard compiles a :class:`~reinskit.policy.Policy` into a bank of
bounded-memory monitors (:mod:`reinskit.ltl`) and advances all of them one agent
step at a time.  Where TRACE only *observed*, REINS must also *plan*: before it
commits the agent's step it asks "what would happen to every monitor if I emitted
this candidate (edited) sequence of events instead?".  :meth:`BehaviorGuard.clone`
and :meth:`BehaviorGuard.simulate` provide exactly that, side-effect-free, by deep
copying the monitor states.  Cloning a bank costs O(#monitors * monitor-state),
constant in the trajectory length, so the shield's per-step planning stays cheap.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence

from .policy import Policy
from .ltl import Monitor, Violation


@dataclass
class StepVerdict:
    step: int
    ok: bool
    violated_now: List[str]
    session_ok: bool


class BehaviorGuard:
    """Streaming policy monitor.  One per agent session."""

    def __init__(self, policy: Policy):
        self.policy = policy
        self.monitors: List[Monitor] = policy.compile()
        self._step = -1

    # ---- streaming ---- #
    def reset(self) -> None:
        for m in self.monitors:
            m.reset()
        self._step = -1

    def step(self, events: Dict[str, bool]) -> StepVerdict:
        self._step += 1
        violated_now: List[str] = []
        for m in self.monitors:
            if not m.update(events, step=self._step):
                violated_now.append(m.name)
        return StepVerdict(step=self._step, ok=not violated_now,
                           violated_now=violated_now, session_ok=self.session_ok)

    # ---- what-if simulation (the shield's planning primitive) ---- #
    def clone(self) -> "BehaviorGuard":
        g = BehaviorGuard.__new__(BehaviorGuard)
        g.policy = self.policy
        g.monitors = [m.clone() for m in self.monitors]
        g._step = self._step
        return g

    def would_violate(self, events: Dict[str, bool]) -> List[str]:
        """Names of monitors that a single ``events`` step would violate now."""
        return [m.name for m in self.monitors if m.would_violate(events)]

    def simulate(self, event_seq: Sequence[Dict[str, bool]]) -> bool:
        """True iff emitting this whole sequence keeps *every* monitor safe at
        *every* step.  Pure: the live bank is untouched."""
        g = self.clone()
        for events in event_seq:
            for m in g.monitors:
                if not m.update(events):
                    return False
        return True

    def simulate_violations(self, event_seq: Sequence[Dict[str, bool]]) -> int:
        """Number of (monitor, step) violations the sequence would cause.  Used
        only by the shield's honest fallback when *no* enactable edit is safe
        (a non-shieldable policy): it then picks the least-violating edit and
        flags the step as an enforcement failure."""
        g = self.clone()
        n = 0
        for events in event_seq:
            for m in g.monitors:
                if not m.update(events):
                    n += 1
        return n

    # ---- read-out ---- #
    @property
    def session_ok(self) -> bool:
        return all(not m.ever_violated for m in self.monitors)

    @property
    def violations(self) -> List[Violation]:
        out: List[Violation] = []
        for m in self.monitors:
            out.extend(m.violations)
        return out

    @property
    def memory_bytes(self) -> int:
        return sum(m.memory_bytes for m in self.monitors)

    def verdict(self) -> dict:
        return {
            "session_ok": self.session_ok,
            "n_violations": len(self.violations),
            "violations": [{"monitor": v.monitor, "step": v.step, "detail": v.detail}
                           for v in self.violations],
            "per_monitor": {m.name: {"ever_violated": m.ever_violated} for m in self.monitors},
        }
