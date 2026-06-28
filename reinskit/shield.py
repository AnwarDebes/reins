"""The REINS shield: a certifying, minimal-intervention runtime enforcer.

The shield sits inline between an agent and its tools.  On each candidate action
it solves a tiny optimisation exactly:

    among all *enactable* edits (reinskit.enact), keep the ones that leave the
    monitor bank safe for the whole emitted sub-sequence
    (BehaviorGuard.simulate), and return the **least-cost** such edit.

Because ``ALLOW`` has cost zero and is enactable everywhere, the shield is the
identity whenever the agent's action is already safe (Theorem: Transparency).
Because ``SUPPRESS`` (and, when present, ``DEFER``) is always enactable and safe
for every monitor family except an outstanding ``Response`` obligation (which
``is_shieldable`` requires to be insertable), a safe edit always exists for a
shieldable policy, so the shield maintains the invariant "no monitor has ever
been violated" for every input (Theorem: Soundness).  And it returns the
cheapest safe edit, so it never restricts the agent more than the policy and the
deployment's capabilities force it to (Theorem: Minimal intervention), a
property an auditor re-derives from the certificate, catching *over*-restriction,
not only under-restriction.

The per-step search is over a small, finite candidate set (a handful of base
edits times the prerequisite prefixes), each scored by one constant-size monitor
simulation, so the shield runs in microseconds and constant memory: it is as
deployable inline as the monitor it enforces.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .adapters import Action, ToolCallAdapter
from .behavior_guard import BehaviorGuard
from .edits import Edit, ALLOW, SUPPRESS, SUBSTITUTE, DEFER, PREFERENCE
from .enact import Capabilities
from .policy import Policy


@dataclass
class ShieldDecision:
    step: int
    input_action: Action
    input_events: Dict[str, bool]
    edit: Edit
    output_actions: List[Action]
    output_events: List[Dict[str, bool]]
    enforced_monitors: List[str]        # monitors that the raw ALLOW would violate
    cost: float
    intervened: bool                    # edit was not the identity
    escalated: bool                     # DEFER: action withheld, human asked
    sound: bool                         # invariant maintained at this step
    enforcement_failed: bool            # no enactable edit was safe (non-shieldable)

    def explain(self) -> str:
        if not self.intervened:
            return f"step {self.step}: ALLOW {self.input_action} (no monitor at risk)"
        why = ", ".join(self.enforced_monitors) or "policy"
        return (f"step {self.step}: {self.edit} on {self.input_action} "
                f"[enforcing {why}] -> {[str(a) for a in self.output_actions]}")


@dataclass
class _Candidate:
    edit: Edit
    out_actions: List[Action]
    out_events: List[Dict[str, bool]]
    cost: float


class Shield:
    """Per-session minimal-intervention enforcer over a behaviour guard."""

    def __init__(self, policy: Policy, caps: Capabilities,
                 adapter: Optional[ToolCallAdapter] = None,
                 guard: Optional[BehaviorGuard] = None,
                 events_of=None):
        self.policy = policy
        self.caps = caps
        self.adapter = adapter
        # single source of truth for action -> events: the adapter when enforcing
        # live, or an injected resolver when an auditor replays from a certificate.
        if events_of is not None:
            self._events_of = events_of
        elif adapter is not None:
            self._events_of = adapter.events_of
        else:
            raise ValueError("Shield needs an adapter or an events_of resolver")
        self.guard = guard if guard is not None else BehaviorGuard(policy)
        self._step = -1
        self.decisions: List[ShieldDecision] = []

    # ------------------------------------------------------------------ #
    def _candidates(self, action: Action) -> List[_Candidate]:
        cands: List[_Candidate] = []
        for edit in self.caps.candidate_edits(action):
            out_actions = edit.output_actions(action)
            out_events = [self._events_of(a) for a in out_actions]
            cands.append(_Candidate(edit, out_actions, out_events,
                                    self.caps.costs.cost(edit)))
        return cands

    def _rank_key(self, c: _Candidate) -> Tuple[float, int, int]:
        # least cost; ties -> least disruptive kind; ties -> fewest inserts
        return (c.cost, PREFERENCE[c.edit.kind], len(c.edit.prefix))

    def decide(self, action: Action) -> ShieldDecision:
        """Plan and commit the least-cost safe edit for ``action``."""
        self._step += 1
        input_events = self._events_of(action)
        enforced = self.guard.would_violate(input_events)

        cands = self._candidates(action)
        safe = [c for c in cands if self.guard.simulate(c.out_events)]

        enforcement_failed = False
        if safe:
            chosen = min(safe, key=self._rank_key)
        else:
            # Non-shieldable step: no enactable edit avoids a violation.  Be honest:
            # pick the least-violating, then least-cost edit, and flag it.
            enforcement_failed = True
            chosen = min(cands, key=lambda c: (
                self.guard.simulate_violations(c.out_events), c.cost,
                PREFERENCE[c.edit.kind]))

        # commit: advance the live guard with the chosen output events
        sound = True
        for ev in chosen.out_events:
            sv = self.guard.step(ev)
            if not sv.ok:
                sound = False

        dec = ShieldDecision(
            step=self._step,
            input_action=action,
            input_events=input_events,
            edit=chosen.edit,
            output_actions=chosen.out_actions,
            output_events=chosen.out_events,
            enforced_monitors=enforced,
            cost=chosen.cost,
            intervened=not chosen.edit.is_identity,
            escalated=chosen.edit.escalates,
            sound=sound and not enforcement_failed,
            enforcement_failed=enforcement_failed,
        )
        self.decisions.append(dec)
        return dec

    # ------------------------------------------------------------------ #
    @property
    def session_sound(self) -> bool:
        return self.guard.session_ok

    def summary(self) -> dict:
        by_kind: Dict[str, int] = {}
        total_cost = 0.0
        n_interv = 0
        for d in self.decisions:
            if d.intervened:
                n_interv += 1
                # label by the *effective* intervention: a non-empty insert prefix
                # is an "insert" (optionally composed with a substitute), not the
                # base ALLOW it rides on.
                if d.edit.prefix:
                    key = "insert" if d.edit.kind == ALLOW else f"insert+{d.edit.kind}"
                else:
                    key = d.edit.kind
                by_kind[key] = by_kind.get(key, 0) + 1
                total_cost += d.cost
        return {
            "n_steps": len(self.decisions),
            "n_interventions": n_interv,
            "interventions_by_kind": by_kind,
            "total_cost": total_cost,
            "session_sound": self.session_sound,
            "enforcement_failures": sum(d.enforcement_failed for d in self.decisions),
        }
