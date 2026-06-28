"""Enactability: which edits the deployment can actually perform, and at what cost.

Classic edit automata assume the enforcer can insert or suppress *any* action.
An LLM agent acts on real tools, so REINS is constrained by an **enactability
relation**: a declarative statement of what this particular deployment is able to
do to the action stream.  :class:`Capabilities` records three things:

* ``substitutions``: for a tool, a list of safer *variant* actions the
  environment will accept in its place (e.g. ``delete_all -> archive``,
  ``send(external) -> send(review_queue)``);
* ``insertables``: prerequisite actions the deployment can inject without the
  agent's cooperation, keyed by the *event* they raise (e.g. the event
  ``audit_log`` is producible by an ``audit_log`` tool the shield may call, the
  event ``authorize`` by an ``authorize`` step);
* ``escalation``: whether a human-in-the-loop *defer* channel exists
  (EU AI Act Article 14 oversight).

plus a :class:`CostModel` ordering interventions by how much they disrupt the
agent's intent.  ``SUPPRESS`` and (when present) ``DEFER`` are always enactable;
they are the safety floor.  ``INSERT`` and ``SUBSTITUTE`` are the *utility-
preserving* edits, available only where the capability table says so, which is
exactly why the safety/utility frontier is a property of the deployment's
capabilities, not of the shield.

The static check :func:`is_shieldable` decides, in O(|policy|), whether the
shield can *guarantee* soundness for a policy under a given capability set:
every ``Response(t, r, d)`` obligation needs its response ``r`` insertable
(``SUPPRESS`` cannot discharge an obligation that is the *absence* of an action);
every other constraint family is dischargeable by ``SUPPRESS`` and so is always
shieldable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations
from typing import Dict, List, Optional, Tuple

from .adapters import Action
from .edits import Edit, ALLOW, SUPPRESS, SUBSTITUTE, DEFER
from .policy import Policy


@dataclass
class CostModel:
    """Cost of each intervention.  Lower = less disruptive to the agent's intent.
    The default ordering encodes 'keep the action if you can, halt only as a last
    resort': allow < insert < substitute < suppress < defer.  An *insert* (keep
    the action, add a missing prerequisite) is the cheapest non-trivial fix; a
    *substitute* keeps partial utility; *suppress* drops one action but the
    session continues; *defer* halts the whole session for a human and is the most
    disruptive to autonomous progress."""
    allow: float = 0.0
    insert: float = 1.0      # per inserted prerequisite action
    substitute: float = 3.0
    suppress: float = 5.0
    defer: float = 8.0

    def cost(self, edit: Edit) -> float:
        base = {ALLOW: self.allow, SUPPRESS: self.suppress,
                SUBSTITUTE: self.substitute, DEFER: self.defer}[edit.kind]
        return base + self.insert * len(edit.prefix)

    def to_dict(self) -> dict:
        return {"allow": self.allow, "insert": self.insert, "substitute": self.substitute,
                "defer": self.defer, "suppress": self.suppress}

    @classmethod
    def from_dict(cls, d: dict) -> "CostModel":
        return cls(**{k: float(v) for k, v in d.items()})


@dataclass
class Capabilities:
    """The enactability relation for one deployment."""
    substitutions: Dict[str, List[Action]] = field(default_factory=dict)
    insertables: Dict[str, Action] = field(default_factory=dict)   # event -> action raising it
    escalation: bool = True
    max_inserts: int = 2                                            # cap on prerequisites per step
    costs: CostModel = field(default_factory=CostModel)

    # ---- enactable edit enumeration ---- #
    def base_edits(self, action: Action) -> List[Edit]:
        edits = [Edit(ALLOW), Edit(SUPPRESS)]
        if self.escalation:
            edits.append(Edit(DEFER))
        for alt in self.substitutions.get(action.name, []):
            edits.append(Edit(SUBSTITUTE, substitute=alt))
        return edits

    def insert_prefixes(self) -> List[Tuple[Action, ...]]:
        """All prerequisite prefixes the deployment can inject (incl. the empty
        prefix), up to ``max_inserts`` actions, in a canonical order."""
        items = [self.insertables[e] for e in sorted(self.insertables)]
        prefixes: List[Tuple[Action, ...]] = [()]
        for r in range(1, min(self.max_inserts, len(items)) + 1):
            for combo in combinations(items, r):
                prefixes.append(tuple(combo))
        return prefixes

    def candidate_edits(self, action: Action) -> List[Edit]:
        """The full enactable edit space at this step: every base edit, optionally
        preceded by an enactable prerequisite prefix.  Small by construction."""
        out: List[Edit] = []
        prefixes = self.insert_prefixes()
        for base in self.base_edits(action):
            for pre in prefixes:
                # an insert prefix on a DEFER is meaningless (the shield is halting)
                if base.kind == DEFER and pre:
                    continue
                out.append(Edit(base.kind, prefix=pre, substitute=base.substitute))
        return out

    # ---- serialisation (for the certificate) ---- #
    def to_dict(self) -> dict:
        return {
            "substitutions": {k: [[a.name, a.args] for a in v]
                              for k, v in self.substitutions.items()},
            "insertables": {e: [a.name, a.args] for e, a in self.insertables.items()},
            "escalation": self.escalation,
            "max_inserts": self.max_inserts,
            "costs": self.costs.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Capabilities":
        subs = {k: [Action.of(n, a) for n, a in v] for k, v in d.get("substitutions", {}).items()}
        ins = {e: Action.of(n, a) for e, (n, a) in d.get("insertables", {}).items()}
        return cls(substitutions=subs, insertables=ins,
                   escalation=d.get("escalation", True),
                   max_inserts=d.get("max_inserts", 2),
                   costs=CostModel.from_dict(d.get("costs", {})))


# Events the idle (NOOP) action raises (see adapters.events_of(NOOP)).  A SUPPRESS
# emits this idle step, so it preserves exactly the Always predicates listed here.
IDLE_EVENTS = frozenset({"within_scope"})


def is_shieldable(policy: Policy, caps: Capabilities) -> Tuple[bool, List[str]]:
    """Static soundness check: can the shield *guarantee* the policy while the
    session keeps running (i.e.\\ without falling back to DEFER/halt)?

    Returns ``(ok, reasons)``.  A SUPPRESS emits the idle action, which raises only
    ``IDLE_EVENTS``; it therefore discharges \\textsc{Never}, \\textsc{BoundedCount}
    and \\textsc{Precedence} unconditionally, but it preserves an
    \\textsc{Always}(p) only when ``p`` is idle-raised, and it cannot discharge a
    \\textsc{Response} obligation (the *absence* of an action) at all.  Hence the
    shield is guaranteed sound-without-halting iff:

      * every \\textsc{Response}(t, r, d) has ``r`` insertable, and
      * every \\textsc{Always}(p) has ``p`` idle-raised or insertable.

    This check assumes the insert budget (``caps.max_inserts``) covers the
    obligations that can come due in a single step; with an escalation channel the
    shield is sound unconditionally (DEFER halts before any violation), so this
    check is the *no-halt* guarantee, not the only route to soundness."""
    blocking: List[str] = []
    needs_insert = 0     # constraints that may require an insert on the same step
    for c in policy.constraints:
        if c["kind"] == "response":
            if c["response"] not in caps.insertables:
                blocking.append(
                    f"{c['name']}: response event '{c['response']}' is not insertable")
            else:
                needs_insert += 1
        elif c["kind"] == "always":
            p = c["pred"]
            if p not in IDLE_EVENTS and p not in caps.insertables:
                blocking.append(
                    f"{c['name']}: predicate '{p}' is neither idle-raised nor insertable")
            elif p in caps.insertables:
                needs_insert += 1
    # conservative insert-budget check: if every insert-requiring constraint could
    # come due on one step, max_inserts must cover them (the simultaneity bound the
    # theorem assumes).  Over-approximates (assumes worst-case co-occurrence).
    if needs_insert > caps.max_inserts:
        blocking.append(
            f"insert budget max_inserts={caps.max_inserts} < {needs_insert} "
            f"constraints that may require simultaneous inserts")
    return (len(blocking) == 0, blocking)


def utility_gaps(policy: Policy, caps: Capabilities) -> List[str]:
    """Constraints that are *shieldable* but only by a utility-destroying SUPPRESS
    because no utility-preserving edit (insert/substitute) is available.  This is
    the diagnostic for where the deployment sits on the safety/utility frontier."""
    gaps: List[str] = []
    for c in policy.constraints:
        if c["kind"] == "precedence" and c["first"] not in caps.insertables:
            gaps.append(
                f"{c['name']}: cannot insert prerequisite '{c['first']}' "
                f"(a violating '{c['second']}' can only be suppressed)")
    return gaps
