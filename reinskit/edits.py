"""The edit algebra: what the shield may do to an agent's action.

REINS generalises Schneider's *security automata* (truncate only) and the
*edit automata* of Ligatti, Bauer and Walker (insert / suppress) to the setting
of an LLM agent acting on external tools, where the enforcer does **not** fully
control the action stream.  An :class:`Edit` is the unit of intervention.  Each
edit rewrites the agent's candidate action ``a`` into an *output sequence* of
actions that the environment actually executes:

    ALLOW            -> [a]                         (identity; cost 0)
    SUPPRESS         -> [noop]                      (block the call)
    SUBSTITUTE(a')   -> [a']                        (a declared safer variant)
    DEFER            -> [noop] + escalate           (hold and ask a human)

and any edit may carry an *insert prefix* of prerequisite actions injected before
the base, e.g. ``INSERT(authorize) then ALLOW(transfer)`` or
``INSERT(audit_log) then ALLOW(read)``.  The prefix is what lets the shield keep
an action's *utility* while making it *safe*: the transfer still happens, just
after the authorisation the policy required.

An edit is a transparent, serialisable record: the receipt in the ledger states
exactly which prerequisite actions were inserted and which base action ran, so an
auditor can replay the intervention without the model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .adapters import Action, NOOP

ALLOW = "allow"
SUPPRESS = "suppress"
SUBSTITUTE = "substitute"
DEFER = "defer"

# fixed tie-break preference on equal cost (lower = less disruptive to utility):
# keep the action (allow) > downgrade it (substitute) > drop it (suppress) > halt (defer)
PREFERENCE = {ALLOW: 0, SUBSTITUTE: 1, SUPPRESS: 2, DEFER: 3}


@dataclass(frozen=True)
class Edit:
    kind: str
    prefix: Tuple[Action, ...] = ()        # prerequisite actions inserted first
    substitute: Optional[Action] = None     # target action when kind == SUBSTITUTE

    def base_action(self, original: Action) -> Action:
        if self.kind == ALLOW:
            return original
        if self.kind == SUBSTITUTE:
            assert self.substitute is not None
            return self.substitute
        return NOOP                          # SUPPRESS emits a benign idle

    def output_actions(self, original: Action) -> List[Action]:
        """The actions the environment executes.  DEFER *withholds* the agent's
        step entirely (halt and escalate), so it emits no executed action; every
        other edit emits its (optional) insert prefix followed by its base."""
        if self.kind == DEFER:
            return []
        return list(self.prefix) + [self.base_action(original)]

    @property
    def escalates(self) -> bool:
        return self.kind == DEFER

    @property
    def is_identity(self) -> bool:
        return self.kind == ALLOW and not self.prefix

    def describe(self, original: Action) -> dict:
        return {
            "kind": self.kind,
            "inserted": [str(a) for a in self.prefix],
            "base": str(self.base_action(original)),
            "escalates": self.escalates,
        }

    def __str__(self) -> str:
        parts = []
        if self.prefix:
            parts.append("insert[" + ", ".join(a.name for a in self.prefix) + "]")
        parts.append(self.kind if self.kind != SUBSTITUTE
                     else f"substitute->{self.substitute.name}")
        return "+".join(parts)
