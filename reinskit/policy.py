"""A small declarative policy language for agent safety (shared with TRACE).

A :class:`Policy` is a list of named temporal constraints over Boolean *events*.
Events are produced per step by an adapter (:mod:`reinskit.adapters`) from what
the agent actually did.  The policy never mentions models or features; it speaks
only of events, so the same policy, and the same shield, move unchanged
across agents and providers.

The policy is what REINS *enforces*.  Its predicates are the only vocabulary the
enforcement layer needs, which is what lets the shield's guarantees be stated and
checked independently of any model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Set

from .ltl import Monitor


def always(pred: str, name: str | None = None) -> dict:
    return {"kind": "always", "name": name or f"always({pred})", "pred": pred}


def never(event: str, name: str | None = None) -> dict:
    return {"kind": "never", "name": name or f"never({event})", "event": event}


def bounded_count(event: str, max_count: int, window: int, name: str | None = None) -> dict:
    return {"kind": "bounded_count",
            "name": name or f"count_le({event},{max_count},{window})",
            "event": event, "max_count": int(max_count), "window": int(window)}


def response(trigger: str, response: str, deadline: int, name: str | None = None) -> dict:
    return {"kind": "response",
            "name": name or f"response({trigger}->{response},{deadline})",
            "trigger": trigger, "response": response, "deadline": int(deadline)}


def precedence(first: str, second: str, name: str | None = None) -> dict:
    return {"kind": "precedence",
            "name": name or f"precedence({first}<{second})",
            "first": first, "second": second}


_EVENT_FIELDS = ("pred", "event", "trigger", "response", "first", "second")


@dataclass
class Policy:
    name: str
    constraints: List[dict] = field(default_factory=list)

    def event_names(self) -> Set[str]:
        names: Set[str] = set()
        for c in self.constraints:
            for f in _EVENT_FIELDS:
                if f in c:
                    names.add(c[f])
        return names

    def compile(self) -> List[Monitor]:
        return [Monitor.from_spec(c) for c in self.constraints]

    def to_dict(self) -> dict:
        return {"name": self.name, "constraints": [dict(c) for c in self.constraints]}

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        return cls(name=d["name"], constraints=[dict(c) for c in d["constraints"]])
