"""Model-agnostic adapters: turn an agent action into policy events.

REINS sits inline between an agent and its tools, so, like TRACE, it must
speak every provider's wire format.  An adapter normalises OpenAI / DeepSeek
``function`` calls and Anthropic ``tool_use`` blocks into a canonical
:class:`Action` ``(name, arguments)`` and then maps that action to the Boolean
*events* a :class:`~reinskit.policy.Policy` is written in, via a declarative
capability table.

One thing REINS needs that a pure monitor does not: the shield *constructs* new
actions (a safer substitute, an injected prerequisite) and must know their
events too.  Because the mapping ``Action -> events`` is a plain function of the
capability table, the shield evaluates the events of any synthetic action with
the same code path, and there is no separate, untrusted "what would this edit do"
oracle.  The audit trail records *events*, so neither the provider nor the fact
that an action was synthesised by the shield ever leaks the model into the
certificate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass(frozen=True)
class Action:
    """A canonical agent action: a tool name and its arguments."""
    name: str
    arguments: tuple = ()           # tuple of (key, value) pairs -> hashable

    @staticmethod
    def of(name: str, arguments: Optional[dict] = None) -> "Action":
        items = tuple(sorted((str(k), _freeze(v)) for k, v in (arguments or {}).items()))
        return Action(name=name, arguments=items)

    @property
    def args(self) -> dict:
        return {k: v for k, v in self.arguments}

    def __str__(self) -> str:
        a = ", ".join(f"{k}={v}" for k, v in self.arguments)
        return f"{self.name}({a})"

    def signature(self) -> str:
        """A canonical, model-free key for this action (used in certificates)."""
        return self.name + "|" + repr(self.arguments)

    def to_dict(self) -> dict:
        return {"name": self.name, "arguments": [[k, _unfreeze(v)] for k, v in self.arguments]}

    @staticmethod
    def from_dict(d: dict) -> "Action":
        return Action.of(d["name"], {k: v for k, v in d.get("arguments", [])})


def _unfreeze(v):
    if isinstance(v, tuple) and v and isinstance(v[0], tuple) and len(v[0]) == 2:
        return {k: _unfreeze(x) for k, x in v}
    if isinstance(v, tuple):
        return [_unfreeze(x) for x in v]
    return v


def _freeze(v):
    if isinstance(v, dict):
        return tuple(sorted((str(k), _freeze(x)) for k, x in v.items()))
    if isinstance(v, (list, tuple)):
        return tuple(_freeze(x) for x in v)
    return v


# canonical synthetic actions the shield uses
NOOP = Action.of("noop")


# provider parsers ------------------------------------------------------ #
def _loads(arguments) -> dict:
    if isinstance(arguments, dict):
        return arguments
    if isinstance(arguments, str):
        try:
            return json.loads(arguments) if arguments.strip() else {}
        except json.JSONDecodeError:
            return {"_raw": arguments}
    return {}


def parse_openai(call: dict) -> Action:
    fn = call.get("function", call)
    return Action.of(fn.get("name", ""), _loads(fn.get("arguments", {})))


def parse_anthropic(call: dict) -> Action:
    return Action.of(call.get("name", ""), _loads(call.get("input", {})))


PARSERS: Dict[str, Callable[[dict], Action]] = {
    "openai": parse_openai,
    "deepseek": parse_openai,
    "anthropic": parse_anthropic,
}


# capability mapping ---------------------------------------------------- #
@dataclass
class AdapterConfig:
    """Declarative tool-capability table (events an action raises)."""
    capabilities: Dict[str, List[str]] = field(default_factory=dict)
    scope_allowlist: List[str] = field(default_factory=list)
    external_recipient_keys: List[str] = field(
        default_factory=lambda: ["to", "recipient", "url", "dest", "address"])
    internal_domains: List[str] = field(
        default_factory=lambda: ["internal", "localhost", "127.0.0.1"])
    arg_rules: Optional[Callable[[Action], Dict[str, bool]]] = None


class ToolCallAdapter:
    """Normalise any provider's tool call into a canonical event dict."""

    def __init__(self, config: AdapterConfig):
        self.config = config

    def parse(self, call: dict, provider: str = "openai") -> Action:
        parser = PARSERS.get(provider)
        if parser is None:
            raise ValueError(f"unknown provider '{provider}' (have {list(PARSERS)})")
        return parser(call)

    def events_of(self, a: Action) -> Dict[str, bool]:
        """Map a (possibly synthetic) action to its policy events."""
        if a.name == NOOP.name:
            # a suppressed step is a benign idle: in scope, raises nothing.
            return {"within_scope": True}
        caps = self.config.capabilities.get(a.name, [])
        args = a.args
        events: Dict[str, bool] = {}
        for tag in caps:
            if tag != "export":
                events[tag] = True
        events["within_scope"] = (not self.config.scope_allowlist) or (a.name in self.config.scope_allowlist)
        external = False
        has_recipient = False
        for k in self.config.external_recipient_keys:
            if k in args:
                has_recipient = True
                val = str(args[k]).lower()
                if val and not any(d in val for d in self.config.internal_domains):
                    external = True
        if external:
            events["target_external"] = True
        if "export" in caps and (external or not has_recipient):
            events["export"] = True
        if self.config.arg_rules is not None:
            for k, v in self.config.arg_rules(a).items():
                events[k] = bool(v)
        return events

    # backward-compatible aliases
    def step_events(self, call: dict, provider: str = "openai") -> Dict[str, bool]:
        return self.events_of(self.parse(call, provider))

    def to_events(self, a: Action) -> Dict[str, bool]:
        return self.events_of(a)
