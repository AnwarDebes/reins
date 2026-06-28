"""The REINS engine: a drop-in certifying shield for an agent session.

``ShieldEngine`` wires the shield and the intervention ledger together behind a
tiny interface an agent runtime calls on every tool call:

    eng = ShieldEngine("s1", policy, caps, adapter, key=KEY)
    for tool_call in agent_run():
        dec = eng.observe(tool_call, provider="anthropic")
        if dec.escalated:
            pause_and_ask_human(); break
        for a in dec.output_actions:        # what the environment should execute
            execute(a)
    cert = eng.seal()                       # signed certificate of the session
    ok, info = verify_shield(eng.ledger.to_dict(), cert, key=KEY)  # model-free

The runtime executes ``dec.output_actions`` (the agent's action, possibly with an
injected prerequisite, a safer substitute, or nothing).  Whatever it executes,
the session certificate proves, to anyone holding the key and without the model,
that the executed behaviour satisfied the policy and that the shield intervened
no more than necessary.
"""

from __future__ import annotations

from typing import Optional

from .adapters import Action, ToolCallAdapter
from .enact import Capabilities, is_shieldable
from .ledger import InterventionLedger, ShieldCertificate
from .policy import Policy
from .shield import Shield, ShieldDecision


class ShieldEngine:
    def __init__(self, session_id: str, policy: Policy, caps: Capabilities,
                 adapter: ToolCallAdapter, key: Optional[bytes] = None):
        self.session_id = session_id
        self.policy = policy
        self.caps = caps
        self.adapter = adapter
        self.shield = Shield(policy, caps, adapter=adapter)
        self.ledger = InterventionLedger(session_id, policy, caps, key=key)
        self.shieldable, self.shieldability_gaps = is_shieldable(policy, caps)

    # ---- inline use ---- #
    def observe(self, call: dict, provider: str = "openai") -> ShieldDecision:
        return self.observe_action(self.adapter.parse(call, provider))

    def observe_action(self, action: Action) -> ShieldDecision:
        dec = self.shield.decide(action)
        self.ledger.append(dec, dec.input_events)
        return dec

    # ---- sealing ---- #
    def seal(self) -> ShieldCertificate:
        summary = self.shield.summary()
        summary["shieldable"] = self.shieldable
        return self.ledger.seal(summary)

    def audit_bundle(self) -> dict:
        return {"ledger": self.ledger.to_dict(), "certificate": self.seal().to_dict()}
