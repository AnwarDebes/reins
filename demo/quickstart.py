"""REINS in 60 seconds: wrap a mock agent, watch the shield repair its actions
with the least-cost enactable edit, then seal and independently verify the
certificate, without the model.

    python demo/quickstart.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reinskit import (Policy, always, never, bounded_count, response, precedence,
                      Action, AdapterConfig, ToolCallAdapter, Capabilities,
                      is_shieldable, ShieldEngine, ShieldCertificate, verify_shield)

KEY = b"demo-key-please-rotate-in-prod!!"

# 1) declare an interpretable temporal policy over tool-call events
policy = Policy("data-handling", [
    always("within_scope"),                              # only allow-listed tools
    never("delete_all"),                                 # destructive op forbidden
    bounded_count("export", max_count=2, window=50),     # <= 2 external sends
    response("sensitive_read", "audit_log", deadline=3), # audit every sensitive read
    precedence("authorize", "transfer"),                 # authorise before transfer
])

# 2) map tools to events
adapter = ToolCallAdapter(AdapterConfig(
    capabilities={
        "read_record": ["read", "sensitive_read"], "send_email": ["export"],
        "transfer_funds": ["transfer"], "delete_all": ["delete_all"],
        "archive": ["write"], "audit_log": ["audit_log"],
        "authorize": ["authorize"], "respond": [], "noop": []},
    scope_allowlist=["read_record", "send_email", "transfer_funds", "archive",
                     "audit_log", "authorize", "respond", "noop"]))

# 3) declare what the deployment can ENACT (its capabilities + cost model)
caps = Capabilities(
    substitutions={"delete_all": [Action.of("archive")]},     # safer variant
    insertables={"audit_log": Action.of("audit_log"),         # injectable prerequisites
                 "authorize": Action.of("authorize")},
    escalation=True)

print("shieldable (soundness guaranteed?):", is_shieldable(policy, caps)[0], "\n")

eng = ShieldEngine("demo-session", policy, caps, adapter, key=KEY)

# 4) a hijacked/forgetful agent's tool calls; REINS keeps the task safe AND moving
agent_calls = [
    {"function": {"name": "read_record", "arguments": '{"id": 42}'}},
    {"function": {"name": "transfer_funds", "arguments": '{"to": "internal"}'}},  # no prior authorize
    {"function": {"name": "delete_all", "arguments": "{}"}},                      # forbidden
    {"function": {"name": "send_email", "arguments": '{"to": "a@partner.com"}'}}, # export 1
    {"function": {"name": "send_email", "arguments": '{"to": "b@partner.com"}'}}, # export 2
    {"function": {"name": "send_email", "arguments": '{"to": "c@partner.com"}'}}, # export 3 -> over budget
    {"function": {"name": "respond", "arguments": "{}"}},                         # audit now due
]
for call in agent_calls:
    dec = eng.observe(call, provider="openai")
    print(dec.explain())

# 5) seal a certificate and re-verify it model-free
cert = eng.seal()
bundle = eng.audit_bundle()
ok, info = verify_shield(bundle["ledger"], ShieldCertificate.from_dict(bundle["certificate"]),
                         key=KEY)
print("\nsession sound:", eng.shield.session_sound, "| interventions:",
      eng.shield.summary()["interventions_by_kind"])
print("certificate verifies (integrity + soundness + minimality):", ok)
assert ok and all(info[k] for k in ("soundness_ok", "minimality_ok"))
print("\nMerkle root:", cert.merkle_root[:32], "...")
