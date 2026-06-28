"""The inline ShieldEngine: provider parsing, executed-action stream, sealing."""

from reinskit import (Policy, never, precedence, response, Action, AdapterConfig,
                      ToolCallAdapter, Capabilities, ShieldEngine, ShieldCertificate,
                      verify_shield)

KEY = b"x" * 32


def deployment():
    cfg = AdapterConfig(
        capabilities={"read_record": ["sensitive_read"], "transfer_funds": ["transfer"],
                      "delete_all": ["delete_all"], "archive": ["write"],
                      "audit_log": ["audit_log"], "authorize": ["authorize"], "noop": []},
        scope_allowlist=["read_record", "transfer_funds", "archive", "audit_log",
                         "authorize", "noop"])
    caps = Capabilities(
        substitutions={"delete_all": [Action.of("archive")]},
        insertables={"audit_log": Action.of("audit_log"),
                     "authorize": Action.of("authorize")})
    pol = Policy("p", [never("delete_all"), precedence("authorize", "transfer"),
                       response("sensitive_read", "audit_log", 3)])
    return pol, caps, ToolCallAdapter(cfg)


def test_observe_parses_providers_and_executes():
    pol, caps, adapter = deployment()
    eng = ShieldEngine("s", pol, caps, adapter, key=KEY)
    # Anthropic tool_use form
    dec = eng.observe({"type": "tool_use", "name": "transfer_funds",
                       "input": {"to": "acct"}}, provider="anthropic")
    names = [a.name for a in dec.output_actions]
    assert names == ["authorize", "transfer_funds"]   # prerequisite injected
    # OpenAI function form
    dec2 = eng.observe({"function": {"name": "delete_all", "arguments": "{}"}},
                       provider="openai")
    assert [a.name for a in dec2.output_actions] == ["archive"]


def test_seal_and_verify_roundtrip():
    pol, caps, adapter = deployment()
    eng = ShieldEngine("s", pol, caps, adapter, key=KEY)
    for a in [Action.of("read_record", {"id": 1}), Action.of("audit_log"),
              Action.of("delete_all"), Action.of("transfer_funds", {"to": "x"})]:
        eng.observe_action(a)
    bundle = eng.audit_bundle()
    cert = ShieldCertificate.from_dict(bundle["certificate"])
    ok, info = verify_shield(bundle["ledger"], cert, key=KEY)
    assert ok, info


def test_shieldability_reported():
    pol = Policy("p", [response("sensitive_read", "audit_log", 3)])
    cfg = AdapterConfig(capabilities={"read_record": ["sensitive_read"]})
    eng = ShieldEngine("s", pol, Capabilities(insertables={}), ToolCallAdapter(cfg))
    assert eng.shieldable is False and eng.shieldability_gaps
