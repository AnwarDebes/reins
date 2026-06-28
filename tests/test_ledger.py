"""The intervention certificate: integrity (tamper-evidence), soundness replay,
and minimal-intervention re-verification (catching under- and over-restriction).
"""

import copy
import pytest

from reinskit import (Policy, always, never, bounded_count, response, precedence,
                      Action, AdapterConfig, ToolCallAdapter, Capabilities,
                      ShieldEngine, ShieldCertificate, verify_shield)
from reinskit.ledger import (LedgerEntry, merkle_root, ShieldCertificate as Cert,
                             GENESIS)

KEY = b"k" * 32

POLICY = Policy("data", [
    always("within_scope"), never("delete_all"),
    bounded_count("export", 2, 50),
    response("sensitive_read", "audit_log", 3),
    precedence("authorize", "transfer"),
])


def build_session():
    cfg = AdapterConfig(
        capabilities={"read_record": ["sensitive_read"], "send_email": ["export"],
                      "transfer_funds": ["transfer"], "delete_all": ["delete_all"],
                      "archive": ["write"], "audit_log": ["audit_log"],
                      "authorize": ["authorize"], "noop": []},
        scope_allowlist=["read_record", "send_email", "transfer_funds", "archive",
                         "audit_log", "authorize", "noop"])
    caps = Capabilities(
        substitutions={"delete_all": [Action.of("archive")]},
        insertables={"audit_log": Action.of("audit_log"),
                     "authorize": Action.of("authorize")})
    eng = ShieldEngine("s1", POLICY, caps, ToolCallAdapter(cfg), key=KEY)
    trace = [Action.of("read_record", {"id": 1}),
             Action.of("send_email", {"to": "a@x.com"}),
             Action.of("transfer_funds", {"to": "acct"}),
             Action.of("delete_all"),
             Action.of("send_email", {"to": "b@x.com"}),
             Action.of("send_email", {"to": "c@x.com"})]
    for a in trace:
        eng.observe_action(a)
    cert = eng.seal()
    return eng, cert


def reseal(entries, summary, policy, caps, key=KEY):
    """Recompute a fully self-consistent chain + certificate (models a producer
    who holds the key but recorded non-minimal edits)."""
    prev = GENESIS
    objs = [LedgerEntry(**e) if isinstance(e, dict) else e for e in entries]
    for o in objs:
        o.signature = None
        o.compute_hash(prev)
        o.sign(key)
        prev = o.entry_hash
    cert = Cert(session_id="s1", policy=policy.to_dict(), capabilities=caps.to_dict(),
                action_events=summary["action_events"], n_entries=len(objs),
                chain_head=prev, merkle_root=merkle_root([o.entry_hash for o in objs]),
                summary=summary["summary"])
    cert.sign(key)
    ledger_dict = {"session_id": "s1", "policy": policy.to_dict(),
                   "capabilities": caps.to_dict(),
                   "entries": [vars(o) for o in objs]}
    return ledger_dict, cert


def test_honest_session_verifies():
    eng, cert = build_session()
    ok, info = verify_shield(eng.ledger.to_dict(), cert, key=KEY)
    assert ok, info
    assert info["minimality_ok"] and info["soundness_ok"]


def test_tamper_event_flip():
    eng, cert = build_session()
    led = eng.ledger.to_dict()
    led["entries"][1]["payload"]["output_events"][0]["within_scope"] = 0
    ok, info = verify_shield(led, cert, key=KEY)
    assert not ok and not info["chain_ok"]


def test_tamper_edit_kind():
    eng, cert = build_session()
    led = eng.ledger.to_dict()
    led["entries"][3]["payload"]["edit"]["kind"] = "allow"
    ok, info = verify_shield(led, cert, key=KEY)
    assert not ok  # chain/sig break (payload changed under the key)


def test_tamper_delete_entry():
    eng, cert = build_session()
    led = eng.ledger.to_dict()
    del led["entries"][2]
    ok, info = verify_shield(led, cert, key=KEY)
    assert not ok and (not info["chain_ok"] or not info["merkle_ok"])


def test_tamper_insert_entry():
    eng, cert = build_session()
    led = eng.ledger.to_dict()
    led["entries"].insert(2, copy.deepcopy(led["entries"][1]))
    ok, info = verify_shield(led, cert, key=KEY)
    assert not ok


def test_tamper_reorder():
    eng, cert = build_session()
    led = eng.ledger.to_dict()
    led["entries"][1], led["entries"][2] = led["entries"][2], led["entries"][1]
    ok, info = verify_shield(led, cert, key=KEY)
    assert not ok and not info["chain_ok"]


def test_forge_without_key():
    eng, cert = build_session()
    led = eng.ledger.to_dict()
    # attacker without the key flips an event and recomputes the hash chain
    led["entries"][1]["payload"]["output_events"][0]["within_scope"] = 0
    prev = GENESIS
    for e in led["entries"]:
        body = {"index": e["index"], "payload": e["payload"], "prev_hash": prev}
        from reinskit.ledger import sha256_hex, canonical
        e["prev_hash"] = prev
        e["entry_hash"] = sha256_hex(canonical(body))
        prev = e["entry_hash"]
    ok, info = verify_shield(led, cert, key=KEY)
    assert not ok and not info["sig_ok"]   # cannot forge the HMAC


def test_minimality_catches_over_restriction():
    """A validly-signed log in which the shield SUPPRESSED an action a cheaper
    substitute would have made safe is caught as non-minimal (over-restriction)."""
    eng, cert = build_session()
    led = eng.ledger.to_dict()
    summary = {"action_events": cert.action_events, "summary": cert.summary}
    # entry 3 was a substitute(delete_all->archive); rewrite it as a suppress (noop)
    e3 = led["entries"][3]["payload"]
    e3["edit"] = {"kind": "suppress", "prefix": [], "substitute": None}
    e3["output"] = [Action.of("noop").to_dict()]
    e3["output_sigs"] = [Action.of("noop").signature()]
    e3["output_events"] = [{"within_scope": 1}]
    led2, cert2 = reseal(led["entries"], summary, POLICY, eng.caps, key=KEY)
    ok, info = verify_shield(led2, cert2, key=KEY)
    assert info["chain_ok"] and info["sig_ok"]      # integrity intact
    assert not info["minimality_ok"]                # but over-restriction caught


def test_minimality_catches_under_restriction():
    """A validly-signed log in which the shield ALLOWED an unsafe action is caught
    by both the soundness replay and the minimality re-check."""
    eng, cert = build_session()
    led = eng.ledger.to_dict()
    summary = {"action_events": cert.action_events, "summary": cert.summary}
    # entry 3 (delete_all): pretend it was allowed through unchanged
    e3 = led["entries"][3]["payload"]
    da = Action.of("delete_all")
    e3["edit"] = {"kind": "allow", "prefix": [], "substitute": None}
    e3["output"] = [da.to_dict()]
    e3["output_sigs"] = [da.signature()]
    e3["output_events"] = [{k: int(v) for k, v in sorted(
        {"delete_all": True, "within_scope": False}.items())}]
    led2, cert2 = reseal(led["entries"], summary, POLICY, eng.caps, key=KEY)
    ok, info = verify_shield(led2, cert2, key=KEY)
    assert not ok
    assert (not info["soundness_ok"]) or (not info["minimality_ok"])
