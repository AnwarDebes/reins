"""Tamper-evident *intervention* ledger and certificate.

Where TRACE certifies what a guard *observed*, REINS certifies what the shield
*did*: every step records the agent's candidate action, the edit the shield
applied, and the resulting executed actions, appended to a hash-chained,
HMAC-signed, Merkle-rooted log in the tamper-evident-logging tradition
(Schneier & Kelsey 1999; Crosby & Wallach 2009; RFC 6962).

    h_i = SHA256( h_{i-1} || canonical(payload_i) ),   sigma_i = HMAC_k(h_i)

An auditor re-verifies the certificate **without the model** and obtains three
guarantees, the third of which is new to this line of work:

  1. *Integrity*: any modification / insertion / deletion / reordering of a
     sealed entry breaks the chain or the Merkle root (Proposition: tamper-evidence).
  2. *Soundness*: replaying the recorded executed-event stream through the
     policy monitors confirms no monitor was ever violated: the agent's behaviour
     after shielding satisfied the policy.
  3. *Minimal intervention*: the certificate embeds the policy, the capability
     set, the cost model and a model-free action->events map, so the auditor
     **re-runs the shield's decision** at every step and checks the recorded edit
     equals the least-cost safe edit.  A shield that *under*-intervened (let an
     unsafe action through) or *over*-intervened (blocked an action a cheaper safe
     edit would have allowed) is caught.  This certifies the agent was neither
     under- nor over-restricted, an auditable answer to the over-blocking that
     plagues guardrails.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

from .adapters import Action, NOOP
from .behavior_guard import BehaviorGuard
from .enact import Capabilities
from .policy import Policy

GENESIS = "0" * 64


# ---------------------------------------------------------------------- #
def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def merkle_root(leaf_hashes: List[str]) -> str:
    if not leaf_hashes:
        return GENESIS
    level = [bytes.fromhex(h) for h in leaf_hashes]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def _ev(events: Dict[str, bool]) -> Dict[str, int]:
    return {k: int(bool(v)) for k, v in sorted(events.items())}


# ---------------------------------------------------------------------- #
@dataclass
class LedgerEntry:
    index: int
    payload: dict
    prev_hash: str = GENESIS
    entry_hash: str = ""
    signature: Optional[str] = None

    def compute_hash(self, prev_hash: str) -> str:
        self.prev_hash = prev_hash
        body = {"index": self.index, "payload": self.payload, "prev_hash": prev_hash}
        self.entry_hash = sha256_hex(canonical(body))
        return self.entry_hash

    def sign(self, key: bytes) -> "LedgerEntry":
        self.signature = hmac_hex(key, self.entry_hash.encode())
        return self


@dataclass
class ShieldCertificate:
    session_id: str
    policy: dict
    capabilities: dict
    action_events: Dict[str, Dict[str, int]]   # signature -> events (model-free)
    n_entries: int
    chain_head: str
    merkle_root: str
    summary: dict
    signature: Optional[str] = None

    def _root_body(self) -> dict:
        return {"session_id": self.session_id, "policy": self.policy,
                "capabilities": self.capabilities, "action_events": self.action_events,
                "n_entries": self.n_entries, "chain_head": self.chain_head,
                "merkle_root": self.merkle_root, "summary": self.summary}

    def sign(self, key: bytes) -> "ShieldCertificate":
        self.signature = hmac_hex(key, canonical(self._root_body()))
        return self

    def verify_signature(self, key: bytes) -> bool:
        if self.signature is None:
            return False
        return hmac.compare_digest(self.signature, hmac_hex(key, canonical(self._root_body())))

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "ShieldCertificate":
        return ShieldCertificate(**d)


# ---------------------------------------------------------------------- #
class InterventionLedger:
    """Append-only, hash-chained log of shield interventions for one session."""

    def __init__(self, session_id: str, policy: Policy, caps: Capabilities,
                 key: Optional[bytes] = None):
        self.session_id = session_id
        self.policy = policy
        self.caps = caps
        self.key = key
        self.entries: List[LedgerEntry] = []
        self.action_events: Dict[str, Dict[str, int]] = {}
        self._head = GENESIS
        self._record_action_events(NOOP, {"within_scope": True})

    def _record_action_events(self, action: Action, events: Dict[str, bool]) -> None:
        self.action_events.setdefault(action.signature(), _ev(events))

    def append(self, decision, input_events: Dict[str, bool]) -> LedgerEntry:
        # record the model-free events of every action this step touched
        self._record_action_events(decision.input_action, input_events)
        for a, ev in zip(decision.output_actions, decision.output_events):
            self._record_action_events(a, ev)
        payload = {
            "step": int(decision.step),
            "input": decision.input_action.to_dict(),
            "input_sig": decision.input_action.signature(),
            "edit": {
                "kind": decision.edit.kind,
                "prefix": [a.to_dict() for a in decision.edit.prefix],
                "substitute": decision.edit.substitute.to_dict() if decision.edit.substitute else None,
            },
            "output": [a.to_dict() for a in decision.output_actions],
            "output_sigs": [a.signature() for a in decision.output_actions],
            "output_events": [_ev(e) for e in decision.output_events],
            "enforced": sorted(decision.enforced_monitors),
            "cost": float(decision.cost),
            "escalated": bool(decision.escalated),
            "enforcement_failed": bool(decision.enforcement_failed),
        }
        e = LedgerEntry(index=len(self.entries), payload=payload)
        e.compute_hash(self._head)
        if self.key is not None:
            e.sign(self.key)
        self.entries.append(e)
        self._head = e.entry_hash
        return e

    def seal(self, summary: dict) -> ShieldCertificate:
        cert = ShieldCertificate(
            session_id=self.session_id,
            policy=self.policy.to_dict(),
            capabilities=self.caps.to_dict(),
            action_events=dict(self.action_events),
            n_entries=len(self.entries),
            chain_head=self._head,
            merkle_root=merkle_root([e.entry_hash for e in self.entries]),
            summary=summary,
        )
        if self.key is not None:
            cert.sign(self.key)
        return cert

    def to_dict(self) -> dict:
        return {"session_id": self.session_id, "policy": self.policy.to_dict(),
                "capabilities": self.caps.to_dict(),
                "entries": [asdict(e) for e in self.entries]}

    @staticmethod
    def entries_from_dict(d: dict) -> List[LedgerEntry]:
        return [LedgerEntry(**e) for e in d["entries"]]


# ---------------------------------------------------------------------- #
def verify_shield(ledger_dict: dict, cert: ShieldCertificate,
                  key: Optional[bytes] = None) -> Tuple[bool, dict]:
    """Re-verify a sealed shield session from scratch, model-free.

    Checks integrity (chain/merkle/signatures), soundness (recorded executed
    behaviour satisfies the policy), and minimal intervention (the recorded edit
    equals the recomputed least-cost safe edit at every step).
    """
    from .shield import Shield   # local import avoids any import cycle

    entries = InterventionLedger.entries_from_dict(ledger_dict)
    info: dict = {"chain_ok": True, "sig_ok": True, "merkle_ok": True,
                  "soundness_ok": True, "minimality_ok": True,
                  "first_bad_entry": None, "notes": []}

    # 1) hash chain + per-entry signatures
    prev = GENESIS
    for e in entries:
        body = {"index": e.index, "payload": e.payload, "prev_hash": prev}
        if sha256_hex(canonical(body)) != e.entry_hash or e.prev_hash != prev:
            info["chain_ok"] = False
            info["first_bad_entry"] = e.index
            info["notes"].append(f"hash/chain mismatch at entry {e.index}")
            break
        if key is not None and e.signature != hmac_hex(key, e.entry_hash.encode()):
            info["sig_ok"] = False
            info["first_bad_entry"] = e.index
            info["notes"].append(f"bad signature at entry {e.index}")
            break
        prev = e.entry_hash

    # 2) Merkle root + chain head + certificate signature
    if merkle_root([e.entry_hash for e in entries]) != cert.merkle_root:
        info["merkle_ok"] = False
        info["notes"].append("merkle root mismatch")
    if entries and entries[-1].entry_hash != cert.chain_head:
        info["chain_ok"] = False
        info["notes"].append("chain head mismatch")
    if key is not None and not cert.verify_signature(key):
        info["sig_ok"] = False
        info["notes"].append("certificate signature invalid")

    # 3) Soundness: replay the executed-event stream; no monitor may ever violate
    policy = Policy.from_dict(cert.policy)
    guard = BehaviorGuard(policy)
    for e in entries:
        for ev in e.payload["output_events"]:
            sv = guard.step({k: bool(v) for k, v in ev.items()})
            if not sv.ok and not e.payload.get("enforcement_failed", False):
                info["soundness_ok"] = False
                info["notes"].append(f"soundness: monitor violated at entry {e.index}")
                break
        if not info["soundness_ok"]:
            break
    if guard.session_ok != cert.summary.get("session_sound", guard.session_ok):
        # only a hard failure if the cert claims soundness it does not have
        if cert.summary.get("session_sound") and not guard.session_ok:
            info["soundness_ok"] = False
            info["notes"].append("certificate claims soundness but replay violates")

    # 4) Minimal intervention: re-run the shield from the certificate and compare
    caps = Capabilities.from_dict(cert.capabilities)
    amap = cert.action_events

    def resolver(a: Action) -> Dict[str, bool]:
        sig = a.signature()
        if sig in amap:
            return {k: bool(v) for k, v in amap[sig].items()}
        # an action the certificate never recorded -> tampering / inconsistency
        raise KeyError(sig)

    try:
        replay = Shield(policy, caps, events_of=resolver)
        for e in entries:
            action = Action.from_dict(e.payload["input"])
            dec = replay.decide(action)
            rec = e.payload["edit"]
            if (dec.edit.kind != rec["kind"]
                    or [a.to_dict() for a in dec.edit.prefix] != rec["prefix"]
                    or (dec.edit.substitute.to_dict() if dec.edit.substitute else None) != rec["substitute"]):
                info["minimality_ok"] = False
                info["first_bad_entry"] = e.index
                info["notes"].append(
                    f"intervention mismatch at entry {e.index}: "
                    f"recorded {rec['kind']}, recomputed {dec.edit.kind}")
                break
            if [_ev(x) for x in dec.output_events] != e.payload["output_events"]:
                info["minimality_ok"] = False
                info["first_bad_entry"] = e.index
                info["notes"].append(f"output-event mismatch at entry {e.index}")
                break
    except KeyError as exc:
        info["minimality_ok"] = False
        info["notes"].append(f"action-events map missing {exc} (tampered certificate)")

    ok = all(info[k] for k in ("chain_ok", "sig_ok", "merkle_ok",
                               "soundness_ok", "minimality_ok"))
    info["ok"] = ok
    return ok, info
