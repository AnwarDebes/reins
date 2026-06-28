"""REINS: Runtime Enforcement of INterpretable Specifications for LLM agents.

A certifying, minimal-intervention runtime *shield*.  Where a detector tells you
an agent *did* something unsafe and a blocking guard *stops* it (at the cost of
the task), REINS computes the least-cost *enactable edit* (inject a missing
prerequisite, substitute a safer variant, suppress, or defer to a human) that
keeps the agent's trajectory inside an interpretable bounded-LTL policy's safe
language, and seals every intervention into a tamper-evident certificate an
auditor re-verifies without the model.

Built on the interpretable propositional substrate of THGTM and TRACE
(Debes, 2026).

Public API
----------
    Policy, always, never, bounded_count, response, precedence   # the spec
    Action, AdapterConfig, ToolCallAdapter                       # agent I/O
    Capabilities, CostModel, is_shieldable, utility_gaps         # enactability
    Edit, ALLOW, SUPPRESS, SUBSTITUTE, DEFER                     # the edit algebra
    Shield, ShieldDecision                                       # the planner
    ShieldEngine                                                 # the inline wrapper
    InterventionLedger, ShieldCertificate, verify_shield         # the certificate
"""

from .policy import Policy, always, never, bounded_count, response, precedence
from .adapters import Action, AdapterConfig, ToolCallAdapter, NOOP
from .behavior_guard import BehaviorGuard, StepVerdict
from .ltl import (Monitor, Always, Never, BoundedCount, Response, Precedence,
                  Violation)
from .enact import Capabilities, CostModel, is_shieldable, utility_gaps
from .edits import Edit, ALLOW, SUPPRESS, SUBSTITUTE, DEFER
from .shield import Shield, ShieldDecision
from .engine import ShieldEngine
from .ledger import (InterventionLedger, ShieldCertificate, verify_shield,
                     merkle_root)
from .automata import ETTABank

__version__ = "1.0.0"
__author__ = "Anwar Debes"

__all__ = [
    "Policy", "always", "never", "bounded_count", "response", "precedence",
    "Action", "AdapterConfig", "ToolCallAdapter", "NOOP",
    "BehaviorGuard", "StepVerdict",
    "Monitor", "Always", "Never", "BoundedCount", "Response", "Precedence", "Violation",
    "Capabilities", "CostModel", "is_shieldable", "utility_gaps",
    "Edit", "ALLOW", "SUPPRESS", "SUBSTITUTE", "DEFER",
    "Shield", "ShieldDecision", "ShieldEngine",
    "InterventionLedger", "ShieldCertificate", "verify_shield", "merkle_root",
    "ETTABank",
]
