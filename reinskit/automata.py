"""Echo-Trace Tsetlin Automata (ETTA): the interpretable substrate.

REINS shares the propositional-logic substrate of THGTM (Debes, 2026) and TRACE:
a two-action Tsetlin Automaton (Granmo, 2018) with ``N`` states per action,
optionally augmented with one float of exponentially-decaying eligibility trace.

    state in {1, ..., 2N}   ->  include literal iff state > N
    trace in [0, 1]         ->  decayed memory of recent state transitions

With ``lambda_decay == 0`` the bank is bit-exactly a vanilla Tsetlin-Automaton
bank.  REINS itself is a *deterministic* enforcement layer and does not require a
learned model to provide its guarantees; the ETTA is vendored so that the policy
predicates the shield enforces can be supplied, when desired, by an interpretable
Tsetlin content guard (as in TRACE) rather than only by declarative adapters.
Keeping one substrate across the three systems means every predicate the shield
reasons about, whether learned or declared, has the same inspectable semantics.

This module is intentionally pure NumPy so an auditor can read it.
"""

from __future__ import annotations

import numpy as np


class ETTABank:
    """Vectorised bank of Echo-Trace Tsetlin Automata, one per (clause, literal)."""

    def __init__(
        self,
        n_clauses: int,
        n_literals: int,
        n_states_per_action: int = 100,
        lambda_decay: float = 0.0,
        trace_alpha: float = 0.0,
        rng: "np.random.Generator | None" = None,
    ):
        if not (0.0 <= lambda_decay < 1.0):
            raise ValueError("lambda_decay must be in [0, 1)")
        if trace_alpha < 0.0:
            raise ValueError("trace_alpha must be >= 0")
        self.n_clauses = int(n_clauses)
        self.n_literals = int(n_literals)
        self.N = int(n_states_per_action)
        self.lam = float(lambda_decay)
        self.alpha = float(trace_alpha)
        self.rng = rng if rng is not None else np.random.default_rng()
        self.state = np.full((self.n_clauses, self.n_literals), self.N, dtype=np.int32)
        self.trace = np.zeros((self.n_clauses, self.n_literals), dtype=np.float32)

    def actions(self) -> np.ndarray:
        """(n_clauses, n_literals) bool: True iff the TA includes the literal."""
        return self.state > self.N

    def clause_outputs(self, literals: np.ndarray, predict: bool = False) -> np.ndarray:
        """Evaluate every clause (AND over included literals) on one literal vector."""
        literals = np.asarray(literals, dtype=bool)
        inc = self.actions()
        bad = inc & ~literals[np.newaxis, :]
        any_bad = bad.any(axis=1)
        out = (~any_bad).astype(np.int8)
        if predict:
            empty = ~inc.any(axis=1)
            out = np.where(empty, np.int8(0), out)
        return out

    def _apply_delta_rows(self, rows: np.ndarray, delta_rows: np.ndarray) -> None:
        self.state[rows] = np.clip(self.state[rows] + delta_rows, 1, 2 * self.N)
        if self.lam > 0.0:
            np.multiply(self.trace, self.lam, out=self.trace)
            nz = delta_rows != 0
            if nz.any():
                self.trace[rows] += nz.astype(np.float32)
                np.minimum(self.trace, 1.0, out=self.trace)

    def _rows(self, feedback_mask) -> np.ndarray:
        if feedback_mask is None:
            return np.arange(self.n_clauses)
        return np.where(np.asarray(feedback_mask, dtype=bool))[0]

    def type_I_feedback(self, clause_outputs, literals, s, feedback_mask=None) -> None:
        """Type I (boost-and-forget) feedback to selected clauses."""
        rows = self._rows(feedback_mask)
        if rows.size == 0:
            return
        cr = np.asarray(clause_outputs, dtype=bool)[rows]
        x = np.asarray(literals, dtype=bool)
        R, L = rows.size, self.n_literals
        boost_p = (s - 1.0) / s
        forget_p = 1.0 / s
        if self.alpha > 0.0:
            amp = 1.0 + self.alpha * self.trace[rows]
            boost_p_arr = np.minimum(1.0, boost_p * amp)
            forget_p_arr = np.minimum(1.0, forget_p * amp)
        else:
            boost_p_arr = boost_p
            forget_p_arr = forget_p
        boost_mask = cr[:, None] & x[None, :]
        rand = self.rng.random((R, L)).astype(np.float32)
        delta = np.zeros((R, L), dtype=np.int32)
        delta[boost_mask & (rand < boost_p_arr)] = 1
        delta[(~boost_mask) & (rand < forget_p_arr)] = -1
        self._apply_delta_rows(rows, delta)

    def type_II_feedback(self, clause_outputs, literals, feedback_mask=None) -> None:
        """Type II (discriminative) feedback to selected clauses."""
        rows = self._rows(feedback_mask)
        if rows.size == 0:
            return
        cr = np.asarray(clause_outputs, dtype=bool)[rows]
        x = np.asarray(literals, dtype=bool)
        inc = self.state[rows] > self.N
        delta = (cr[:, None] & (~x[None, :]) & (~inc)).astype(np.int32)
        self._apply_delta_rows(rows, delta)
