"""The vendored ETTA substrate: vanilla-TA regime and clause evaluation."""

import numpy as np

from reinskit import ETTABank


def test_starts_at_exclude_boundary():
    b = ETTABank(n_clauses=4, n_literals=6)
    assert not b.actions().any()           # all literals excluded initially


def test_clause_output_is_and_of_included():
    b = ETTABank(n_clauses=1, n_literals=4)
    b.state[0, 0] = b.N + 1                 # include literal 0
    b.state[0, 2] = b.N + 1                 # include literal 2
    assert b.clause_outputs(np.array([1, 0, 1, 0]))[0] == 1   # 0 and 2 present
    assert b.clause_outputs(np.array([1, 0, 0, 0]))[0] == 0   # 2 missing


def test_empty_clause_predict_vs_train():
    b = ETTABank(n_clauses=1, n_literals=3)
    x = np.array([1, 1, 1])
    assert b.clause_outputs(x, predict=False)[0] == 1   # empty clause -> 1 in train
    assert b.clause_outputs(x, predict=True)[0] == 0    # -> 0 at predict


def test_vanilla_regime_no_trace():
    b = ETTABank(n_clauses=2, n_literals=4, lambda_decay=0.0)
    assert b.trace.sum() == 0.0
    co = b.clause_outputs(np.array([1, 0, 1, 0]))
    b.type_I_feedback(co, np.array([1, 0, 1, 0]), s=3.0)
    assert b.trace.sum() == 0.0            # trace stays zero with lambda=0
