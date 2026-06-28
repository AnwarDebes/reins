# Changelog

## v1.0.0 - June 2026

First public release of **REINS** (Runtime Enforcement of INterpretable
Specifications): a certifying, model-free, minimal-intervention runtime shield
for LLM agents.

### Added
- **Edit algebra** (`edits.py`): allow / suppress / substitute / insert / defer,
  generalising security and edit automata to agent tool calls.
- **Enactability relation + cost model** (`enact.py`): a declarative statement of
  the edits a deployment can perform, with a static `is_shieldable` soundness
  check and a `utility_gaps` diagnostic.
- **Repair planner** (`shield.py`): per-step least-cost safe edit by exact
  simulation; proven soundness, identity-on-safe transparency, and per-step
  minimal intervention.
- **Intervention certificate** (`ledger.py`): hash-chained, HMAC-signed,
  Merkle-rooted log with a model-free `verify_shield` checking integrity,
  soundness, **and** minimal intervention (catching under- *and* over-restriction).
- **Inline engine** (`engine.py`) and model-agnostic adapters (`adapters.py`).
- Bounded-LTL monitors with side-effect-free lookahead and fast cloning
  (`ltl.py`, `behavior_guard.py`); vendored Echo-Trace Tsetlin substrate
  (`automata.py`).
- Seven reproducible experiments (E1-E7), figure and number scripts, 62 unit
  tests, a quickstart demo, and the paper source.
