"""Run every REINS experiment end-to-end, regenerating results/*.json.

Each module is self-contained and writes its own results/<name>.json; this driver
just invokes them in order so ``python experiments/run_all.py`` reproduces every
number in the paper on a single CPU in a couple of minutes.
"""

from __future__ import annotations

import importlib
import time

MODULES = ["safety_utility", "soundness", "transparency", "certificate",
           "systems", "robustness", "case_studies"]


def main():
    for name in MODULES:
        print(f"\n===== {name} =====")
        t0 = time.perf_counter()
        importlib.import_module(name).main()
        print(f"  ({time.perf_counter() - t0:.1f}s)")
    print("\nAll experiments done; results/*.json regenerated.")


if __name__ == "__main__":
    main()
