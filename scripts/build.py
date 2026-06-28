"""No-make build driver (Windows-friendly).

    python scripts/build.py test       # run the unit tests
    python scripts/build.py reproduce  # regenerate results/*.json
    python scripts/build.py figures    # rebuild paper/figures/*
    python scripts/build.py numbers    # rebuild paper/_numbers.tex
    python scripts/build.py paper      # compile paper/reins.pdf
    python scripts/build.py all        # reproduce -> figures -> numbers -> paper
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(cmd, cwd=ROOT):
    print(f"$ {' '.join(cmd)}  (cwd={cwd})")
    subprocess.run(cmd, cwd=cwd, check=True)


def test():
    run([sys.executable, "-m", "pytest", "-q"])


def reproduce():
    run([sys.executable, os.path.join("experiments", "run_all.py")])


def figures():
    run([sys.executable, os.path.join("scripts", "make_figures.py")])


def numbers():
    run([sys.executable, os.path.join("scripts", "paper_numbers.py")])


def paper():
    paper_dir = os.path.join(ROOT, "paper")
    for _ in range(2):
        run(["pdflatex", "-interaction=nonstopmode", "reins.tex"], cwd=paper_dir)
    run(["bibtex", "reins"], cwd=paper_dir)
    for _ in range(2):
        run(["pdflatex", "-interaction=nonstopmode", "reins.tex"], cwd=paper_dir)
    print("built", os.path.join(paper_dir, "reins.pdf"))


TARGETS = {"test": test, "reproduce": reproduce, "figures": figures,
           "numbers": numbers, "paper": paper}


def main():
    args = sys.argv[1:] or ["all"]
    if args == ["all"]:
        reproduce(); figures(); numbers(); paper()
        return
    for a in args:
        if a not in TARGETS:
            print(f"unknown target '{a}'; choose from {list(TARGETS)} or 'all'")
            sys.exit(2)
        TARGETS[a]()


if __name__ == "__main__":
    main()
