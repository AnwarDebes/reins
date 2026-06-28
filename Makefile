# REINS convenience targets.  No `make`?  Use: python scripts/build.py <target>
PY ?= python

.PHONY: all test reproduce figures numbers paper demo clean

all: reproduce figures numbers paper

test:
	$(PY) -m pytest -q

reproduce:
	$(PY) experiments/run_all.py

figures:
	$(PY) scripts/make_figures.py

numbers:
	$(PY) scripts/paper_numbers.py

demo:
	$(PY) demo/quickstart.py

paper:
	cd paper && pdflatex -interaction=nonstopmode reins.tex && bibtex reins && \
	  pdflatex -interaction=nonstopmode reins.tex && \
	  pdflatex -interaction=nonstopmode reins.tex

clean:
	cd paper && rm -f *.aux *.bbl *.blg *.out *.log
