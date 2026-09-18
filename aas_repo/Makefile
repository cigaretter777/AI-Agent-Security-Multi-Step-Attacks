.PHONY: test verify compile rebuild audit

PYTHONPATH := src
export PYTHONPATH

test:
	python -m unittest discover -s tests -v

verify:
	python scripts/verify_submission.py

compile:
	python -m compileall -q src scripts tests submission baselines experiments/extracted_modules

rebuild:
	python scripts/extract_final_attack.py notebooks/final_submission.py --output submission/attack.py

audit:
	python scripts/profile_audit.py
