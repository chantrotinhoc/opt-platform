.PHONY: test lint
test:
	PYTHONPATH=apps/api:apps/agent python -m pytest -q apps tests
