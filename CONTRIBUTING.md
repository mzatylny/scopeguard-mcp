# Contributing

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy src/scopeguard_mcp
bandit -q -r src
pytest
python -m build
twine check dist/*
```

## Pull requests

- Keep analyzers deterministic and read-only.
- Add tests for every authorization, target-parsing, or execution-boundary change.
- Maintain at least 90% measured coverage.
- Add a denial-path test for every authorization or execution-path test.
- Never return matched secret values in findings, logs, exceptions, or fixtures.
- Preserve audit and scan-run state transitions as atomic, append-oriented operations.
- Do not add arbitrary command execution or user-controlled shell strings.
- Document new capabilities and their operator controls.

Security-sensitive changes should explain the threat, trust boundary, failure mode, and
negative tests in the pull request description.
