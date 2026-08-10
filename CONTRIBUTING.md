# Contributing

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
ruff check .
pytest
python -m build
```

## Pull requests

- Keep analyzers deterministic and read-only.
- Add tests for every authorization, target-parsing, or execution-boundary change.
- Maintain at least 90% measured coverage.
- Never return matched secret values in findings, logs, exceptions, or fixtures.
- Do not add arbitrary command execution or user-controlled shell strings.
- Document new capabilities and their operator controls.

Security-sensitive changes should explain the threat, trust boundary, failure mode, and
negative tests in the pull request description.
