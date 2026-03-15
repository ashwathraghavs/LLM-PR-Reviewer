# Contributing

## Development setup

```bash
git clone https://github.com/your-org/llm-pr-reviewer.git
cd llm-pr-reviewer
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-cov
```

## Running the tests

```bash
# Full suite
pytest tests/ -v

# Just the deterministic tests (no LLM calls needed)
pytest tests/test_injection_scanner.py tests/test_cost_controls.py tests/test_judge_calibration.py -v

# With coverage
pytest tests/ --cov=src/reviewer --cov-report=term-missing
```

## What to contribute

### Injection patterns

If you encounter an injection attempt in the wild that the scanner didn't catch, add it to `INJECTION_PATTERNS` in `injection_defense.py` and add a corresponding test in `tests/test_injection_scanner.py`. A pattern without a test won't be accepted — regressions are too easy otherwise.

### Golden calibration cases

This is the highest-value contribution. If you have a real PR where the reviewer produced a wrong verdict — either a false positive (blocked good code) or a false negative (approved bad code) — please add it to `tests/golden_set/` with:

1. A sanitized diff (strip author info, proprietary variable names if needed)
2. The static analysis output that accompanied it
3. The correct expected verdict and a comment explaining why

These cases build up institutional knowledge about where the judge's judgment is reliable and where it isn't.

### Scoring weight changes

Open an issue before changing `SECURITY_WEIGHT`, `QUALITY_WEIGHT`, or `TEST_WEIGHT`. These affect every repo using the system and benefit from discussion. Include data from the golden set showing what the score distribution looks like before and after the change.

### Cost cap changes

The defaults in `config.py` are conservative by design. If your team's volume warrants different caps, change them in your fork rather than in the defaults. The defaults should work safely for a team that doesn't know their review volume yet.

## Code style

- `ruff` for formatting (line length 100)
- Type hints on all function signatures
- No bare `except` — always catch a specific exception type
- Every new module needs a docstring explaining its purpose and design rationale

## Release process

Version numbers follow the scoring model's major version — if you change the weighting formula in a way that would shift most PR scores, that's a major version bump. Patch releases are backwards-compatible fixes.
