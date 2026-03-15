# Golden test set

This directory contains real PR diffs with known correct verdicts, used to detect
scoring drift and prompt regression.

## Adding a case

Create a subdirectory named after the PR category:

```
tests/golden_set/
└── sql_injection_blocked/
    ├── diff.patch          # sanitized diff (strip author info)
    ├── static_output.json  # bandit + pylint + safety results
    ├── expected.json       # {"decision": "REQUEST_CHANGES", "score_range": [0, 50]}
    └── notes.md            # why this verdict is correct
```

Then reference it in `tests/test_judge_calibration.py` under `GOLDEN_CASES`.

## What makes a good golden case

- The verdict was agreed upon by at least two senior engineers
- The code is real (or closely based on real code) — synthetic examples
  tend not to exercise the same failure modes
- The notes explain the *reasoning*, not just the verdict — so future
  maintainers understand what the case is testing

## Current cases

Cases are defined in `tests/test_judge_calibration.py` as inline synthetic
static analysis output. Replace with real diffs from your codebase as you
accumulate them.
