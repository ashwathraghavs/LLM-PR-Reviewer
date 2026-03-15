"""
Tests for cost controls: pre-flight estimation, budget caps, rate limiting.
Run with: pytest tests/test_cost_controls.py -v
"""

import pytest
from unittest.mock import patch

from src.reviewer.cost_controls import (
    estimate_tokens,
    preflight_cost_check,
    truncate_diff_to_budget,
    PromptTooLargeError,
    BudgetExceededError,
)
from src.reviewer import config


class TestTokenEstimation:
    def test_empty_string(self):
        assert estimate_tokens("") == 0

    def test_approximate_english(self):
        # "Hello world" = 11 chars → ~2 tokens
        tokens = estimate_tokens("Hello world")
        assert 2 <= tokens <= 4

    def test_large_prompt(self):
        text   = "x" * 40_000
        tokens = estimate_tokens(text)
        assert tokens == 10_000


class TestPreflightCheck:
    def test_normal_prompt_passes(self):
        prompt = "def add(a, b): return a + b"
        result = preflight_cost_check(prompt)
        assert "est_cost_usd" in result
        assert result["est_cost_usd"] > 0

    def test_oversized_prompt_raises(self):
        huge_prompt = "x" * (config.MAX_INPUT_TOKENS * 4 + 1000)
        with pytest.raises(PromptTooLargeError):
            preflight_cost_check(huge_prompt)

    def test_cost_exceeds_cap_raises(self):
        # Create a prompt that estimates over MAX_COST_PER_REVIEW
        # by temporarily lowering the cap
        original_cap = config.MAX_COST_PER_REVIEW
        config.MAX_COST_PER_REVIEW = 0.000001
        try:
            with pytest.raises(BudgetExceededError):
                preflight_cost_check("some reasonable prompt with content")
        finally:
            config.MAX_COST_PER_REVIEW = original_cap


class TestDiffTruncation:
    def test_small_diff_unchanged(self):
        files = [{"filename": "a.py", "patch": "+x = 1\n+y = 2\n", "status": "modified"}]
        result = truncate_diff_to_budget(files, {})
        assert len(result) == 1
        assert "+x = 1" in result[0]["patch"]

    def test_prioritizes_flagged_lines(self):
        patch = "\n".join(f"+line_{i} = {i}" for i in range(200))
        files  = [{"filename": "a.py", "patch": patch, "status": "modified"}]
        static = {
            "bandit": {
                "a.py": {
                    "raw_results": [{"line_number": 5, "test_id": "B101",
                                     "issue_severity": "HIGH", "test_name": "test"}]
                }
            },
            "pylint": {},
        }
        original_max = config.MAX_INPUT_TOKENS
        config.MAX_INPUT_TOKENS = 50  # Force truncation
        try:
            result = truncate_diff_to_budget(files, static)
            assert len(result) > 0
            # Line 5 should be in the truncated output
            assert any("line_4" in r["patch"] or "line_5" in r["patch"] for r in result)
        finally:
            config.MAX_INPUT_TOKENS = original_max
