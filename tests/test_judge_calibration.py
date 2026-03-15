"""
Calibration test suite — detects scoring drift and prompt sensitivity regressions.

The golden set consists of real PR characteristics with expected score ranges
established by senior engineers. Run this after any prompt change:

    pytest tests/test_judge_calibration.py -v

If average drift exceeds 5 points or any case falls outside its expected range,
the test fails and the prompt change should be reconsidered.
"""

import pytest

# ── Golden set ────────────────────────────────────────────────────────────────
# Each entry describes a category of PR rather than a specific diff,
# since we can't include real proprietary code in the test suite.
# Replace with real diffs from your own repository for maximum calibration value.
#
# Structure:
#   name: descriptive label
#   expected_decision: APPROVE | REQUEST_CHANGES | COMMENT
#   score_range: (min, max) acceptable overall score
#   static: synthetic static analysis output matching the scenario

GOLDEN_CASES = [
    {
        "name":              "clean_pr_no_findings",
        "expected_decision": "APPROVE",
        "score_range":       (75, 100),
        "static": {
            "pylint": {"main.py": {"error_count": 0, "warning_count": 1, "messages": [], "top": []}},
            "bandit": {"main.py": {"high_count": 0, "medium_count": 0, "raw_results": [], "top": []}},
            "safety": {"vulnerabilities": []},
        },
    },
    {
        "name":              "high_severity_sql_injection",
        "expected_decision": "REQUEST_CHANGES",
        "score_range":       (0, 50),
        "static": {
            "pylint": {"db.py": {"error_count": 0, "warning_count": 0, "messages": [], "top": []}},
            "bandit": {"db.py": {
                "high_count": 1,
                "medium_count": 0,
                "raw_results": [{
                    "test_id": "B608", "test_name": "hardcoded_sql_expressions",
                    "issue_severity": "HIGH", "line_number": 24,
                    "issue_text": "Possible SQL injection via string-based query construction"
                }],
                "top": ["[HIGH] hardcoded_sql_expressions (B608) L24: Possible SQL injection"],
            }},
            "safety": {"vulnerabilities": []},
        },
    },
    {
        "name":              "known_cve_in_dependencies",
        "expected_decision": "REQUEST_CHANGES",
        "score_range":       (0, 40),
        "static": {
            "pylint": {},
            "bandit": {},
            "safety": {"vulnerabilities": [
                {"package": "requests", "affected_versions": "< 2.32.0",
                 "cve": "CVE-2024-35195", "advisory": "SSRF vulnerability"}
            ]},
        },
    },
    {
        "name":              "many_pylint_errors",
        "expected_decision": "REQUEST_CHANGES",
        "score_range":       (20, 65),
        "static": {
            "pylint": {"module.py": {
                "error_count": 8,
                "warning_count": 12,
                "messages": [{"symbol": "undefined-variable", "type": "error", "line": i, "message": "Undefined variable"} for i in range(8)],
                "top": ["[ERROR] undefined-variable L5"] * 6,
            }},
            "bandit": {"module.py": {"high_count": 0, "medium_count": 0, "raw_results": [], "top": []}},
            "safety": {"vulnerabilities": []},
        },
    },
    {
        "name":              "medium_security_borderline",
        "expected_decision": "COMMENT",
        "score_range":       (60, 80),
        "static": {
            "pylint": {"api.py": {"error_count": 1, "warning_count": 3, "messages": [], "top": []}},
            "bandit": {"api.py": {
                "high_count": 0,
                "medium_count": 2,
                "raw_results": [
                    {"test_id": "B105", "test_name": "hardcoded_password_string",
                     "issue_severity": "MEDIUM", "line_number": 12, "issue_text": "Possible hardcoded password"},
                ],
                "top": ["[MEDIUM] hardcoded_password_string (B105) L12"],
            }},
            "safety": {"vulnerabilities": []},
        },
    },
]


class TestDeterministicOverrides:
    """
    These tests don't require LLM calls — they test the override layer directly.
    Fast, cheap, and should run on every CI build.
    """

    def test_high_bandit_caps_security_score(self):
        from src.reviewer.output_validator import apply_deterministic_overrides
        verdict = {
            "security_score": 90, "quality_score": 85, "test_score": 80,
            "overall_score": 85, "confidence": "HIGH", "inline_comments": [],
            "decision": "APPROVE",
        }
        static = {
            "bandit": {"main.py": {"high_count": 1, "raw_results": []}},
            "pylint": {}, "safety": {"vulnerabilities": []},
        }
        result = apply_deterministic_overrides(verdict, static, {"injection_risk": False, "findings": []})
        assert result["security_score"] <= 40
        assert result["decision"] == "REQUEST_CHANGES"

    def test_cve_forces_block(self):
        from src.reviewer.output_validator import apply_deterministic_overrides
        verdict = {
            "security_score": 80, "quality_score": 90, "test_score": 85,
            "overall_score": 85, "confidence": "HIGH", "inline_comments": [],
            "decision": "APPROVE",
        }
        static = {
            "bandit": {"main.py": {"high_count": 0, "raw_results": []}},
            "pylint": {},
            "safety": {"vulnerabilities": [{"cve": "CVE-2024-0001"}]},
        }
        result = apply_deterministic_overrides(verdict, static, {"injection_risk": False, "findings": []})
        assert result["decision"] == "REQUEST_CHANGES"

    def test_injection_detection_zeroes_score(self):
        from src.reviewer.output_validator import apply_deterministic_overrides
        verdict = {
            "security_score": 95, "quality_score": 95, "test_score": 95,
            "overall_score": 95, "confidence": "HIGH", "inline_comments": [],
            "decision": "APPROVE",
        }
        injection_scan = {
            "injection_risk": True,
            "high_count": 1,
            "findings": [{"file": "attack.py", "severity": "HIGH", "label": "System prompt impersonation", "type": "INJECTION_PATTERN"}],
        }
        result = apply_deterministic_overrides(verdict, {}, injection_scan)
        assert result["overall_score"] == 0
        assert result["decision"] == "REQUEST_CHANGES"

    def test_clean_pr_approves(self):
        from src.reviewer.output_validator import apply_deterministic_overrides
        verdict = {
            "security_score": 88, "quality_score": 84, "test_score": 79,
            "overall_score": 84, "confidence": "HIGH", "inline_comments": [],
            "decision": "APPROVE",
        }
        static = {
            "bandit": {"main.py": {"high_count": 0, "raw_results": []}},
            "pylint": {"main.py": {"error_count": 0, "warning_count": 1}},
            "safety": {"vulnerabilities": []},
        }
        result = apply_deterministic_overrides(verdict, static, {"injection_risk": False, "findings": []})
        assert result["decision"] == "APPROVE"


class TestHallucinationFilter:
    def test_unanchored_finding_stripped(self):
        from src.reviewer.judge import validate_findings
        verdict = {
            "inline_comments": [
                {"path": "a.py", "line": 5, "body": "SQL injection",
                 "source_tool": "bandit", "tool_id": "B608"},  # valid
                {"path": "a.py", "line": 10, "body": "Made up issue",
                 "source_tool": "bandit", "tool_id": "B999"},  # hallucinated
            ]
        }
        static = {
            "bandit": {"a.py": {
                "raw_results": [{"test_id": "B608", "line_number": 5, "issue_severity": "HIGH",
                                  "test_name": "hardcoded_sql", "issue_text": "SQL injection"}]
            }},
            "pylint": {},
        }
        result = validate_findings(verdict, static)
        ids = [c["tool_id"] for c in result["inline_comments"]]
        assert "B608" in ids
        assert "B999" not in ids

    def test_pylint_finding_validated(self):
        from src.reviewer.judge import validate_findings
        verdict = {
            "inline_comments": [
                {"path": "a.py", "line": 3, "body": "Undefined variable",
                 "source_tool": "pylint", "tool_id": "undefined-variable"},
            ]
        }
        static = {
            "bandit": {},
            "pylint": {"a.py": {
                "messages": [{"symbol": "undefined-variable", "type": "error", "line": 3, "message": "x"}]
            }},
        }
        result = validate_findings(verdict, static)
        assert len(result["inline_comments"]) == 1
