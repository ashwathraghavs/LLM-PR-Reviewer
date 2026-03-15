"""
Output integrity validation.

Canary token checks, score anomaly detection, and decision/score
consistency checks. Runs after the LLM responds, before the verdict
is acted on.
"""

import json
import re


def validate_output_integrity(raw_output: str, canary: str, static_results: dict) -> dict:
    issues = []
    verdict = {}

    # ── Canary leak ────────────────────────────────────────────────────────────
    if canary in raw_output:
        issues.append(
            "CRITICAL: canary token leaked into output — "
            "prompt context may have been accessed by the reviewed code"
        )

    # ── Parse and validate JSON structure ─────────────────────────────────────
    try:
        json_match = re.search(r"\{[^{}]*\"overall_score\"[^{}]*\}", raw_output, re.DOTALL)
        if json_match:
            verdict = json.loads(json_match.group(0))
    except json.JSONDecodeError:
        issues.append("Malformed JSON in verdict — possible output injection")

    # ── Score bounds ───────────────────────────────────────────────────────────
    for key in ["security_score", "quality_score", "test_score", "overall_score"]:
        val = verdict.get(key)
        if val is not None:
            if not isinstance(val, (int, float)) or not (0 <= val <= 100):
                issues.append(f"Score out of valid range: {key}={val}")

    # ── Score/findings consistency ─────────────────────────────────────────────
    overall = verdict.get("overall_score", 0)
    total_high_bandit = sum(
        r.get("high_count", 0)
        for r in static_results.get("bandit", {}).values()
    )
    if overall > 90 and total_high_bandit > 0:
        issues.append(
            f"Score anomaly: overall_score={overall} but bandit found "
            f"{total_high_bandit} HIGH severity finding(s)"
        )

    # ── Decision/score mismatch ────────────────────────────────────────────────
    decision = verdict.get("decision", "")
    if decision == "APPROVE" and overall < 70:
        issues.append(
            f"Decision/score mismatch: decision=APPROVE but overall_score={overall}"
        )

    return {
        "clean":   len(issues) == 0,
        "issues":  issues,
        "verdict": verdict,
    }


def apply_deterministic_overrides(
    verdict: dict,
    static_results: dict,
    injection_scan: dict,
) -> dict:
    """
    The LLM is advisory. These rules are absolute.

    A successfully manipulated LLM still hits this wall.
    Tools always have the final word on blockers.
    """
    overrides = []

    # ── Injection detected → immediate block ──────────────────────────────────
    if injection_scan.get("injection_risk") or verdict.get("injection_detected"):
        high_findings = [
            f for f in injection_scan.get("findings", [])
            if f["severity"] == "HIGH"
        ]
        return {
            "overall_score":  0,
            "security_score": 0,
            "quality_score":  verdict.get("quality_score", 50),
            "test_score":     verdict.get("test_score", 50),
            "decision":       "REQUEST_CHANGES",
            "confidence":     "HIGH",
            "summary": (
                "**PR blocked: prompt injection patterns detected in diff.**\n\n"
                "This PR has been flagged for security review. The findings below "
                "indicate content in the diff that attempted to manipulate the "
                "automated review system.\n\n"
                + "\n".join(
                    f"- `{f['file']}`: {f.get('label', f['type'])}"
                    for f in high_findings[:3]
                )
            ),
            "inline_comments":          [],
            "deterministic_overrides":  ["INJECTION_DETECTED"],
        }

    # ── HIGH bandit finding → security_score capped + force block ─────────────
    total_high = sum(
        r.get("high_count", 0)
        for r in static_results.get("bandit", {}).values()
    )
    if total_high > 0:
        if verdict.get("security_score", 0) > 40:
            overrides.append(
                f"security_score capped at 40 — {total_high} HIGH bandit finding(s) present"
            )
            verdict["security_score"] = 40
        overrides.append("REQUEST_CHANGES forced — HIGH severity security finding")

    # ── Known CVEs → block unconditionally ────────────────────────────────────
    cves = static_results.get("safety", {}).get("vulnerabilities", [])
    if cves:
        overrides.append(f"Blocked — {len(cves)} known CVE(s) in dependencies")

    # ── Pylint errors → quality_score capped ──────────────────────────────────
    total_errors = sum(
        r.get("error_count", 0)
        for r in static_results.get("pylint", {}).values()
    )
    if total_errors > 3 and verdict.get("quality_score", 0) > 50:
        overrides.append(
            f"quality_score capped at 50 — {total_errors} pylint error(s)"
        )
        verdict["quality_score"] = 50

    # ── Recompute overall from possibly-clamped scores ─────────────────────────
    from .config import SECURITY_WEIGHT, QUALITY_WEIGHT, TEST_WEIGHT, APPROVAL_THRESHOLD, BLOCK_THRESHOLD
    verdict["overall_score"] = round(
        verdict.get("security_score", 50) * SECURITY_WEIGHT +
        verdict.get("quality_score",  50) * QUALITY_WEIGHT  +
        verdict.get("test_score",     50) * TEST_WEIGHT
    )

    # ── Re-derive decision ─────────────────────────────────────────────────────
    score = verdict["overall_score"]
    conf  = verdict.get("confidence", "MEDIUM")

    if overrides or score < BLOCK_THRESHOLD:
        verdict["decision"] = "REQUEST_CHANGES"
    elif score >= APPROVAL_THRESHOLD and conf in ("HIGH", "MEDIUM"):
        verdict["decision"] = "APPROVE"
    else:
        verdict["decision"] = "COMMENT"

    if overrides:
        verdict["deterministic_overrides"] = overrides
        verdict["summary"] = (
            "**Deterministic overrides applied — these findings are non-negotiable:**\n"
            + "\n".join(f"- {o}" for o in overrides)
            + "\n\n---\n\n"
            + verdict.get("summary", "")
        )

    return verdict
