"""
Deterministic static analysis runners.
These are the ground truth layer — the LLM explains what these tools find,
it does not discover findings independently.
"""

import json
import subprocess
import tempfile
from pathlib import Path

from . import github_client


def run_pylint(path: str) -> dict:
    result = subprocess.run(
        ["pylint", "--output-format=json", "--score=no", path],
        capture_output=True, text=True,
    )
    try:
        messages = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        messages = []

    errors   = [m for m in messages if m.get("type") in ("error", "fatal")]
    warnings = [m for m in messages if m.get("type") == "warning"]
    return {
        "error_count":   len(errors),
        "warning_count": len(warnings),
        "messages":      messages,
        "top": [
            f"[{m['type'].upper()}] {m['symbol']} L{m['line']}: {m['message']}"
            for m in (errors + warnings)[:6]
        ],
    }


def run_bandit(path: str) -> dict:
    result = subprocess.run(
        ["bandit", "-f", "json", "-q", path],
        capture_output=True, text=True,
    )
    try:
        data = json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        data = {}

    issues  = data.get("results", [])
    high    = [i for i in issues if i.get("issue_severity") == "HIGH"]
    medium  = [i for i in issues if i.get("issue_severity") == "MEDIUM"]
    return {
        "high_count":   len(high),
        "medium_count": len(medium),
        "raw_results":  issues,
        "top": [
            f"[{i['issue_severity']}] {i['test_name']} ({i['test_id']}) "
            f"L{i['line_number']}: {i['issue_text']}"
            for i in (high + medium)[:5]
        ],
    }


def run_safety() -> dict:
    req = Path("requirements.txt")
    if not req.exists():
        return {"status": "no requirements.txt found", "vulnerabilities": []}

    result = subprocess.run(
        ["safety", "check", "-r", str(req), "--json"],
        capture_output=True, text=True,
    )
    try:
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        return {
            "status": "ok",
            "vulnerabilities": data.get("vulnerabilities", []),
        }
    except json.JSONDecodeError:
        return {"status": "parse_error", "raw": result.stdout[:500], "vulnerabilities": []}


def run_static_analysis(pr_files: list[dict]) -> dict:
    pylint_results = {}
    bandit_results = {}

    with tempfile.TemporaryDirectory() as tmp:
        for f in pr_files:
            if not f["filename"].endswith(".py") or f["status"] == "removed":
                continue
            content = github_client.fetch_raw(f["raw_url"])
            fp      = Path(tmp) / Path(f["filename"]).name
            fp.write_text(content)
            pylint_results[f["filename"]] = run_pylint(str(fp))
            bandit_results[f["filename"]] = run_bandit(str(fp))

    return {
        "pylint": pylint_results,
        "bandit": bandit_results,
        "safety": run_safety(),
    }
