"""
Repository context assembler.

The LLM only sees the diff by default, which means it has no idea
that payment_processor.py is called by 40 services, or that this
file had a security incident six months ago. This module fetches
the context that turns generic advice into actionable review.
"""

import subprocess
import yaml
from pathlib import Path

from . import github_client
from .config import (
    RISK_REGISTRY_PATH,
    CONTRIBUTING_MD_PATH,
    CODEOWNERS_PATH,
    INCIDENT_LOG_PATH,
)


def build_repo_context(pr_files: list[dict], repo_root: str = ".") -> dict:
    context = {}

    for f in pr_files:
        filename = f["filename"]
        if not filename.endswith(".py"):
            continue

        ctx = {}

        # Who imports this module? (basic dependency graph)
        stem   = Path(filename).stem
        result = subprocess.run(
            ["grep", "-rn", f"import {stem}", repo_root, "--include=*.py"],
            capture_output=True, text=True,
        )
        callers = [line.split(":")[0] for line in result.stdout.splitlines()[:5]]
        ctx["imported_by"] = callers

        # Recent git history for this file
        log = subprocess.run(
            ["git", "log", "--oneline", "-10", "--", filename],
            capture_output=True, text=True,
            cwd=repo_root,
        )
        ctx["recent_commits"] = log.stdout.strip().splitlines()

        # Corresponding test file
        test_candidates = [
            filename.replace("src/", "tests/").replace(".py", "_test.py"),
            filename.replace("src/", "tests/test_"),
            f"tests/test_{Path(filename).name}",
        ]
        ctx["test_file_exists"] = False
        for candidate in test_candidates:
            tp = Path(repo_root, candidate)
            if tp.exists():
                ctx["test_file_exists"] = True
                ctx["test_file_path"]   = candidate
                ctx["test_file"]        = tp.read_text()[:2000]
                break

        # Package-level README or docstring
        readme = Path(repo_root, Path(filename).parent, "README.md")
        if readme.exists():
            ctx["module_readme"] = readme.read_text()[:1000]

        context[filename] = ctx

    return context


def build_business_context(pr_metadata: dict, repo_root: str = ".") -> str:
    parts = []

    # Developer's own framing of the change
    if pr_metadata.get("body"):
        parts.append(f"## Developer intent\n{pr_metadata['body'][:1000]}")

    # File risk registry — maintains per-file risk metadata and notes
    registry_path = Path(repo_root, RISK_REGISTRY_PATH)
    if registry_path.exists():
        registry = yaml.safe_load(registry_path.read_text()) or {}
        relevant = {
            prefix: meta
            for prefix, meta in registry.items()
            if any(f["filename"].startswith(prefix) for f in pr_metadata.get("files", []))
        }
        if relevant:
            parts.append(f"## File risk metadata\n{yaml.dump(relevant)}")

    # Past incidents on changed files
    incident_path = Path(repo_root, INCIDENT_LOG_PATH)
    if incident_path.exists():
        log_text = incident_path.read_text()
        for f in pr_metadata.get("files", []):
            fname = Path(f["filename"]).name
            if fname in log_text:
                start   = log_text.index(fname)
                excerpt = log_text[start:start + 500]
                parts.append(f"## Past incidents involving {fname}\n{excerpt}")

    return "\n\n".join(parts)


def load_org_context(repo_root: str = ".") -> str:
    parts = []

    contributing = Path(repo_root, CONTRIBUTING_MD_PATH)
    if contributing.exists():
        parts.append(f"## Team coding standards\n{contributing.read_text()[:2000]}")

    codeowners = Path(repo_root, CODEOWNERS_PATH)
    if codeowners.exists():
        parts.append(f"## CODEOWNERS\n{codeowners.read_text()[:500]}")

    return "\n\n".join(parts)


def format_context_for_prompt(repo_ctx: dict, biz_ctx: str, org_ctx: str) -> str:
    sections = []

    if org_ctx:
        sections.append(org_ctx)

    if biz_ctx:
        sections.append(biz_ctx)

    for filename, ctx in repo_ctx.items():
        lines = [f"### Context for `{filename}`"]
        if ctx.get("imported_by"):
            lines.append(f"Imported by: {', '.join(ctx['imported_by'])}")
        if ctx.get("recent_commits"):
            lines.append("Recent git history:\n" + "\n".join(ctx["recent_commits"]))
        if not ctx.get("test_file_exists"):
            lines.append("WARNING: No test file found for this module.")
        elif ctx.get("test_file"):
            lines.append(f"Test file ({ctx['test_file_path']}):\n```python\n{ctx['test_file']}\n```")
        if ctx.get("module_readme"):
            lines.append(f"Module documentation:\n{ctx['module_readme']}")
        sections.append("\n".join(lines))

    return "\n\n".join(sections)
