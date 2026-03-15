"""
GitHub REST API v3 client.
All GitHub interactions go through this module — keeping API calls
in one place makes it straightforward to mock in tests and swap for
a GitHub App token if you move to Option B deployment.
"""

import os
import httpx


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _repo() -> str:
    return os.environ["GITHUB_REPOSITORY"]


def _pr() -> int:
    return int(os.environ["PR_NUMBER"])


def fetch_pr_files() -> list[dict]:
    url  = f"https://api.github.com/repos/{_repo()}/pulls/{_pr()}/files"
    resp = httpx.get(url, headers=_headers())
    resp.raise_for_status()
    return resp.json()


def fetch_pr_metadata() -> dict:
    url  = f"https://api.github.com/repos/{_repo()}/pulls/{_pr()}"
    resp = httpx.get(url, headers=_headers())
    resp.raise_for_status()
    data = resp.json()
    return {
        "title":  data.get("title", ""),
        "body":   data.get("body", ""),
        "author": data.get("user", {}).get("login", "unknown"),
        "base":   data.get("base", {}).get("ref", "main"),
    }


def fetch_raw(raw_url: str) -> str:
    resp = httpx.get(raw_url, headers=_headers())
    resp.raise_for_status()
    return resp.text


def post_review(decision: str, summary: str, inline_comments: list[dict]) -> None:
    """
    decision: "APPROVE" | "REQUEST_CHANGES" | "COMMENT"
    inline_comments: [{"path": str, "line": int, "body": str}]

    If inline comments have bad line numbers the API rejects the whole review,
    so we retry without comments on failure rather than losing the summary.
    """
    url     = f"https://api.github.com/repos/{_repo()}/pulls/{_pr()}/reviews"
    payload = {
        "body":  summary,
        "event": decision,
        "comments": [
            {
                "path": c["path"],
                "line": c["line"],
                "body": c["body"],
                "side": "RIGHT",
            }
            for c in inline_comments
            if c.get("line", 0) > 0
        ],
    }
    resp = httpx.post(url, headers=_headers(), json=payload)
    if not resp.is_success:
        payload["comments"] = []
        resp = httpx.post(url, headers=_headers(), json=payload)
    resp.raise_for_status()


def post_pr_comment(body: str) -> None:
    """Post a plain issue comment (not a review) — used for rate limit and budget notices."""
    url  = f"https://api.github.com/repos/{_repo()}/issues/{_pr()}/comments"
    resp = httpx.post(url, headers=_headers(), json={"body": body})
    resp.raise_for_status()
