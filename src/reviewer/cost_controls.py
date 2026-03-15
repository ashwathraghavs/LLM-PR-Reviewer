"""
API cost controls: pre-flight estimation, spend tracking, rate limiting,
and anomaly detection.

The goal is that no individual PR, no individual repo, and no scripted
abuse pattern can run up an unexpected bill. Multiple layers enforce this
so a bug in any one layer doesn't expose the whole system.
"""

import os
import sqlite3
import time
from datetime import date, datetime, timedelta
from pathlib import Path

from .config import (
    MODEL,
    PRICING,
    MAX_COST_PER_REVIEW,
    MAX_INPUT_TOKENS,
    PER_REPO_DAILY_CAP,
    ORG_MONTHLY_CAP,
    COST_ALERT_THRESHOLD,
    RATE_BUCKET_CAPACITY,
    RATE_REFILL_PER_HOUR,
    DAILY_REVIEW_MAX,
    SPIKE_RATIO_THRESHOLD,
    SPIKE_MIN_ABSOLUTE,
    SPEND_DB_PATH,
    AUDIT_DB_PATH,
)
from .notifier import notify_slack


class PromptTooLargeError(Exception):
    pass

class BudgetExceededError(Exception):
    pass

class DailyCapExceededError(Exception):
    pass

class MonthlyCapExceededError(Exception):
    pass

class RateLimitExceededError(Exception):
    pass


# ── Database setup ─────────────────────────────────────────────────────────────

def _init_spend_db():
    conn = sqlite3.connect(SPEND_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS spend (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            repo         TEXT,
            pr_number    INTEGER,
            author       TEXT,
            timestamp    TEXT,
            input_tokens INTEGER,
            output_tokens INTEGER,
            cost_usd     REAL,
            model        TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rate_buckets (
            author       TEXT,
            repo         TEXT,
            tokens       REAL DEFAULT 5,
            last_refill  TEXT,
            PRIMARY KEY (author, repo)
        )
    """)
    conn.commit()
    conn.close()


def _init_audit_db():
    conn = sqlite3.connect(AUDIT_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            pr_number         INTEGER,
            author            TEXT,
            repo              TEXT,
            timestamp         TEXT,
            overall_score     INTEGER,
            decision          TEXT,
            injection_detected INTEGER,
            overrides_applied INTEGER,
            llm_raw_score     INTEGER
        )
    """)
    conn.commit()
    conn.close()


# ── Token and cost estimation ──────────────────────────────────────────────────

def estimate_tokens(text: str) -> int:
    """
    Heuristic: ~4 characters per token for English/code.
    Good enough for pre-flight checks — actual usage is recorded after the call.
    """
    return len(text) // 4


def preflight_cost_check(prompt: str) -> dict:
    input_tokens  = estimate_tokens(prompt)
    output_tokens = 1_500  # worst case, matches MAX_OUTPUT_TOKENS

    if input_tokens > MAX_INPUT_TOKENS:
        raise PromptTooLargeError(
            f"Prompt is ~{input_tokens} tokens — exceeds {MAX_INPUT_TOKENS} limit. "
            f"The diff will be truncated before the API call."
        )

    prices   = PRICING[MODEL]
    est_cost = (input_tokens * prices["input"]) + (output_tokens * prices["output"])

    if est_cost > MAX_COST_PER_REVIEW:
        raise BudgetExceededError(
            f"Estimated cost ${est_cost:.4f} exceeds per-review cap ${MAX_COST_PER_REVIEW}. "
            f"Diff must be reduced before calling the API."
        )

    return {
        "input_tokens": input_tokens,
        "est_cost_usd": round(est_cost, 5),
    }


def truncate_diff_to_budget(pr_files: list[dict], static: dict) -> list[dict]:
    """
    Truncate diff to fit within MAX_INPUT_TOKENS.
    Priority: lines near static analysis findings → other changed lines → context lines.
    """
    flagged = {}
    for filename, results in static.get("bandit", {}).items():
        flagged.setdefault(filename, set())
        for issue in results.get("raw_results", []):
            flagged[filename].add(issue.get("line_number", 0))
    for filename, results in static.get("pylint", {}).items():
        flagged.setdefault(filename, set())
        for msg in results.get("messages", []):
            flagged[filename].add(msg.get("line", 0))

    budget   = MAX_INPUT_TOKENS
    result   = []
    used     = 0

    for f in pr_files:
        patch = f.get("patch", "") or ""
        if not patch:
            continue

        file_flagged = flagged.get(f["filename"], set())
        lines        = patch.splitlines()

        priority, normal = [], []
        for i, line in enumerate(lines):
            line_num     = i + 1
            near_flagged = any(abs(line_num - fl) <= 3 for fl in file_flagged)
            if near_flagged or line.startswith(("+", "-")):
                priority.append(line)
            else:
                normal.append(line)

        selected = priority + normal
        cost     = estimate_tokens("\n".join(selected))
        if used + cost > budget:
            # Only take what fits
            chars_left = (budget - used) * 4
            joined     = "\n".join(selected)
            selected   = joined[:chars_left].splitlines()

        used += estimate_tokens("\n".join(selected))
        result.append({**f, "patch": "\n".join(selected), "truncated": True})

        if used >= budget:
            break

    return result


# ── Spend tracking ─────────────────────────────────────────────────────────────

def record_spend(repo: str, pr_number: int, author: str, usage: dict) -> float:
    _init_spend_db()
    prices = PRICING[MODEL]
    cost   = (
        usage.get("input_tokens", 0)  * prices["input"] +
        usage.get("output_tokens", 0) * prices["output"]
    )
    conn = sqlite3.connect(SPEND_DB_PATH)
    conn.execute(
        "INSERT INTO spend VALUES (NULL,?,?,?,?,?,?,?,?)",
        (repo, pr_number, author, datetime.utcnow().isoformat(),
         usage.get("input_tokens", 0), usage.get("output_tokens", 0), cost, MODEL)
    )
    conn.commit()
    conn.close()
    return cost


def check_repo_daily_cap(repo: str) -> dict:
    _init_spend_db()
    today = date.today().isoformat()
    conn  = sqlite3.connect(SPEND_DB_PATH)
    spent = conn.execute(
        "SELECT COALESCE(SUM(cost_usd),0) FROM spend WHERE repo=? AND timestamp LIKE ?",
        (repo, f"{today}%")
    ).fetchone()[0]
    conn.close()

    if spent >= PER_REPO_DAILY_CAP:
        raise DailyCapExceededError(
            f"Repo `{repo}` has spent ${spent:.2f} today — "
            f"daily cap ${PER_REPO_DAILY_CAP:.2f} reached. "
            f"LLM review disabled until midnight UTC."
        )

    pct = spent / PER_REPO_DAILY_CAP
    if pct >= COST_ALERT_THRESHOLD:
        notify_slack(
            f"Cost alert: `{repo}` is at {pct*100:.0f}% of daily cap "
            f"(${spent:.2f} / ${PER_REPO_DAILY_CAP:.2f})"
        )

    return {"spent_today": spent, "remaining": PER_REPO_DAILY_CAP - spent}


def check_org_monthly_cap() -> dict:
    _init_spend_db()
    month = datetime.utcnow().strftime("%Y-%m")
    conn  = sqlite3.connect(SPEND_DB_PATH)
    spent = conn.execute(
        "SELECT COALESCE(SUM(cost_usd),0) FROM spend WHERE timestamp LIKE ?",
        (f"{month}%",)
    ).fetchone()[0]
    conn.close()

    if spent >= ORG_MONTHLY_CAP:
        raise MonthlyCapExceededError(
            f"Org has spent ${spent:.2f} this month — "
            f"monthly cap ${ORG_MONTHLY_CAP:.2f} reached. "
            f"All LLM reviews are suspended."
        )

    pct = spent / ORG_MONTHLY_CAP
    if pct >= COST_ALERT_THRESHOLD:
        notify_slack(
            f"Monthly spend alert: org is at {pct*100:.0f}% of monthly cap "
            f"(${spent:.2f} / ${ORG_MONTHLY_CAP:.2f})"
        )

    return {"spent_this_month": spent}


# ── Rate limiting ──────────────────────────────────────────────────────────────

def check_rate_limit(author: str, repo: str) -> dict:
    _init_spend_db()
    conn = sqlite3.connect(SPEND_DB_PATH)
    row  = conn.execute(
        "SELECT tokens, last_refill FROM rate_buckets WHERE author=? AND repo=?",
        (author, repo)
    ).fetchone()

    now         = time.time()
    tokens      = row[0] if row else float(RATE_BUCKET_CAPACITY)
    last_refill = float(row[1]) if row else now

    elapsed = (now - last_refill) / 3600
    tokens  = min(float(RATE_BUCKET_CAPACITY), tokens + elapsed * RATE_REFILL_PER_HOUR)

    if tokens < 1:
        wait_secs = int((1 - tokens) / RATE_REFILL_PER_HOUR * 3600)
        conn.close()
        raise RateLimitExceededError(
            f"@{author} has exceeded the review rate limit. "
            f"Please wait {wait_secs // 60} minutes before opening another PR for review."
        )

    today       = date.today().isoformat()
    daily_count = conn.execute(
        "SELECT COUNT(*) FROM spend WHERE author=? AND repo=? AND timestamp LIKE ?",
        (author, repo, f"{today}%")
    ).fetchone()[0]

    if daily_count >= DAILY_REVIEW_MAX:
        conn.close()
        raise RateLimitExceededError(
            f"@{author} has reached the daily review limit ({DAILY_REVIEW_MAX} reviews/day). "
            f"Resets at midnight UTC."
        )

    conn.execute("""
        INSERT INTO rate_buckets (author, repo, tokens, last_refill)
        VALUES (?,?,?,?)
        ON CONFLICT(author,repo) DO UPDATE SET tokens=excluded.tokens, last_refill=excluded.last_refill
    """, (author, repo, tokens - 1, str(now)))
    conn.commit()
    conn.close()

    return {"tokens_remaining": tokens - 1, "daily_count": daily_count + 1}


# ── Anomaly detection ──────────────────────────────────────────────────────────

def detect_spend_anomaly(repo: str) -> dict:
    _init_spend_db()
    today = date.today().isoformat()
    conn  = sqlite3.connect(SPEND_DB_PATH)

    today_spend = conn.execute(
        "SELECT COALESCE(SUM(cost_usd),0) FROM spend WHERE repo=? AND timestamp LIKE ?",
        (repo, f"{today}%")
    ).fetchone()[0]

    avg_row = conn.execute("""
        SELECT COALESCE(AVG(daily_total), 0) FROM (
            SELECT DATE(timestamp) as day, SUM(cost_usd) as daily_total
            FROM spend
            WHERE repo=? AND DATE(timestamp) < DATE('now')
            GROUP BY day ORDER BY day DESC LIMIT 7
        )
    """, (repo,)).fetchone()
    conn.close()

    avg_daily   = avg_row[0] or 0.01
    spike_ratio = today_spend / avg_daily

    if spike_ratio > SPIKE_RATIO_THRESHOLD and today_spend > SPIKE_MIN_ABSOLUTE:
        notify_slack(
            f"Spend spike on `{repo}`: ${today_spend:.2f} today vs "
            f"${avg_daily:.2f} 7-day avg ({spike_ratio:.1f}x). "
            f"LLM reviews paused pending investigation."
        )
        return {"anomaly": True, "spike_ratio": spike_ratio, "today": today_spend}

    return {"anomaly": False, "today": today_spend, "avg": avg_daily}


# ── Audit logging ──────────────────────────────────────────────────────────────

def log_review_event(
    pr_number: int,
    author: str,
    repo: str,
    verdict: dict,
) -> None:
    _init_audit_db()
    overrides = verdict.get("deterministic_overrides", [])
    conn = sqlite3.connect(AUDIT_DB_PATH)
    conn.execute(
        "INSERT INTO reviews VALUES (NULL,?,?,?,?,?,?,?,?,?)",
        (
            pr_number,
            author,
            repo,
            datetime.utcnow().isoformat(),
            verdict.get("overall_score", 0),
            verdict.get("decision", "COMMENT"),
            int(verdict.get("injection_detected", False)),
            len(overrides),
            verdict.get("llm_raw_score", verdict.get("overall_score", 0)),
        ),
    )
    conn.commit()
    conn.close()


def detect_probing_behavior(author: str, repo: str) -> dict:
    """
    Flag authors who appear to be systematically probing the judge.
    High PR volume + injection attempts or high score variance = suspicious.
    """
    _init_audit_db()
    since = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    conn  = sqlite3.connect(AUDIT_DB_PATH)
    rows  = conn.execute("""
        SELECT overall_score, injection_detected, overrides_applied
        FROM reviews
        WHERE author=? AND repo=? AND timestamp > ?
        ORDER BY timestamp DESC
    """, (author, repo, since)).fetchall()
    conn.close()

    if len(rows) < 3:
        return {"suspicious": False}

    scores     = [r[0] for r in rows]
    injections = sum(1 for r in rows if r[1])
    score_range = max(scores) - min(scores)
    suspicious  = injections > 0 or (len(rows) > 5 and score_range > 40)

    return {
        "suspicious":         suspicious,
        "pr_count_24h":       len(rows),
        "injection_attempts": injections,
        "score_variance":     score_range,
        "recommendation":     "FLAG_FOR_SECURITY_REVIEW" if suspicious else "OK",
    }
