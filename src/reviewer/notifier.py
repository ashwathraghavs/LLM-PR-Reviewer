"""
Slack notification helper.
Set the SLACK_WEBHOOK_URL environment variable to enable alerts.
If the variable is not set, notifications are silently skipped — the
system degrades gracefully without a Slack integration.
"""

import os
import httpx


def notify_slack(message: str, channel: str = "#ci-cost-alerts") -> None:
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook:
        print(f"[Slack not configured] {message}")
        return

    try:
        httpx.post(
            webhook,
            json={
                "channel": channel,
                "text":    f":moneybag: *LLM PR Reviewer*\n{message}",
            },
            timeout=5,
        )
    except Exception as e:
        # Never let a Slack failure break the review pipeline
        print(f"Slack notification failed: {e}")


def notify_security(message: str) -> None:
    notify_slack(message, channel="#security-alerts")
