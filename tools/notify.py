"""Outbound notifications (Slack / Telegram) for alerts and reports.

Webhook URLs and bot tokens are read from the environment — never from config
or the command line — and are redacted from logs. Delivery failures are
returned as a failed :class:`OperationResult` rather than raised, so a flaky
notifier never breaks the operation it was reporting on.
"""

from __future__ import annotations

from core.base import OperationResult, timed
from utils.exceptions import DependencyError
from utils.logging_config import get_logger
from utils.security import get_secret

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore[assignment]

_log = get_logger("notify")


def _require_requests() -> None:
    if requests is None:  # pragma: no cover
        raise DependencyError("notifications require 'requests' (pip install requests)")


def send_slack(message: str, *, webhook_env: str = "SLACK_WEBHOOK_URL") -> OperationResult:
    """Post *message* to a Slack incoming webhook named by *webhook_env*."""
    with timed("notify", "slack") as result:
        _require_requests()
        url = get_secret(webhook_env)
        if not url:
            result.status = result.status.SKIPPED
            result.finalize(f"{webhook_env} not set — Slack notification skipped")
            return result
        response = requests.post(url, json={"text": message}, timeout=10)
        result.data = {"status_code": response.status_code}
        if response.status_code >= 300:
            result.fail(f"Slack webhook returned {response.status_code}")
        else:
            result.finalize("Slack notification sent")
    return result


def send_telegram(
    message: str,
    *,
    token_env: str = "TELEGRAM_BOT_TOKEN",
    chat_id_env: str = "TELEGRAM_CHAT_ID",
) -> OperationResult:
    """Send *message* via the Telegram Bot API using env-provided credentials."""
    with timed("notify", "telegram") as result:
        _require_requests()
        token = get_secret(token_env)
        chat_id = get_secret(chat_id_env)
        if not token or not chat_id:
            result.status = result.status.SKIPPED
            result.finalize("Telegram credentials not set — skipped")
            return result
        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": message},
            timeout=10,
        )
        result.data = {"status_code": response.status_code}
        if response.status_code >= 300:
            result.fail(f"Telegram API returned {response.status_code}")
        else:
            result.finalize("Telegram notification sent")
    return result
