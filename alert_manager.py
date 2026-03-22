"""
alert_manager.py
----------------
Fires alerts via:
  1. Email  (SMTP / TLS)
  2. Webhook (generic HTTP POST with JSON payload)

Both channels are retried on failure.
"""

import json
import logging
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List

import requests

logger = logging.getLogger(__name__)


class AlertManager:
    """Dispatches alerts through email and/or webhook channels."""

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self._trigger_levels: List[str] = [
            lv.upper() for lv in cfg.get("trigger_on_levels", ["ERROR", "CRITICAL", "FATAL"])
        ]
        self._suspicious_keywords: List[str] = [
            kw.lower() for kw in cfg.get("suspicious_keywords", [])
        ]

        email_cfg = cfg.get("email", {})
        self._email_enabled: bool = email_cfg.get("enabled", False)
        self._smtp_host: str = email_cfg.get("smtp_host", "")
        self._smtp_port: int = int(email_cfg.get("smtp_port", 587))
        self._use_tls: bool = email_cfg.get("use_tls", True)
        self._sender: str = email_cfg.get("sender", "")
        self._smtp_password: str = email_cfg.get("password", "")
        self._recipients: List[str] = email_cfg.get("recipients", [])
        self._subject_prefix: str = email_cfg.get("subject_prefix", "[LOG-ALERT]")

        webhook_cfg = cfg.get("webhook", {})
        self._webhook_enabled: bool = webhook_cfg.get("enabled", False)
        self._webhook_url: str = webhook_cfg.get("url", "")
        self._webhook_headers: Dict[str, str] = webhook_cfg.get("headers", {})
        self._webhook_timeout: int = int(webhook_cfg.get("timeout_seconds", 10))
        self._webhook_max_retries: int = int(webhook_cfg.get("max_retries", 3))
        self._webhook_retry_delay: int = int(webhook_cfg.get("retry_delay_seconds", 5))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def should_alert(self, log_event: Dict[str, Any], analysis: Dict[str, Any]) -> bool:
        """Return True if this event warrants an alert."""
        level = log_event.get("level", "").upper()
        if level in self._trigger_levels:
            return True

        # Also check analysis severity
        severity = analysis.get("severity", "").upper()
        if severity in self._trigger_levels:
            return True

        # Check for suspicious keywords in the raw message
        message = (log_event.get("message") or log_event.get("raw") or "").lower()
        if any(kw in message for kw in self._suspicious_keywords):
            return True

        return False

    def fire(
        self,
        log_event: Dict[str, Any],
        analysis: Dict[str, Any],
        case_id: int,
    ) -> Dict[str, str]:
        """
        Send alerts to all configured channels.
        Returns a dict mapping channel name → 'sent' | 'failed'.
        """
        results: Dict[str, str] = {}
        payload = self._build_payload(log_event, analysis, case_id)

        if self._email_enabled:
            results["email"] = self._send_email(payload)

        if self._webhook_enabled:
            results["webhook"] = self._send_webhook(payload)

        return results

    # ------------------------------------------------------------------
    # Payload builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_payload(
        log_event: Dict[str, Any],
        analysis: Dict[str, Any],
        case_id: int,
    ) -> Dict[str, Any]:
        return {
            "case_id": case_id,
            "log_time": log_event.get("_time", ""),
            "log_level": log_event.get("level", ""),
            "log_source": log_event.get("source", ""),
            "log_host": log_event.get("host", ""),
            "message_snippet": (log_event.get("message") or "")[:500],
            "severity": analysis.get("severity", ""),
            "summary": analysis.get("summary", ""),
            "root_cause": analysis.get("root_cause", ""),
            "solution": analysis.get("solution", ""),
            "related_components": analysis.get("related_components", []),
            "confidence": analysis.get("confidence", 0.0),
        }

    # ------------------------------------------------------------------
    # Email channel
    # ------------------------------------------------------------------

    def _send_email(self, payload: Dict[str, Any]) -> str:
        subject = (
            f"{self._subject_prefix} [{payload['severity']}] {payload['summary'][:80]}"
        )
        body = self._render_email_body(payload)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self._sender
        msg["To"] = ", ".join(self._recipients)
        msg.attach(MIMEText(body, "plain"))

        try:
            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=15) as server:
                if self._use_tls:
                    server.starttls()
                server.login(self._sender, self._smtp_password)
                server.sendmail(self._sender, self._recipients, msg.as_string())
            logger.info("Alert email sent for case_id=%d", payload["case_id"])
            return "sent"
        except Exception as exc:
            logger.error("Failed to send alert email: %s", exc)
            return "failed"

    @staticmethod
    def _render_email_body(p: Dict[str, Any]) -> str:
        comps = ", ".join(p["related_components"]) or "N/A"
        return f"""\
🚨 LOG ANALYSIS ALERT
=====================
Case ID      : {p['case_id']}
Log Time     : {p['log_time']}
Level        : {p['log_level']}
Source       : {p['log_source']}
Host         : {p['log_host']}
Severity     : {p['severity']}
Confidence   : {p['confidence']:.0%}

SUMMARY
-------
{p['summary']}

ROOT CAUSE
----------
{p['root_cause']}

SOLUTION
--------
{p['solution']}

Related Components: {comps}

MESSAGE SNIPPET
---------------
{p['message_snippet']}
"""

    # ------------------------------------------------------------------
    # Webhook channel
    # ------------------------------------------------------------------

    def _send_webhook(self, payload: Dict[str, Any]) -> str:
        for attempt in range(1, self._webhook_max_retries + 1):
            try:
                resp = requests.post(
                    self._webhook_url,
                    headers=self._webhook_headers,
                    json=payload,
                    timeout=self._webhook_timeout,
                )
                if resp.ok:
                    logger.info(
                        "Webhook alert sent for case_id=%d (HTTP %d)",
                        payload["case_id"],
                        resp.status_code,
                    )
                    return "sent"
                logger.warning(
                    "Webhook responded with HTTP %d on attempt %d: %s",
                    resp.status_code, attempt, resp.text[:200],
                )
            except requests.RequestException as exc:
                logger.warning("Webhook attempt %d failed: %s", attempt, exc)

            if attempt < self._webhook_max_retries:
                time.sleep(self._webhook_retry_delay)

        logger.error(
            "All %d webhook attempts failed for case_id=%d",
            self._webhook_max_retries,
            payload["case_id"],
        )
        return "failed"
