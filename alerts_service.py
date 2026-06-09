"""
Alerts Service — Send Slack and Email notifications for SSL certificate warnings/critical states.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
import requests

import config


def send_slack_alert(
    message: str,
    webhook_url: Optional[str] = None
) -> bool:
    """Send a text message to a Slack webhook."""
    url = webhook_url or config.SLACK_WEBHOOK_URL
    if not url:
        return False
    try:
        payload = {"text": message}
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        return True
    except Exception as exc:
        print(f"Error sending Slack alert: {exc}")
        return False


def send_email_alert(
    subject: str,
    body: str,
    smtp_config: Optional[Dict[str, str]] = None
) -> bool:
    """Send an email alert via SMTP."""
    cfg = smtp_config or {
        "server": config.SMTP_SERVER,
        "port": str(config.SMTP_PORT),
        "user": config.SMTP_USER,
        "password": config.SMTP_PASSWORD,
        "to": config.EMAIL_TO,
        "from": config.EMAIL_FROM,
    }

    server = cfg.get("server")
    port_str = cfg.get("port") or "587"
    user = cfg.get("user")
    password = cfg.get("password")
    to_email = cfg.get("to")
    from_email = cfg.get("from") or "ssl-watcher@localhost"

    if not (server and port_str and to_email):
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = from_email
        msg["To"] = to_email
        msg["Subject"] = subject

        msg.attach(MIMEText(body, "plain"))

        port = int(port_str)
        # Choose connection method based on common ports
        if port == 465:
            # SSL
            with smtplib.SMTP_SSL(server, port, timeout=10) as smtp:
                if user and password:
                    smtp.login(user, password)
                smtp.send_message(msg)
        else:
            # TLS (587, 25, etc.)
            with smtplib.SMTP(server, port, timeout=10) as smtp:
                smtp.ehlo()
                if port != 25:
                    smtp.starttls()
                    smtp.ehlo()
                if user and password:
                    smtp.login(user, password)
                smtp.send_message(msg)
        return True
    except Exception as exc:
        print(f"Error sending Email alert: {exc}")
        return False


def generate_digest_message(results: List[Dict[str, object]]) -> tuple[str, str, str]:
    """
    Filter results to create alert summaries.
    Returns: (slack_text, email_subject, email_body)
    """
    critical_alerts = []
    warning_alerts = []
    error_alerts = []

    for r in results:
        status = r.get("status")
        domain = r.get("domain")
        days = r.get("days_left")
        err = r.get("error")

        if status == "CRITICAL":
            days_str = f"{days} days left" if days is not None else "expired"
            critical_alerts.append(f"• *{domain}* ({days_str})")
        elif status == "WARNING":
            warning_alerts.append(f"• *{domain}* ({days} days left)")
        elif status == "ERROR":
            error_alerts.append(f"• *{domain}* (Error: {err})")

    if not (critical_alerts or warning_alerts or error_alerts):
        return "", "", ""

    # Slack Formatting
    slack_lines = ["🚨 *SSL Certificate Expiry Watcher Alert Summary* 🚨\n"]
    if critical_alerts:
        slack_lines.append("🔴 *CRITICAL STATUS (Expiry imminent or Expired):*")
        slack_lines.extend(critical_alerts)
        slack_lines.append("")
    if warning_alerts:
        slack_lines.append("🟡 *WARNING STATUS (Expiring soon):*")
        slack_lines.extend(warning_alerts)
        slack_lines.append("")
    if error_alerts:
        slack_lines.append("❌ *SCAN ERRORS (Verification or connection issues):*")
        slack_lines.extend(error_alerts)
        slack_lines.append("")
    slack_text = "\n".join(slack_lines)

    # Email Subject
    severities = []
    if critical_alerts:
        severities.append("CRITICAL")
    if warning_alerts:
        severities.append("WARNING")
    subj_status = "/".join(severities) if severities else "ERROR"
    subject = f"[{subj_status}] SSL Certificate Expiry Alert"

    # Email Body (Plain Text)
    email_lines = [
        "SSL Certificate Watcher Alert Summary",
        "=====================================\n"
    ]
    if critical_alerts:
        email_lines.append("CRITICAL STATUS (Expiry imminent or Expired):")
        email_lines.extend([line.replace("• *", "- ").replace("*", "") for line in critical_alerts])
        email_lines.append("")
    if warning_alerts:
        email_lines.append("WARNING STATUS (Expiring soon):")
        email_lines.extend([line.replace("• *", "- ").replace("*", "") for line in warning_alerts])
        email_lines.append("")
    if error_alerts:
        email_lines.append("SCAN ERRORS (Verification or connection issues):")
        email_lines.extend([line.replace("• *", "- ").replace("*", "") for line in error_alerts])
        email_lines.append("")
    email_lines.append("Please log into the dashboard to check the details and perform renewals.")
    email_body = "\n".join(email_lines)

    return slack_text, subject, email_body


def check_and_send_alerts(results: List[Dict[str, object]]) -> Dict[str, bool]:
    """
    Check scan results and dispatch alerts if warnings/critical statuses are present.
    Returns status of notifications.
    """
    slack_text, email_subj, email_body = generate_digest_message(results)
    if not slack_text:
        return {"slack": False, "email": False, "sent": False}

    slack_sent = False
    email_sent = False

    if config.SLACK_WEBHOOK_URL:
        slack_sent = send_slack_alert(slack_text)

    if config.SMTP_SERVER and config.EMAIL_TO:
        email_sent = send_email_alert(email_subj, email_body)

    return {
        "slack": slack_sent,
        "email": email_sent,
        "sent": slack_sent or email_sent
    }
