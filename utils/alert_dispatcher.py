"""
ThreatPulse — Multi-Channel Alert Dispatcher
Modular alerting system: WhatsApp, Telegram, Email, Slack, Webhook.
Add channels by implementing the channel functions and enabling via .env.

KEY FIX: All env vars are re-read on every dispatch_alert() call via load_dotenv(override=True)
so that credentials added after startup (e.g. TELEGRAM_CHAT_ID) take effect immediately
without restarting the services.
"""
import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENV_PATH    = os.path.join(PROJECT_ROOT, '.env')

# Initial load at import time
load_dotenv(_ENV_PATH, override=True)


def _reload_env():
    """Re-read .env on every alert dispatch so new credentials take effect immediately."""
    load_dotenv(_ENV_PATH, override=True)


# ── Severity helper ───────────────────────────────────────────────────────────
def _get_severity(risk_score: float) -> str:
    if risk_score >= 80: return 'CRITICAL'
    if risk_score >= 60: return 'HIGH'
    if risk_score >= 40: return 'MEDIUM'
    return 'LOW'


# ── Channel: Telegram ─────────────────────────────────────────────────────────
def _send_telegram(event: dict, incident_id: int, response_actions: str = '') -> bool:
    try:
        from utils.telegram_alerter import send_alert as tg_send
        return tg_send(event, incident_id, response_actions)
    except Exception as e:
        print(f"❌ Telegram channel error: {e}")
        return False


# ── Channel: WhatsApp (Twilio) ────────────────────────────────────────────────
def _send_whatsapp(event: dict, incident_id: int, response_actions: str = '') -> bool:
    try:
        from utils.alerting import trigger_whatsapp_alert
        return trigger_whatsapp_alert(event, incident_id) is not None
    except Exception as e:
        print(f"❌ WhatsApp channel error: {e}")
        return False


# ── Channel: Email (SMTP) ─────────────────────────────────────────────────────
def _send_email(event: dict, incident_id: int, response_actions: str = '') -> bool:
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    email_to  = os.getenv("EMAIL_TO", "")
    if not smtp_user or not smtp_pass or not email_to:
        print("⚠️  Email: SMTP credentials not configured. Skipping.")
        return False
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        email_from = os.getenv("EMAIL_FROM", "") or smtp_user
        risk = float(event.get('risk_score', 0))
        severity = _get_severity(risk)
        subject = f"[{severity}] ThreatPulse Alert — INC-{str(incident_id).zfill(4)}"
        html_body = f"""
        <html><body style="font-family: monospace; background: #030609; color: #00e5b0; padding: 24px;">
        <h2 style="color: #f03250;">🚨 ThreatPulse Security Alert</h2>
        <table style="border-collapse: collapse; width: 100%;">
            <tr><td style="padding: 6px; color: #2e5570;">Severity</td><td style="color: {'#f03250' if severity == 'CRITICAL' else '#ffb800'}">{severity}</td></tr>
            <tr><td style="padding: 6px; color: #2e5570;">Threat Type</td><td>{event.get('attack_type', 'unknown').replace('_',' ').title()}</td></tr>
            <tr><td style="padding: 6px; color: #2e5570;">User</td><td>{event.get('user', 'N/A')}</td></tr>
            <tr><td style="padding: 6px; color: #2e5570;">Source IP</td><td>{event.get('ip', 'N/A')}</td></tr>
            <tr><td style="padding: 6px; color: #2e5570;">Risk Score</td><td>{risk:.0f}/100</td></tr>
            <tr><td style="padding: 6px; color: #2e5570;">Incident ID</td><td>INC-{str(incident_id).zfill(4)}</td></tr>
        </table>
        <p style="margin-top: 16px; color: #6e9ab5;">{event.get('explanation', '')}</p>
        <p style="color: #2e5570;">ThreatPulse • {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
        </body></html>
        """
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = email_from
        msg['To']      = email_to
        msg.attach(MIMEText(html_body, 'html'))
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, email_to, msg.as_string())
        print(f"✅ Email Alert sent to {email_to} — INC-{str(incident_id).zfill(4)}")
        return True
    except Exception as e:
        print(f"❌ Email send failed: {e}")
        return False


# ── Channel: Slack ────────────────────────────────────────────────────────────
def _send_slack(event: dict, incident_id: int, response_actions: str = '') -> bool:
    slack_url = os.getenv("SLACK_WEBHOOK_URL", "")
    if not slack_url:
        print("⚠️  Slack: SLACK_WEBHOOK_URL not configured. Skipping.")
        return False
    try:
        risk = float(event.get('risk_score', 0))
        severity = _get_severity(risk)
        color = '#f03250' if severity == 'CRITICAL' else '#ff8c00' if severity == 'HIGH' else '#ffb800'
        payload = {
            "attachments": [{
                "color": color,
                "title": f"🚨 ThreatPulse Alert — INC-{str(incident_id).zfill(4)}",
                "fields": [
                    {"title": "Severity",    "value": severity,                                                   "short": True},
                    {"title": "Threat Type", "value": event.get('attack_type', 'unknown').replace('_',' ').title(), "short": True},
                    {"title": "User",        "value": event.get('user', 'N/A'),                                    "short": True},
                    {"title": "Source IP",   "value": event.get('ip', 'N/A'),                                     "short": True},
                    {"title": "Risk Score",  "value": f"{risk:.0f}/100",                                          "short": True},
                ],
                "text":   event.get('explanation', '')[:300],
                "footer": f"ThreatPulse • {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            }]
        }
        resp = requests.post(slack_url, json=payload, timeout=10)
        if resp.status_code == 200:
            print(f"✅ Slack Alert sent — INC-{str(incident_id).zfill(4)}")
            return True
        return False
    except Exception as e:
        print(f"❌ Slack send failed: {e}")
        return False


# ── Channel: Generic Webhook ──────────────────────────────────────────────────
def _send_webhook(event: dict, incident_id: int, response_actions: str = '') -> bool:
    webhook_url = os.getenv("ALERT_WEBHOOK_URL", "")
    if not webhook_url:
        return False
    try:
        payload = {
            "incident_id":      incident_id,
            "timestamp":        datetime.utcnow().isoformat(),
            "severity":         _get_severity(event.get('risk_score', 0)),
            "attack_type":      event.get('attack_type', 'unknown'),
            "user":             event.get('user', ''),
            "ip":               event.get('ip', ''),
            "risk_score":       event.get('risk_score', 0),
            "response_actions": response_actions,
            "explanation":      event.get('explanation', ''),
        }
        resp = requests.post(webhook_url, json=payload, timeout=10)
        if resp.ok:
            print(f"✅ Webhook Alert posted — INC-{str(incident_id).zfill(4)}")
            return True
        return False
    except Exception as e:
        print(f"❌ Webhook send failed: {e}")
        return False


# ── Main Dispatcher ───────────────────────────────────────────────────────────
def dispatch_alert(event: dict, incident_id: int, response_actions: str = '') -> dict:
    """
    Dispatch a security alert across all enabled channels.
    Reloads .env on every call so credentials added after startup take immediate effect.

    Args:
        event: dict with threat details (user, ip, risk_score, attack_type, explanation…)
        incident_id: numeric incident ID
        response_actions: SOAR actions JSON string
    Returns:
        dict: {channel: success_bool} for each attempted channel
    """
    # ← KEY FIX: re-read env on every alert so TELEGRAM_CHAT_ID etc. are always current
    _reload_env()

    enable_telegram = os.getenv("ENABLE_TELEGRAM", "true").lower() == "true"
    enable_whatsapp = os.getenv("ENABLE_WHATSAPP", "true").lower() == "true"
    enable_email    = os.getenv("ENABLE_EMAIL",    "false").lower() == "true"
    enable_slack    = os.getenv("ENABLE_SLACK",    "false").lower() == "true"
    enable_webhook  = os.getenv("ENABLE_WEBHOOK",  "false").lower() == "true"

    results = {}

    if enable_telegram:
        results['telegram'] = _send_telegram(event, incident_id, response_actions)

    if enable_whatsapp:
        results['whatsapp'] = _send_whatsapp(event, incident_id, response_actions)

    if enable_email:
        results['email'] = _send_email(event, incident_id, response_actions)

    if enable_slack:
        results['slack'] = _send_slack(event, incident_id, response_actions)

    if enable_webhook:
        results['webhook'] = _send_webhook(event, incident_id, response_actions)

    if not results:
        print("⚠️  No alert channels enabled. Set ENABLE_TELEGRAM=true etc. in .env")

    return results


# ── Backward-compatible wrapper ───────────────────────────────────────────────
def trigger_alert(event: dict, incident_id: int) -> dict:
    """Backward-compatible multi-channel dispatch."""
    return dispatch_alert(event, incident_id)
