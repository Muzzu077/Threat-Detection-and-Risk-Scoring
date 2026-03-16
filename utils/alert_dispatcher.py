"""
ThreatPulse — Multi-Channel Alert Dispatcher
Modular alerting system: WhatsApp, Telegram, Email, Slack, Webhook.
Add channels by implementing the channel functions and enabling via .env.
"""
import os
import json
import requests
from datetime import datetime
from typing import Optional
from dotenv import load_dotenv

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(PROJECT_ROOT, '.env'), override=True)


# ── Channel configuration flags ───────────────────────────────────────────────
ENABLE_WHATSAPP = os.getenv("ENABLE_WHATSAPP", "true").lower() == "true"
ENABLE_TELEGRAM = os.getenv("ENABLE_TELEGRAM", "true").lower() == "true"
ENABLE_EMAIL    = os.getenv("ENABLE_EMAIL",    "false").lower() == "true"
ENABLE_SLACK    = os.getenv("ENABLE_SLACK",    "false").lower() == "true"
ENABLE_WEBHOOK  = os.getenv("ENABLE_WEBHOOK",  "false").lower() == "true"

# Email config
SMTP_HOST   = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT   = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER   = os.getenv("SMTP_USER", "")
SMTP_PASS   = os.getenv("SMTP_PASS", "")
EMAIL_FROM  = os.getenv("EMAIL_FROM", "")
EMAIL_TO    = os.getenv("EMAIL_TO", "")

# Slack
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

# Generic webhook
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "")


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
    if not SMTP_USER or not SMTP_PASS or not EMAIL_TO:
        print("⚠️  Email: SMTP credentials not configured. Skipping.")
        return False
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

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
        msg['From']    = EMAIL_FROM or SMTP_USER
        msg['To']      = EMAIL_TO
        msg.attach(MIMEText(html_body, 'html'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, EMAIL_TO, msg.as_string())

        print(f"✅ Email Alert sent to {EMAIL_TO} — INC-{str(incident_id).zfill(4)}")
        return True
    except Exception as e:
        print(f"❌ Email send failed: {e}")
        return False


# ── Channel: Slack ────────────────────────────────────────────────────────────
def _send_slack(event: dict, incident_id: int, response_actions: str = '') -> bool:
    if not SLACK_WEBHOOK_URL:
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
                    {"title": "Severity",    "value": severity,                                          "short": True},
                    {"title": "Threat Type", "value": event.get('attack_type', 'unknown').replace('_',' ').title(), "short": True},
                    {"title": "User",        "value": event.get('user', 'N/A'),                          "short": True},
                    {"title": "Source IP",   "value": event.get('ip', 'N/A'),                            "short": True},
                    {"title": "Risk Score",  "value": f"{risk:.0f}/100",                                 "short": True},
                ],
                "text":   event.get('explanation', '')[:300],
                "footer": f"ThreatPulse • {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            }]
        }
        resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        result = resp.status_code == 200
        if result:
            print(f"✅ Slack Alert sent — INC-{str(incident_id).zfill(4)}")
        return result
    except Exception as e:
        print(f"❌ Slack send failed: {e}")
        return False


# ── Channel: Generic Webhook ──────────────────────────────────────────────────
def _send_webhook(event: dict, incident_id: int, response_actions: str = '') -> bool:
    if not ALERT_WEBHOOK_URL:
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
        resp = requests.post(ALERT_WEBHOOK_URL, json=payload, timeout=10)
        result = resp.ok
        if result:
            print(f"✅ Webhook Alert posted — INC-{str(incident_id).zfill(4)}")
        return result
    except Exception as e:
        print(f"❌ Webhook send failed: {e}")
        return False


# ── Main Dispatcher ───────────────────────────────────────────────────────────
def dispatch_alert(event: dict, incident_id: int, response_actions: str = '') -> dict:
    """
    Dispatch a security alert across all enabled channels.
    
    Args:
        event: dict with threat details (user, ip, risk_score, attack_type, explanation…)
        incident_id: numeric incident ID
        response_actions: comma-separated SOAR actions taken
    Returns:
        dict: {channel: success_bool} for each attempted channel
    """
    results = {}

    if ENABLE_TELEGRAM:
        results['telegram'] = _send_telegram(event, incident_id, response_actions)

    if ENABLE_WHATSAPP:
        results['whatsapp'] = _send_whatsapp(event, incident_id, response_actions)

    if ENABLE_EMAIL:
        results['email'] = _send_email(event, incident_id, response_actions)

    if ENABLE_SLACK:
        results['slack'] = _send_slack(event, incident_id, response_actions)

    if ENABLE_WEBHOOK:
        results['webhook'] = _send_webhook(event, incident_id, response_actions)

    if not results:
        print("⚠️  No alert channels enabled. Set ENABLE_TELEGRAM=true etc. in .env")

    return results


# ── Backward-compatible wrapper ───────────────────────────────────────────────
def trigger_alert(event: dict, incident_id: int) -> dict:
    """Backward-compatible multi-channel dispatch."""
    return dispatch_alert(event, incident_id)
