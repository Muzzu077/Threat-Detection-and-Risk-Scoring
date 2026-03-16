"""
ThreatPulse — Telegram Alert Bot
Sends rich security incident alerts with inline action buttons.
Bot: t.me/Threat_pulse_bot
"""
import os
import json
import requests
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv(os.path.join(PROJECT_ROOT, '.env'), override=True)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")

TELEGRAM_API = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

# ── Severity emoji mapping ─────────────────────────────────────────────────────
SEV_EMOJI = {
    'critical': '🔴',
    'high':     '🟠',
    'medium':   '🟡',
    'low':      '🟢',
}

ATTACK_EMOJI = {
    'brute_force':         '🔐',
    'sql_injection':       '💉',
    'data_exfiltration':   '📤',
    'port_scan':           '🔍',
    'malware':             '🦠',
    'privilege_escalation':'⬆️',
    'lateral_movement':    '↔️',
    'normal':              '✅',
}

def _get_severity(risk_score: float) -> str:
    if risk_score >= 80: return 'critical'
    if risk_score >= 60: return 'high'
    if risk_score >= 40: return 'medium'
    return 'low'


def _format_response_actions(response_actions: str) -> str:
    if not response_actions:
        return '  ⏳ Pending SOAR analysis'
    actions = []
    if 'block_ip'       in response_actions: actions.append('  ✔ IP Blocked')
    if 'disable_account' in response_actions: actions.append('  ✔ Account Disabled')
    if 'rate_limit'     in response_actions: actions.append('  ✔ Rate Limit Applied')
    if 'firewall_rule'  in response_actions: actions.append('  ✔ Firewall Rule Added')
    return '\n'.join(actions) if actions else '  ⏳ No actions taken yet'


def send_alert(event: dict, incident_id: int, response_actions: str = '') -> bool:
    """
    Send a formatted critical alert to Telegram with inline buttons.
    
    Args:
        event: dict with keys: user, action, ip, risk_score, attack_type, country, explanation
        incident_id: integer incident ID
        response_actions: comma-separated SOAR action string
    Returns:
        True if sent successfully, False otherwise
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("⚠️  Telegram: BOT_TOKEN or CHAT_ID not set. Skipping alert.")
        return False

    risk       = float(event.get('risk_score', 0))
    sev        = _get_severity(risk)
    sev_emoji  = SEV_EMOJI.get(sev, '⚪')
    atk_type   = event.get('attack_type', 'unknown')
    atk_emoji  = ATTACK_EMOJI.get(atk_type, '⚠️')
    ip         = event.get('ip', 'N/A')
    country    = event.get('country', 'UNKNOWN')
    user       = event.get('user', 'N/A')
    action     = event.get('action', 'N/A')
    explanation = event.get('explanation', '')
    inc_id_str = str(incident_id).zfill(4)

    message = (
        f"🚨 *THREATPULSE SECURITY ALERT*\n"
        f"{'━' * 28}\n\n"
        f"{sev_emoji} *Severity:* {sev.upper()}\n"
        f"{atk_emoji} *Threat Type:* {atk_type.replace('_', ' ').title()}\n"
        f"👤 *User:* `{user}`\n"
        f"🌐 *Source IP:* `{ip}` ({country})\n"
        f"⚡ *Action:* {action}\n"
        f"📊 *Risk Score:* {risk:.0f}/100\n\n"
        f"🛡️ *Actions Taken:*\n{_format_response_actions(response_actions)}\n"
    )

    if explanation:
        # Keep explanation concise
        short_exp = explanation[:300] + '...' if len(explanation) > 300 else explanation
        message += f"\n📝 *Analysis:*\n_{short_exp}_\n"

    message += (
        f"\n{'━' * 28}\n"
        f"📋 Incident: `INC-{inc_id_str}`\n"
        f"🕐 {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
    )

    # Inline keyboard buttons
    inline_keyboard = {
        "inline_keyboard": [
            [
                {"text": "🔍 View Incident", "url": f"http://localhost:5173/incidents/{incident_id}"},
                {"text": "⚡ API Docs",       "url": "http://localhost:8000/docs"},
            ],
            [
                {"text": "🔒 Block IP",         "callback_data": f"block_ip:{ip}:{incident_id}"},
                {"text": "🔓 View on Dashboard", "url": f"http://localhost:5173"},
            ]
        ]
    }

    payload = {
        "chat_id":    TELEGRAM_CHAT_ID,
        "text":       message,
        "parse_mode": "Markdown",
        "reply_markup": json.dumps(inline_keyboard),
        "disable_web_page_preview": True,
    }

    try:
        resp = requests.post(f"{TELEGRAM_API}/sendMessage", json=payload, timeout=10)
        if resp.status_code == 200:
            print(f"✅ Telegram Alert sent! Incident INC-{inc_id_str} → chat {TELEGRAM_CHAT_ID}")
            return True
        else:
            print(f"❌ Telegram send failed: {resp.status_code} — {resp.text}")
            return False
    except Exception as e:
        print(f"❌ Telegram exception: {e}")
        return False


def send_system_status(message: str) -> bool:
    """Send a plain system status/info message to Telegram."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    payload = {
        "chat_id":    TELEGRAM_CHAT_ID,
        "text":       f"ℹ️ *ThreatPulse System*\n\n{message}",
        "parse_mode": "Markdown",
    }
    try:
        resp = requests.post(f"{TELEGRAM_API}/sendMessage", json=payload, timeout=10)
        return resp.status_code == 200
    except Exception:
        return False


def send_daily_summary(stats: dict) -> bool:
    """Send a daily threat summary report to the Telegram channel."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False

    message = (
        f"📊 *THREATPULSE DAILY SUMMARY*\n"
        f"{'━' * 28}\n\n"
        f"🔴 Critical Events: {stats.get('critical_count', 0)}\n"
        f"🟠 High Events:     {stats.get('high_count', 0)}\n"
        f"📁 Total Events:    {stats.get('total_events', 0)}\n"
        f"📋 Open Incidents:  {stats.get('open_incidents', 0)}\n"
        f"📊 Avg Risk Score:  {stats.get('avg_risk', 0):.1f}/100\n\n"
        f"🕐 {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
    )

    payload = {
        "chat_id":    TELEGRAM_CHAT_ID,
        "text":       message,
        "parse_mode": "Markdown",
    }
    try:
        resp = requests.post(f"{TELEGRAM_API}/sendMessage", json=payload, timeout=10)
        result = resp.status_code == 200
        if result:
            print("✅ Telegram daily summary sent!")
        return result
    except Exception as e:
        print(f"❌ Telegram summary failed: {e}")
        return False


def register_webhook_receiver(webhook_url: str) -> bool:
    """Register a webhook so Telegram sends callback_data to ThreatPulse API."""
    if not TELEGRAM_BOT_TOKEN:
        return False
    payload = {"url": webhook_url}
    try:
        resp = requests.post(f"{TELEGRAM_API}/setWebhook", json=payload, timeout=10)
        result = resp.status_code == 200
        print(f"{'✅' if result else '❌'} Telegram webhook: {webhook_url} → {resp.json()}")
        return result
    except Exception as e:
        print(f"❌ Telegram webhook registration failed: {e}")
        return False


def get_bot_info() -> dict:
    """Fetch bot info to verify the token is valid."""
    if not TELEGRAM_BOT_TOKEN:
        return {}
    try:
        resp = requests.get(f"{TELEGRAM_API}/getMe", timeout=10)
        if resp.status_code == 200:
            return resp.json().get("result", {})
    except Exception:
        pass
    return {}
