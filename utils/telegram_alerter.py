"""
ThreatPulse — Telegram Alert Bot
Sends rich security incident alerts with inline action buttons.
Bot: t.me/Threat_pulse_bot

All credentials are read from .env at CALL TIME on every function invocation
so that TELEGRAM_CHAT_ID / BOT_TOKEN set after startup are always picked up.
"""
import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENV_PATH    = os.path.join(PROJECT_ROOT, '.env')

# Initial env load at import
load_dotenv(_ENV_PATH, override=True)

TELEGRAM_API_BASE = "https://api.telegram.org/bot"


def _creds():
    """Return (token, chat_id, api_url) fresh from .env on every call."""
    load_dotenv(_ENV_PATH, override=True)
    token   = os.getenv("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
    api_url = f"{TELEGRAM_API_BASE}{token}"
    return token, chat_id, api_url


# ── Severity emoji mapping ─────────────────────────────────────────────────────
SEV_EMOJI = {
    'critical': '🔴',
    'high':     '🟠',
    'medium':   '🟡',
    'low':      '🟢',
}

ATTACK_EMOJI = {
    'brute_force':          '🔐',
    'sql_injection':        '💉',
    'data_exfiltration':    '📤',
    'port_scan':            '🔍',
    'malware':              '🦠',
    'privilege_escalation': '⬆️',
    'lateral_movement':     '↔️',
    'normal':               '✅',
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
    if 'block_ip'        in response_actions: actions.append('  ✔ IP Blocked')
    if 'disable_account' in response_actions: actions.append('  ✔ Account Disabled')
    if 'rate_limit'      in response_actions: actions.append('  ✔ Rate Limit Applied')
    if 'firewall_rule'   in response_actions: actions.append('  ✔ Firewall Rule Added')
    return '\n'.join(actions) if actions else '  ⏳ No actions taken yet'


def send_alert(event: dict, incident_id: int, response_actions: str = '') -> bool:
    """
    Send a formatted critical alert to Telegram with inline action buttons.
    Reads BOT_TOKEN and CHAT_ID from .env at call time.
    """
    token, chat_id, api_url = _creds()

    if not token or not chat_id:
        print(f"⚠️  Telegram: BOT_TOKEN={bool(token)} CHAT_ID={bool(chat_id)} — skipping alert.")
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
        short_exp = explanation[:300] + '...' if len(explanation) > 300 else explanation
        message += f"\n📝 *Analysis:*\n_{short_exp}_\n"

    message += (
        f"\n{'━' * 28}\n"
        f"📋 Incident: `INC-{inc_id_str}`\n"
        f"🕐 {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
    )

    inline_keyboard = {
        "inline_keyboard": [
            [
                {"text": "🔍 View Incident", "url": f"http://localhost:5173/incidents/{incident_id}"},
                {"text": "⚡ API Docs",       "url": "http://localhost:8000/docs"},
            ],
            [
                {"text": "🔒 Block IP",          "callback_data": f"block_ip:{ip}:{incident_id}"},
                {"text": "🖥️ Dashboard",         "url": "http://localhost:5173"},
            ]
        ]
    }

    payload = {
        "chat_id":    chat_id,
        "text":       message,
        "parse_mode": "Markdown",
        "reply_markup": json.dumps(inline_keyboard),
        "disable_web_page_preview": True,
    }

    try:
        resp = requests.post(f"{api_url}/sendMessage", json=payload, timeout=10)
        if resp.status_code == 200:
            print(f"✅ Telegram Alert sent! INC-{inc_id_str} → chat {chat_id}")
            return True
        else:
            print(f"❌ Telegram send failed: {resp.status_code} — {resp.text[:200]}")
            return False
    except Exception as e:
        print(f"❌ Telegram exception: {e}")
        return False


def send_system_status(message: str) -> bool:
    """Send a plain system info message to Telegram."""
    token, chat_id, api_url = _creds()
    if not token or not chat_id:
        return False
    payload = {
        "chat_id":    chat_id,
        "text":       f"ℹ️ *ThreatPulse System*\n\n{message}",
        "parse_mode": "Markdown",
    }
    try:
        resp = requests.post(f"{api_url}/sendMessage", json=payload, timeout=10)
        return resp.status_code == 200
    except Exception:
        return False


def send_daily_summary(stats: dict) -> bool:
    """Send a daily threat summary to Telegram."""
    token, chat_id, api_url = _creds()
    if not token or not chat_id:
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
        "chat_id":    chat_id,
        "text":       message,
        "parse_mode": "Markdown",
    }
    try:
        resp = requests.post(f"{api_url}/sendMessage", json=payload, timeout=10)
        result = resp.status_code == 200
        if result:
            print("✅ Telegram daily summary sent!")
        return result
    except Exception as e:
        print(f"❌ Telegram summary failed: {e}")
        return False


def get_bot_info() -> dict:
    """Fetch bot info to verify the token is valid."""
    token, _, api_url = _creds()
    if not token:
        return {}
    try:
        resp = requests.get(f"{api_url}/getMe", timeout=10)
        if resp.status_code == 200:
            return resp.json().get("result", {})
    except Exception:
        pass
    return {}


def register_webhook_receiver(webhook_url: str) -> bool:
    """Register a webhook so Telegram sends callbacks to ThreatPulse API."""
    token, _, api_url = _creds()
    if not token:
        return False
    payload = {"url": webhook_url}
    try:
        resp = requests.post(f"{api_url}/setWebhook", json=payload, timeout=10)
        result = resp.status_code == 200
        print(f"{'✅' if result else '❌'} Telegram webhook: {webhook_url} → {resp.json()}")
        return result
    except Exception as e:
        print(f"❌ Telegram webhook failed: {e}")
        return False
