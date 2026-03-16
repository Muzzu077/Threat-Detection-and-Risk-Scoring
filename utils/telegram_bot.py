"""
ThreatPulse — Telegram Bot Callback Handler
Polls for inline button clicks and executes SOAR actions.

Handles callback_data patterns:
  block_ip:<ip>:<incident_id>
  resolve:<incident_id>
  details:<incident_id>
  soar:<incident_id>
"""
import os
import sys
import io
import json
import time
import threading
import requests
from datetime import datetime
from dotenv import load_dotenv

# Fix Windows console encoding
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

load_dotenv(os.path.join(PROJECT_ROOT, '.env'), override=True)

TELEGRAM_API_BASE = "https://api.telegram.org/bot"
API_BASE = "http://localhost:8000"


def _creds():
    load_dotenv(os.path.join(PROJECT_ROOT, '.env'), override=True)
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
    return token, chat_id, f"{TELEGRAM_API_BASE}{token}"


def _answer_callback(api_url: str, callback_id: str, text: str):
    """Send a toast notification back to the user who clicked the button."""
    try:
        requests.post(f"{api_url}/answerCallbackQuery", json={
            "callback_query_id": callback_id,
            "text": text,
            "show_alert": True,
        }, timeout=5)
    except Exception:
        pass


def _edit_message(api_url: str, chat_id: str, message_id: int, new_text: str):
    """Append status text below the original alert message."""
    try:
        requests.post(f"{api_url}/sendMessage", json={
            "chat_id": chat_id,
            "text": new_text,
            "parse_mode": "Markdown",
            "reply_to_message_id": message_id,
        }, timeout=5)
    except Exception:
        pass


def handle_block_ip(api_url: str, chat_id: str, message_id: str, callback_id: str, ip: str, incident_id: str):
    """Block an IP via the SOAR response engine."""
    try:
        from src.response_engine import block_ip
        result = block_ip(ip)
        status = result.get("status", "unknown")

        if status == "success":
            _answer_callback(api_url, callback_id, f"IP {ip} has been blocked!")
            _edit_message(api_url, chat_id, message_id,
                          f"🔒 *IP Blocked*\n`{ip}` blocked by operator via Telegram.\nIncident: `INC-{incident_id.zfill(4)}`")
        elif status == "already_blocked":
            _answer_callback(api_url, callback_id, f"IP {ip} is already blocked.")
        else:
            _answer_callback(api_url, callback_id, f"Block IP: {status}")
    except Exception as e:
        _answer_callback(api_url, callback_id, f"Error: {str(e)[:100]}")


def handle_resolve(api_url: str, chat_id: str, message_id: str, callback_id: str, incident_id: str):
    """Mark an incident as resolved."""
    try:
        from src.database import db
        db.update_incident_status(int(incident_id), "RESOLVED", "Telegram Operator")
        _answer_callback(api_url, callback_id, f"INC-{incident_id.zfill(4)} marked as RESOLVED!")
        _edit_message(api_url, chat_id, message_id,
                      f"✅ *Incident Resolved*\n`INC-{incident_id.zfill(4)}` marked RESOLVED by operator via Telegram.")
    except Exception as e:
        _answer_callback(api_url, callback_id, f"Error: {str(e)[:100]}")


def handle_details(api_url: str, chat_id: str, message_id: str, callback_id: str, incident_id: str):
    """Fetch and display incident details."""
    try:
        from src.database import db
        incident, log_event = db.get_incident_details(int(incident_id))
        if not incident:
            _answer_callback(api_url, callback_id, "Incident not found.")
            return

        _answer_callback(api_url, callback_id, "Loading details...")

        details = (
            f"📋 *Incident Details — INC-{incident_id.zfill(4)}*\n"
            f"{'━' * 28}\n\n"
            f"👤 *User:* `{incident.user}`\n"
            f"⚡ *Action:* {incident.action}\n"
            f"🎯 *Attack Type:* {(incident.attack_type or 'unknown').replace('_', ' ').title()}\n"
            f"📊 *Risk Score:* {incident.risk_score:.0f}/100\n"
            f"📌 *Status:* {incident.status}\n"
            f"👷 *Owner:* {incident.owner}\n"
        )

        if log_event:
            details += (
                f"\n🌐 *IP:* `{log_event.ip}`\n"
                f"🗺 *Country:* {log_event.country or 'UNKNOWN'}\n"
                f"🔬 *ML Confidence:* {log_event.ml_confidence or 0:.0f}%\n"
                f"🛡 *Threat Intel Score:* {log_event.threat_intel_score or 0:.0f}\n"
            )

        if incident.note:
            short_note = incident.note[:400] + '...' if len(incident.note) > 400 else incident.note
            details += f"\n📝 *AI Analysis:*\n_{short_note}_\n"

        if incident.response_actions:
            details += f"\n🤖 *SOAR Actions:* {incident.response_actions}\n"

        details += f"\n🕐 {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"

        _edit_message(api_url, chat_id, message_id, details)

    except Exception as e:
        _answer_callback(api_url, callback_id, f"Error: {str(e)[:100]}")


def handle_soar(api_url: str, chat_id: str, message_id: str, callback_id: str, incident_id: str):
    """Trigger full SOAR response for an incident."""
    try:
        from src.database import db
        from src.response_engine import execute_response

        incident, log_event = db.get_incident_details(int(incident_id))
        if not incident:
            _answer_callback(api_url, callback_id, "Incident not found.")
            return

        _answer_callback(api_url, callback_id, "Executing SOAR response...")

        event_dict = {
            "user": incident.user,
            "action": incident.action,
            "ip": log_event.ip if log_event else "unknown",
            "risk_score": incident.risk_score,
            "explanation": log_event.explanation if log_event else "",
            "attack_type": incident.attack_type or "unknown",
        }

        response = execute_response(event_dict, int(incident_id))
        actions = response.get("actions_taken", [])

        # Update incident in DB
        db.update_incident_response(int(incident_id), json.dumps([a.get("action", "") for a in actions]))

        # Build reply
        action_lines = []
        for a in actions:
            status_icon = "✅" if a.get("status") == "success" else "⚠️"
            action_lines.append(f"  {status_icon} {a.get('action', '').replace('_', ' ').title()}")

        reply = (
            f"🤖 *SOAR Response Executed*\n"
            f"{'━' * 28}\n"
            f"Incident: `INC-{incident_id.zfill(4)}`\n\n"
            f"*{len(actions)} action(s) taken:*\n"
            + "\n".join(action_lines)
        )

        if actions:
            for a in actions:
                if a.get("command"):
                    reply += f"\n\n`$ {a['command']}`"
                    break

        _edit_message(api_url, chat_id, message_id, reply)

    except Exception as e:
        _answer_callback(api_url, callback_id, f"SOAR Error: {str(e)[:100]}")


def poll_callbacks():
    """Long-poll Telegram for callback queries (button clicks)."""
    token, chat_id, api_url = _creds()
    if not token:
        print("[Telegram Bot] No TELEGRAM_BOT_TOKEN set. Callback handler disabled.")
        return

    print(f"[Telegram Bot] Polling for button callbacks...")
    offset = 0

    while True:
        try:
            token, chat_id, api_url = _creds()
            resp = requests.get(f"{api_url}/getUpdates", params={
                "offset": offset,
                "timeout": 30,
                "allowed_updates": json.dumps(["callback_query"]),
            }, timeout=35)

            if resp.status_code != 200:
                time.sleep(5)
                continue

            updates = resp.json().get("result", [])
            for update in updates:
                offset = update["update_id"] + 1
                callback = update.get("callback_query")
                if not callback:
                    continue

                data = callback.get("data", "")
                cb_id = callback["id"]
                msg = callback.get("message", {})
                msg_id = msg.get("message_id", "")
                cb_chat_id = str(msg.get("chat", {}).get("id", chat_id))

                print(f"[Telegram Bot] Button clicked: {data}")

                parts = data.split(":")
                action = parts[0]

                if action == "block_ip" and len(parts) >= 3:
                    ip = parts[1]
                    inc_id = parts[2]
                    handle_block_ip(api_url, cb_chat_id, msg_id, cb_id, ip, inc_id)

                elif action == "resolve" and len(parts) >= 2:
                    inc_id = parts[1]
                    handle_resolve(api_url, cb_chat_id, msg_id, cb_id, inc_id)

                elif action == "details" and len(parts) >= 2:
                    inc_id = parts[1]
                    handle_details(api_url, cb_chat_id, msg_id, cb_id, inc_id)

                elif action == "soar" and len(parts) >= 2:
                    inc_id = parts[1]
                    handle_soar(api_url, cb_chat_id, msg_id, cb_id, inc_id)

                else:
                    _answer_callback(api_url, cb_id, f"Unknown action: {data}")

        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.ConnectionError:
            time.sleep(5)
        except Exception as e:
            print(f"[Telegram Bot] Error: {e}")
            time.sleep(5)


def start_polling_thread():
    """Start the Telegram callback poller as a daemon thread."""
    token, _, _ = _creds()
    if not token:
        return None

    # Delete any existing webhook so polling works
    try:
        requests.post(f"{TELEGRAM_API_BASE}{token}/deleteWebhook", timeout=5)
    except Exception:
        pass

    t = threading.Thread(target=poll_callbacks, daemon=True, name="telegram-bot-poller")
    t.start()
    print("[Telegram Bot] Callback handler started (background thread)")
    return t


if __name__ == "__main__":
    print("ThreatPulse Telegram Bot — Callback Handler")
    print("Listening for inline button clicks...")
    print("Press Ctrl+C to stop.\n")
    poll_callbacks()
