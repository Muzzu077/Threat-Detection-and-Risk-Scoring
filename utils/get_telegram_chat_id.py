"""
ThreatPulse — Telegram Chat ID Auto-Fetcher
Run this after you have messaged your bot on Telegram.

Steps:
  1. Open Telegram, search for @Threat_pulse_bot (t.me/Threat_pulse_bot)
  2. Click START or send /start
  3. Run this script: python utils/get_telegram_chat_id.py
  4. Your Chat ID will be printed AND automatically saved to .env
"""
import os
import re
import requests

BOT_TOKEN = os.getenv(
    "TELEGRAM_BOT_TOKEN",
    "8759533207:AAHgqXqfy5fg8LDI4uz0WjY2w6JttTXUlOc"
)

def get_chat_id():
    url  = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"
    resp = requests.get(url, timeout=10)

    if resp.status_code != 200:
        print(f"❌ Telegram API error: {resp.status_code}")
        return None

    data    = resp.json()
    updates = data.get("result", [])

    if not updates:
        print()
        print("❌ No messages found yet!")
        print()
        print("   Please do the following FIRST:")
        print("   1. Open Telegram")
        print("   2. Search for:  @Threat_pulse_bot")
        print("   3. Click START or send /start")
        print("   4. Run this script again")
        print()
        return None

    # Get the most recent message's chat ID
    latest  = updates[-1]
    message = latest.get("message") or latest.get("callback_query", {}).get("message", {})
    chat    = message.get("chat", {})
    chat_id = chat.get("id")
    name    = chat.get("first_name") or chat.get("title") or str(chat_id)

    if chat_id:
        print()
        print("=" * 50)
        print(f"  ✅ TELEGRAM CHAT ID FOUND!")
        print(f"  Name    : {name}")
        print(f"  Chat ID : {chat_id}")
        print("=" * 50)
        print()
        _save_to_env(chat_id)
        _send_test_message(chat_id)
        return chat_id

    print("❌ Could not extract chat ID from updates.")
    return None


def _save_to_env(chat_id: int):
    """Update TELEGRAM_CHAT_ID in .env file."""
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
    if not os.path.exists(env_path):
        print(f"⚠️ .env file not found at {env_path}")
        return

    with open(env_path, 'r') as f:
        content = f.read()

    if "TELEGRAM_CHAT_ID=" in content:
        # Replace existing (even if empty)
        content = re.sub(r'TELEGRAM_CHAT_ID=.*', f'TELEGRAM_CHAT_ID={chat_id}', content)
    else:
        content += f'\nTELEGRAM_CHAT_ID={chat_id}\n'

    with open(env_path, 'w') as f:
        f.write(content)

    print(f"💾 Saved TELEGRAM_CHAT_ID={chat_id} to .env")


def _send_test_message(chat_id: int):
    """Send a welcome test message to confirm the setup."""
    url     = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id":    chat_id,
        "parse_mode": "Markdown",
        "text": (
            "🛡️ *ThreatPulse SOC Platform*\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "✅ *Telegram integration is ACTIVE!*\n\n"
            "You will now receive:\n"
            "  🚨 Critical security alerts\n"
            "  📊 Daily threat summaries\n"
            "  ⚡ SOAR action notifications\n\n"
            "_Your SOC is now watching 24/7_ 👁️"
        ),
    }
    resp = requests.post(url, json=payload, timeout=10)
    if resp.status_code == 200:
        print("📩 Test message sent to Telegram! Check your bot now.")
    else:
        print(f"⚠️ Test message failed: {resp.text}")


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))
    BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", BOT_TOKEN)
    get_chat_id()
