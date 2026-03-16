import requests
import sys
import os

# Add parent path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.alerting import send_telegram_alert, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

if __name__ == "__main__":
    print("🚀 Testing Telegram Notification...")
    print(f"🔹 Bot Token: {TELEGRAM_BOT_TOKEN[:5]}...*****")
    print(f"🔹 Chat ID: {TELEGRAM_CHAT_ID}")
    
    print(f"🔹 Chat ID: {TELEGRAM_CHAT_ID}")
    
    msg = "🚨 *Debug Test*: Checking connectivity..."
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": msg,
        "parse_mode": "Markdown"
    }
    
    try:
        print(f"📡 Sending request to {url[:30]}...")
        response = requests.post(url, json=payload, timeout=10)
        print(f"⬇️ Status Code: {response.status_code}")
        print(f"📄 Response: {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
