import os
import json
from dotenv import load_dotenv

# Load environment variables from Project Root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env_path = os.path.join(PROJECT_ROOT, '.env')

if os.path.exists(env_path):
    load_dotenv(env_path, override=True)

# Configuration — set all credentials in .env file
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_WHATSAPP_FROM = os.getenv("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886")
TO_WHATSAPP = os.getenv("TO_WHATSAPP", "")

def trigger_whatsapp_alert(event, incident_id):
    """Sends a WhatsApp alert via Twilio SDK."""
    message = (
        f"🚨 *THREAT PULSE ALERT* 🚨\n\n"
        f"👤 User: {event['user']}\n"
        f"⚡ Action: {event['action']}\n"
        f"🔴 Risk Score: {event['risk_score']:.0f}/100\n\n"
        f"📝 Reason:\n{event['explanation']}\n\n"
        f"📋 Incident ID: {incident_id}\n\n"
        f"🛡️ Immediate investigation recommended."
    )

    try:
        sid = TWILIO_ACCOUNT_SID.strip() if TWILIO_ACCOUNT_SID else ""
        token = TWILIO_AUTH_TOKEN.strip() if TWILIO_AUTH_TOKEN else ""

        if not sid or not token:
            print("❌ Alert Skipped: Twilio Credentials not set.")
            return None

        from twilio.rest import Client
        client = Client(sid, token)

        twilio_msg = client.messages.create(
            from_=TWILIO_WHATSAPP_FROM,
            body=message,
            to=TO_WHATSAPP
        )

        print(f"✅ WhatsApp Alert sent! Incident: {incident_id} | SID: {twilio_msg.sid}")
        return twilio_msg.sid

    except Exception as e:
        print(f"❌ Failed to send WhatsApp: {e}")
        return None

# For backward compatibility
def send_whatsapp_alert(event_details, incident_id=None):
    return trigger_whatsapp_alert(event_details, incident_id)

def format_alert_message(event):
    return f"Security Alert: {event['user']} - {event['risk_score']}"
