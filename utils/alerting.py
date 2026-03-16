import requests
import os
import sys
from dotenv import load_dotenv

# 1️⃣ Load environment variables from Project Root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env_path = os.path.join(PROJECT_ROOT, '.env')

if os.path.exists(env_path):
    load_dotenv(env_path)

# 2️⃣ Configuration & Validation (Using your provided keys as defaults)


def trigger_whatsapp_alert(event, incident_id):
    """
    Sends a WhatsApp alert using direct API calls (requests) to avoid
    Windows 'MAX_PATH' issues with the official SDK.
    """
    message = f"""
🚨 CRITICAL SECURITY ALERT

User/IP: {event['user']}
Action: {event['action']}
Risk Score: {event['risk_score']:.1f}

Reason:
{event['explanation']}

Incident ID: {incident_id}
"""
    
    try:
        # Strip potential whitespace from keys
        sid = TWILIO_ACCOUNT_SID.strip() if TWILIO_ACCOUNT_SID else ""
        token = TWILIO_AUTH_TOKEN.strip() if TWILIO_AUTH_TOKEN else ""
        
        if not sid or not token:
             print("❌ Alert Skipped: Twilio Credentials not set.")
             return None

        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
        
        payload = {
            "From": TWILIO_WHATSAPP_FROM,
            "To": TO_WHATSAPP,
            "Body": message
        }
        
        response = requests.post(url, data=payload, auth=(sid, token), timeout=10)
        
        if response.status_code == 201:
            res_data = response.json()
            print(f"✅ WhatsApp Alert sent! Incident: {incident_id} | SID: {res_data.get('sid')}")
            return res_data.get('sid')
        else:
            print(f"❌ Failed to reach WhatsApp: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Error in trigger_whatsapp_alert: {e}")
        return None

# For backward compatibility
def send_whatsapp_alert(event_details, incident_id=None):
    return trigger_whatsapp_alert(event_details, incident_id)

def format_alert_message(event):
    return f"Security Alert: {event['user']} - {event['risk_score']}"
