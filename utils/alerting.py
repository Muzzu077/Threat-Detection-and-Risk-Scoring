import requests
import os
import json

# 🚨 CONFIGURATION (Twilio WhatsApp) 🚨
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_WHATSAPP_FROM = 'whatsapp:+14155238886'
TO_WHATSAPP = 'whatsapp:+918074708433'

def trigger_whatsapp_alert(event, incident_id):
    """
    Sends a WhatsApp alert with the user's specific requested format.
    Uses requests to avoid Twilio library path issues on Windows.
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
        # Strip potential whitespace
        sid = TWILIO_ACCOUNT_SID.strip() if TWILIO_ACCOUNT_SID else ""
        token = TWILIO_AUTH_TOKEN.strip() if TWILIO_AUTH_TOKEN else ""
        
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

# For backward compatibility with existing code
def send_whatsapp_alert(event_details, incident_id=None):
    return trigger_whatsapp_alert(event_details, incident_id)

def format_alert_message(event):
    return f"Security Alert: {event['user']} - {event['risk_score']}"
