import sys
import os

# Add parent path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.alerting import trigger_whatsapp_alert, send_whatsapp_alert

if __name__ == "__main__":
    print("🚀 Testing WhatsApp Notification (Manual Request Mode)...")
    
    test_event = {
        'user': 'HACKER_WIN',
        'risk_score': 95.5,
        'action': 'PATH_FIX_VERIFY',
        'explanation': 'Bypassing library limit'
    }
    
    sid = trigger_whatsapp_alert(test_event, "INC-TEST-001")
    if sid:
        print(f"✅ Success! Alert triggered with custom format.")
    else:
        print("❌ Failed. Check console output for errors.")
