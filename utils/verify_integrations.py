import os
import sys
from dotenv import load_dotenv

# Add parent path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Load env
load_dotenv()

def verify_openrouter():
    print("\n🔮 Verifying OpenRouter (StepFun) Integration...")
    try:
        from utils.gemini_client import generate_security_summary
        test_event = {
            'user': 'TEST_USER',
            'action': 'Suspicious Login',
            'status': 'Failed',
            'resource': 'Admin Panel',
            'risk_score': 88,
            'explanation': 'Multiple failed login attempts from unknown IP.'
        }
        print("   Sending test prompt to Gemini...")
        summary = generate_security_summary(test_event)
        print(f"   Detailed Summary Length: {len(summary)}")
        
        with open("verification_result.txt", "w", encoding="utf-8") as f:
            f.write(summary)
            
        print(f"   ✅ OpenRouter Response received and saved to verification_result.txt")
        if "Error" in summary:
            print("   ⚠️  Warning: OpenRouter returned an error message.")
        else:
            print("   ✅ OpenRouter Success confirmed.")
    except Exception as e:
        print(f"   ❌ OpenRouter Verification Failed: {e}")

def verify_twilio():
    print("\n📱 Verifying Twilio WhatsApp Integration...")
    try:
        from utils.alerting import trigger_whatsapp_alert
        test_event = {
            'user': 'TEST_USER',
            'risk_score': 99.9,
            'action': 'Unauthorized Access',
            'explanation': 'Integration Test Trigger'
        }
        print(f"   Sending WhatsApp to {os.getenv('TO_WHATSAPP')}...")
        sid = trigger_whatsapp_alert(test_event, "TEST-INCIDENT-001")
        if sid:
            print(f"   ✅ WhatsApp Sent! SID: {sid}")
        else:
            print("   ❌ WhatsApp Sending Failed (Check logs).")
    except Exception as e:
        print(f"   ❌ Twilio Verification Failed: {e}")

if __name__ == "__main__":
    print("🚀 Starting Integration Verification")
    verify_openrouter()
    verify_twilio()
