import os
import sys
from dotenv import load_dotenv

print("--- DEBUGGING ENVIRONMENT VARIABLES ---")
print(f"Current Working Directory: {os.getcwd()}")

# 1. Check Root .env
root_env = os.path.join(os.getcwd(), '.env')
print(f"Checking for .env at: {root_env}")

if os.path.exists(root_env):
    print("✅ .env file exists.")
    try:
        with open(root_env, 'r') as f:
            content = f.read().strip()
            print(f"📄 File Size: {len(content)} bytes")
            if "AC069bed" in content:
                print("✅ Found an Account SID in the raw file content.")
            else:
                print("❌ Raw file content does NOT appear to contain the Account SID you provided (AC069bed...).")
                print("   Current content preview (first 2 lines):")
                lines = content.split('\n')[:2]
                for line in lines:
                    print(f"   {line}")
    except Exception as e:
        print(f"❌ Error reading file: {e}")
else:
    print("❌ .env file NOT FOUND at this path.")

# 2. Try Loading
print("\n--- ATTEMPTING TO LOAD ---")
load_dotenv(root_env)
sid = os.getenv("TWILIO_ACCOUNT_SID")
token = os.getenv("TWILIO_AUTH_TOKEN")

if sid:
    print(f"✅ Loaded TWILIO_ACCOUNT_SID: {sid[:4]}...{sid[-4:]}")
else:
    print("❌ TWILIO_ACCOUNT_SID is None or Empty.")

if token:
    print(f"✅ Loaded TWILIO_AUTH_TOKEN: {token[:4]}...{token[-4:]}")
else:
    print("❌ TWILIO_AUTH_TOKEN is None or Empty.")

print("---------------------------------------")
