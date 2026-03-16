import time
import random
import pandas as pd
import os
from datetime import datetime
import textwrap

# Setup
INGEST_DIR = 'logs_ingest'
os.makedirs(INGEST_DIR, exist_ok=True)

# Profiles
USERS = ['public_guest', 'customer_101', 'customer_102', 'bot_crawler', 'hacker_xyz']
ROLES = {
    'public_guest': 'guest',
    'customer_101': 'user',
    'customer_102': 'user',
    'bot_crawler': 'impersonator', 
    'hacker_xyz': 'unknown'
}
IPS = {
    'public_guest': '172.16.0.5',
    'customer_101': '192.168.1.5',
    'customer_102': '192.168.1.6',
    'bot_crawler': '45.33.22.11', # Suspicious
    'hacker_xyz': '182.21.4.9' # Targeted
}
ACTIONS = ['view_page', 'login', 'api_call', 'failed_login', 'sql_inject_attempt']
RESOURCES = ['home', 'about', 'products', 'login_page', 'admin_panel', 'user_settings']

def generate_traffic_stream():
    print(f"🚦 Starting Live Traffic Simulator...")
    print(f"📂 Writing events to {INGEST_DIR}/ ...")
    
    batch_id = 0
    
    while True:
        try:
            # Random sleep to simulate traffic variability
            time.sleep(random.uniform(2.0, 5.0))
            
            # Generate 1-3 events per batch
            batch_events = []
            num_events = random.randint(1, 3)
            
            for _ in range(num_events):
                # Pick a scenario
                scenario = random.choices(
                    ['normal_browse', 'login_success', 'attack_attempt', 'bot_scan'],
                    weights=[60, 20, 10, 10],
                    k=1
                )[0]
                
                timestamp = datetime.now()
                
                if scenario == 'normal_browse':
                    user = random.choice(['public_guest', 'customer_101', 'customer_102'])
                    action = 'view_page'
                    status = 'success'
                    resource = random.choice(['home', 'about', 'products'])
                    
                elif scenario == 'login_success':
                    user = random.choice(['customer_101', 'customer_102'])
                    action = 'login'
                    status = 'success'
                    resource = 'login_page'
                    
                elif scenario == 'attack_attempt':
                    user = 'hacker_xyz'
                    action = random.choice(['failed_login', 'sql_inject_attempt'])
                    status = 'failed'
                    resource = 'admin_panel' # High risk
                    
                elif scenario == 'bot_scan':
                    user = 'bot_crawler'
                    action = 'api_call'
                    status = '403_forbidden'
                    resource = 'user_settings' # Accessing restricted

                # Build Row
                batch_events.append({
                    'timestamp': timestamp,
                    'user': user,
                    'role': ROLES[user],
                    'ip': IPS[user],
                    'action': action,
                    'status': status,
                    'resource': resource
                })
            
            # Write Batch
            df = pd.DataFrame(batch_events)
            filename = f"stream_{batch_id}_{int(time.time())}.csv"
            filepath = os.path.join(INGEST_DIR, filename)
            
            df.to_csv(filepath, index=False)
            print(f"➡️ Sent batch {batch_id}: {num_events} events -> {filename}")
            
            batch_id += 1
            
        except KeyboardInterrupt:
            print("\n🛑 Traffic Simulator Stopped.")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    generate_traffic_stream()
