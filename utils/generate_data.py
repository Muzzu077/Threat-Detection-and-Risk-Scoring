import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
import os

# Constants
# Constants (Aligned with simulate_live_traffic.py)
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
    'bot_crawler': '45.33.22.11', 
    'hacker_xyz': '182.21.4.9' 
}
# Combined actions from simulator
ACTIONS = ['view_page', 'login', 'api_call', 'failed_login', 'sql_inject_attempt', 'download_report']
RESOURCES = ['home', 'about', 'products', 'login_page', 'admin_panel', 'user_settings', 'sensitive_data']

def generate_logs(num_rows=1000, output_file='data/sample_logs.csv', attack_ratio=0.0):
    data = []
    start_time = datetime.now() - timedelta(days=7)
    
    # Weights similar to simulator: Normal (60%), Login (20%), Suspicious (15%), Attack (10%)...
    # We'll approximate for training data
    
    for _ in range(num_rows):
        is_attack = random.random() < attack_ratio
        
        # Base timestamp
        timestamp = start_time + timedelta(minutes=random.randint(0, 60*24*7))
        
        if is_attack:
            # High Risk / Critical Scenarios
            scenario = random.choice(['attack_attempt', 'bot_scan'])
            if scenario == 'attack_attempt':
                user = 'hacker_xyz'
                action = random.choice(['failed_login', 'sql_inject_attempt'])
                status = 'failed'
                resource = 'admin_panel'
            else: # bot_scan
                user = 'bot_crawler'
                action = 'api_call'
                status = '403_forbidden'
                resource = 'user_settings'
                
            hour = random.choice([0, 1, 2, 22, 23]) # Night often
            
        else:
            # Low / Medium Risk Scenarios
            # 80% Normal, 20% Suspicious (Medium) behavior to learn from?
            # Actually, for "normal" training data, we want mostly Normal.
            # But the model needs to see everything to encode labels? 
            # IsolationForest assumes training data is mostly "normal".
            
            scenario = random.choices(['normal', 'login', 'suspicious'], weights=[60, 20, 10])[0]
            hour = random.randint(8, 20)
            
            if scenario == 'normal':
                user = random.choice(['public_guest', 'customer_101', 'customer_102'])
                action = 'view_page'
                status = 'success'
                resource = random.choice(['home', 'about', 'products'])
                
            elif scenario == 'login':
                user = random.choice(['customer_101', 'customer_102'])
                action = 'login'
                status = 'success'
                resource = 'login_page'
                
            elif scenario == 'suspicious':
                # Mimic the Medium risk scenario
                user = random.choice(['customer_101', 'customer_102'])
                action = 'download_report'
                status = 'success'
                resource = 'sensitive_data'

        # Lookup Role/IP
        role = ROLES[user]
        ip = IPS[user]
        
        # Override timestamp hour
        timestamp = timestamp.replace(hour=hour, minute=random.randint(0, 59))

        data.append([timestamp.strftime('%Y-%m-%d %H:%M:%S'), user, role, ip, action, status, resource])

        data.append([timestamp.strftime('%Y-%m-%d %H:%M:%S'), user, role, ip, action, status, resource])

    df = pd.DataFrame(data, columns=['timestamp', 'user', 'role', 'ip', 'action', 'status', 'resource'])
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df.to_csv(output_file, index=False)
    print(f"Generated {num_rows} logs in {output_file}")

if __name__ == '__main__':
    # 1. Generate normal-ish training data (cleaner)
    generate_logs(num_rows=2000, output_file='data/sample_logs.csv', attack_ratio=0.02)
    
    # 2. Generate attack-heavy test data
    generate_logs(num_rows=500, output_file='data/attack_logs.csv', attack_ratio=0.3)
