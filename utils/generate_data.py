import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
import os

# Constants
USERS = ['alice', 'bob', 'charlie', 'dave', 'eve_admin', 'frank_admin']
ROLES = {'alice': 'user', 'bob': 'user', 'charlie': 'user', 'dave': 'user', 'eve_admin': 'admin', 'frank_admin': 'admin'}
IPS = ['192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.13', '10.0.0.5', '10.0.0.6']
# External/Suspicious IPs
SUSPICIOUS_IPS = ['182.21.4.9', '45.33.22.11', '203.0.113.5']
ACTIONS = ['login', 'logout', 'file_access', 'data_export', 'system_config']
STATUSES = ['success', 'failed']
RESOURCES = ['HR_portal', 'project_docs', 'admin_panel', 'finance_db', 'public_site']

def generate_logs(num_rows=1000, output_file='data/sample_logs.csv', attack_ratio=0.0):
    data = []
    start_time = datetime.now() - timedelta(days=7)
    
    for _ in range(num_rows):
        is_attack = random.random() < attack_ratio
        
        # Base timestamp: mostly during office hours (9-17)
        if is_attack and random.random() < 0.7:
            # Attack: unusual time (e.g., 2 AM)
            hour = random.choice([0, 1, 2, 3, 4, 20, 21, 22, 23])
        else:
            # Normal: office hours
            hour = random.randint(9, 17)
            
        timestamp = start_time + timedelta(minutes=random.randint(0, 60*24*7))
        timestamp = timestamp.replace(hour=hour, minute=random.randint(0, 59))
        
        if is_attack:
            # Attack Scenarios
            scenario = random.choice(['brute_force', 'unusual_admin', 'data_exfil'])
            
            if scenario == 'brute_force':
                user = random.choice(USERS)
                role = ROLES[user]
                ip = random.choice(SUSPICIOUS_IPS) if random.random() > 0.5 else random.choice(IPS)
                action = 'login'
                status = 'failed'
                resource = 'admin_panel'
            
            elif scenario == 'unusual_admin':
                 # Admin login from new IP at odd hours
                user = 'eve_admin'
                role = ROLES[user]
                ip = random.choice(SUSPICIOUS_IPS)
                action = 'login'
                status = 'success'
                resource = 'admin_panel'
                
            elif scenario == 'data_exfil':
                user = random.choice(['alice', 'bob']) # Normal user trying to access sensitive data
                role = ROLES[user]
                ip = IPS[USERS.index(user)]
                action = 'data_export'
                status = 'success'
                resource = 'finance_db'
        
        else:
            # Normal Behavior
            user = random.choice(USERS)
            role = ROLES[user]
            ip = IPS[USERS.index(user)]
            action = random.choice(ACTIONS)
            
            if action == 'login':
                status = 'success' if random.random() > 0.05 else 'failed' # Occasional failure is normal
            else:
                status = 'success'
                
            resource = random.choice(RESOURCES)
            
            # Constraints for realism
            if role == 'user' and resource == 'admin_panel':
                 # Normal users rarely access admin panel successfully
                 status = 'failed'

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
