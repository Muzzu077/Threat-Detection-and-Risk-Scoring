import time
import random
import pandas as pd
import os
import sys
import io
from datetime import datetime
import textwrap

# Fix Windows console encoding for emoji/unicode characters
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)

# Setup
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
INGEST_DIR = os.path.join(PROJECT_ROOT, 'logs_ingest')
os.makedirs(INGEST_DIR, exist_ok=True)

# Profiles
EMPLOYEES = ['james_wilson', 'sarah_connor', 'michael_chang', 'emily_davis', 'admin_mark', 'finance_julia']
GUESTS = ['public_guest_1', 'public_guest_2', 'contractor_bob']
APT_GROUPS = ['apt29_cozybear', 'lazarus_group', 'fancy_bear', 'shadow_brokers', 'revil_affiliate', 'darkside_operator', 'anonymous_op', 'scattered_spider']
BOT_SCANNERS = ['shodan_scanner', 'masscan_node', 'zgrab_probe', 'census_bot', 'mirai_node', 'log4j_crawler']

ROLES = {
    'james_wilson': 'user', 'sarah_connor': 'user', 'michael_chang': 'developer', 
    'emily_davis': 'hr', 'admin_mark': 'sysadmin', 'finance_julia': 'finance',
    'public_guest_1': 'guest', 'public_guest_2': 'guest', 'contractor_bob': 'contractor'
}

# Assign static IPs to legitimate users
IPS = {user: f"192.168.1.{100 + i}" for i, user in enumerate(EMPLOYEES)}
IPS.update({user: f"172.16.0.{10 + i}" for i, user in enumerate(GUESTS)})

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
            num_events = random.randint(1, 4)
            
            for _ in range(num_events):
                # Pick a scenario
                scenario = random.choices(
                    ['normal_browse', 'login_success', 'suspicious_activity', 'attack_attempt', 'bot_scan'],
                    weights=[45, 20, 10, 15, 10], # Adjusted for better demo mix
                    k=1
                )[0]
                
                timestamp = datetime.now()
                
                if scenario == 'normal_browse':
                    user = random.choice(EMPLOYEES + GUESTS)
                    action = 'view_page'
                    status = 'success'
                    resource = random.choice(['/home', '/about', '/products', '/dashboard'])
                    
                elif scenario == 'login_success':
                    user = random.choice(EMPLOYEES)
                    action = 'login'
                    status = 'success'
                    resource = '/api/v1/auth/login'

                elif scenario == 'suspicious_activity': # Medium Risk
                    user = random.choice(['emily_davis', 'finance_julia', 'contractor_bob'])
                    action = 'download_report'
                    status = 'success'
                    resource = random.choice(['/api/finance/q3_earnings.pdf', '/api/hr/employee_data.csv', '/backup/db_dump.sql'])
                    
                elif scenario == 'attack_attempt':
                    user = random.choice(APT_GROUPS)
                    
                    # Professional attack actions
                    action = random.choice([
                        'failed_login', 'sql_inject_attempt', 'xss_payload_detected', 
                        'port_scan', 'directory_traversal_attempt', 'credential_stuffing',
                        'command_injection', 'malicious_file_upload'
                    ])
                    status = 'failed'
                    resource = random.choice([
                        '/api/v1/admin/auth', '/db/backup.sql', '/etc/passwd', 
                        '/var/www/html/config.php', '/api/users/export', '/wp-admin.php'
                    ])
                    
                elif scenario == 'bot_scan':
                    user = random.choice(BOT_SCANNERS)
                    action = 'unauthorized_api_call'
                    status = '403_forbidden'
                    resource = random.choice(['/api/v2/metrics', '/.git/config', '/wp-admin/login.php', '/.env', '/actuator/env'])

                # Generate highly dynamic IPs for attackers
                if user in APT_GROUPS:
                    current_role = 'external_threat'
                    # Realistic public IPs (avoiding private ranges)
                    current_ip = f"{random.choice([45, 82, 114, 185, 203, 212, 91, 77, 194])}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                elif user in BOT_SCANNERS:
                    current_role = 'automated_scanner'
                    current_ip = f"{random.choice([5, 34, 52, 104, 167, 13, 3])}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                else:
                    current_role = ROLES.get(user, 'standard_user')
                    current_ip = IPS.get(user, '192.168.1.100')

                # Build Row
                batch_events.append({
                    'timestamp': timestamp,
                    'user': user,
                    'role': current_role,
                    'ip': current_ip,
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
