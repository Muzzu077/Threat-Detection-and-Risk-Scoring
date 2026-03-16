import time
import os
import sys

# Add parent dir to path to import from src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv

# 1️⃣ Explicitly load environment variables from project root
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
load_dotenv(os.path.join(PROJECT_ROOT, '.env'))

from src.database import db
from src.anomaly_detection import load_model, train_anomaly_model, detect_anomalies, check_rule_based_anomalies, save_model
from src.context_analysis import analyze_context
from src.risk_scoring import calculate_risk_score
from src.explainability import generate_explanation
from src.log_parser import load_and_preprocess_logs
from utils.alerting import send_whatsapp_alert, format_alert_message, trigger_whatsapp_alert

WATCH_DIR = 'logs_ingest'

class LogHandler(FileSystemEventHandler):
    def __init__(self, model, encoders):
        self.model = model
        self.encoders = encoders

    def on_created(self, event):
        if event.is_directory or not event.src_path.endswith('.csv'):
            return
        
        # Debounce: Wait a tiny bit for file write to complete
        time.sleep(0.1)
        self.process_log_file(event.src_path)

    def process_log_file(self, filepath):
        try:
            # 1. Load Data
            df = load_and_preprocess_logs(filepath)
            if df.empty:
                return

            # print(f"Processing {len(df)} events...")
            
            # 2. Predict using pre-loaded model
            df['anomaly_score'] = detect_anomalies(df, self.model, self.encoders)

            # 3. Process Each Event
            for index, row in df.iterrows():
                # Rule Checks
                rule_score, rule_reasons = check_rule_based_anomalies(row)
                
                # Context
                time_risk, role_risk, resource_risk, context_reasons = analyze_context(row)
                
                # Total Score
                final_anomaly_score = row['anomaly_score'] + rule_score
                total_risk = calculate_risk_score(final_anomaly_score, time_risk, role_risk, resource_risk)
                
                # Explanation
                explanation = generate_explanation(row, final_anomaly_score, context_reasons, rule_reasons)
                
                # Save to DB
                event_dict = {
                    'timestamp': row['timestamp'].to_pydatetime(),
                    'user': row['user'],
                    'role': row['role'],
                    'ip': row['ip'],
                    'action': row['action'],
                    'status': row['status'],
                    'resource': row['resource'],
                    'anomaly_score': final_anomaly_score,
                    'risk_score': total_risk,
                    'time_risk': time_risk,
                    'role_risk': role_risk,
                    'resource_risk': resource_risk,
                    'explanation': explanation
                }
                
                # 5. Insert Logic (Handles Incident Creation automatically in DB layer if critical)
                event_id, incident_id = db.insert_event(event_dict)
                
                # 6. Instant Alerting
                if total_risk > 80:
                    print(f"🚨 CRITICAL ALERT: {row['user']} (Score: {total_risk:.1f})")
                    trigger_whatsapp_alert(event_dict, incident_id)


                
            print(f"✅ Processed {len(df)} events from {os.path.basename(filepath)}")
            
            # Optional: Move processed file to archive ?? For now just leave it.

        except Exception as e:
            print(f"❌ Error processing file: {e}")

def start_ingestion_service():
    os.makedirs(WATCH_DIR, exist_ok=True)
    
    # Pre-load Model
    print("🧠 Loading AI Model...")
    model, encoders = load_model('model.pkl')
    if model is None:
        print("⚠️ No model found. Please run 'utils/generate_data.py' first to train a base model.")
        # Alternatively we can't really train on nothing.
        return

    event_handler = LogHandler(model, encoders)
    observer = Observer()
    observer.schedule(event_handler, path=WATCH_DIR, recursive=False)
    observer.start()
    
    print(f"👀 Watching {WATCH_DIR} for new events...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_ingestion_service()
