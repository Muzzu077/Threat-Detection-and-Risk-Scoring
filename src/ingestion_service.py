import time
import os
import sys
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
load_dotenv(os.path.join(PROJECT_ROOT, '.env'))

from src.database import db
from src.model_tf import load_tf_model, detect_anomalies_tf
from src.context_analysis import analyze_context
from src.risk_scoring import calculate_risk_score
from src.explainability import generate_explanation
from src.log_parser import load_and_preprocess_logs
from src.anomaly_detection import check_rule_based_anomalies

# NEW: Extended modules
from src.ml_engine import load_ml_engine, predict_attack_type
from src.threat_intel import check_ip
from src.response_engine import execute_response
from src.attack_graph import get_attack_chains, build_graph

from utils.alerting import trigger_whatsapp_alert
from utils.gemini_client import generate_security_summary

WATCH_DIR = os.path.join(PROJECT_ROOT, 'logs_ingest')


class LogHandler(FileSystemEventHandler):
    def __init__(self, tf_model, tf_encoders, ml_model, ml_encoders):
        self.tf_model = tf_model
        self.tf_encoders = tf_encoders
        self.ml_model = ml_model
        self.ml_encoders = ml_encoders

    def on_created(self, event):
        if event.is_directory or not event.src_path.endswith('.csv'):
            return
        time.sleep(0.1)
        self.process_log_file(event.src_path)

    def process_log_file(self, filepath):
        try:
            df = load_and_preprocess_logs(filepath)
            if df.empty:
                return

            # 1. TF Autoencoder anomaly scores
            df['anomaly_score'] = detect_anomalies_tf(df, self.tf_model, self.tf_encoders)

            for index, row in df.iterrows():
                # 2. Rule-based checks
                rule_score, rule_reasons = check_rule_based_anomalies(row)

                # 3. Context analysis
                time_risk, role_risk, resource_risk, context_reasons = analyze_context(row)

                # 4. Final risk score
                final_anomaly_score = row['anomaly_score'] + rule_score
                total_risk = calculate_risk_score(final_anomaly_score, time_risk, role_risk, resource_risk)

                # 5. Explanation
                explanation = generate_explanation(row, final_anomaly_score, context_reasons, rule_reasons)

                # 6. NEW: ML Classification
                row_df = pd.DataFrame([row])
                ml_result = predict_attack_type(row_df, self.ml_model, self.ml_encoders)
                attack_type = ml_result.get("predicted_class", "unknown")
                ml_confidence = ml_result.get("confidence", 0.0)

                # 7. NEW: Threat Intelligence
                ti_result = check_ip(str(row.get('ip', '')))
                country = ti_result.get("country", "UNKNOWN")
                threat_intel_score = float(ti_result.get("abuse_score", 0))
                threat_intel_reason = (
                    f"AbuseIPDB: {threat_intel_score}% confidence, "
                    f"{ti_result.get('total_reports', 0)} reports"
                    if ti_result.get("data_source") == "abuseipdb" else ""
                )
                # Boost risk score if IP is known bad
                if ti_result.get("is_suspicious"):
                    total_risk = min(100, total_risk + 15)

                # 8. Save to DB
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
                    'explanation': explanation,
                    # NEW fields
                    'attack_type': attack_type,
                    'ml_confidence': ml_confidence,
                    'country': country,
                    'threat_intel_score': threat_intel_score,
                    'threat_intel_reason': threat_intel_reason,
                    'response_actions': ""
                }

                event_id, incident_id = db.insert_event(event_dict)

                # 9. Critical alert handling
                if total_risk > 80:
                    print(f"🚨 CRITICAL [{attack_type.upper()}] | {row['user']} (Score: {total_risk:.1f}) from {country}")

                    # AI Summary
                    event_dict['attack_type'] = attack_type
                    ai_summary = generate_security_summary(event_dict)

                    if incident_id:
                        db.update_incident_note(incident_id, ai_summary)

                    # 10. NEW: SOAR Auto-Response for critical (>90)
                    if total_risk > 90:
                        print(f"🤖 SOAR: Triggering automated response for incident {incident_id}")
                        response = execute_response(event_dict, incident_id)
                        response_json = json.dumps([a.get("action", "") for a in response.get("actions_taken", [])])
                        if incident_id:
                            db.update_incident_response(incident_id, response_json)
                        print(f"   ✅ {response['actions_count']} automated action(s) taken.")

                    # WhatsApp Alert
                    trigger_whatsapp_alert(event_dict, incident_id)

            print(f"✅ Processed {len(df)} events from {os.path.basename(filepath)}")

        except Exception as e:
            print(f"❌ Error processing file: {e}")
            import traceback
            traceback.print_exc()


def start_ingestion_service():
    os.makedirs(WATCH_DIR, exist_ok=True)

    print("🧠 Loading TensorFlow Autoencoder Model...")
    tf_model, tf_encoders = load_tf_model()
    if tf_model is None:
        print("⚠️ No TF model. Run 'python utils/generate_data.py' first.")
        return

    print("🤖 Loading ML Classification Engine...")
    ml_model, ml_encoders = load_ml_engine()
    if ml_model is None:
        print("⚠️ ML model not found. Run 'python utils/train_ml_engine.py' first.")
        print("   Continuing with TF model only...")

    event_handler = LogHandler(tf_model, tf_encoders, ml_model, ml_encoders)
    observer = Observer()
    observer.schedule(event_handler, path=WATCH_DIR, recursive=False)
    observer.start()

    print(f"👀 Watching {WATCH_DIR} for new log events...")
    print("   Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    start_ingestion_service()
