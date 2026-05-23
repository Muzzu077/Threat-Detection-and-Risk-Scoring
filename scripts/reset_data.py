import os
import sys

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database import db, LogEvent, Incident, AttackChain
from sqlalchemy import text

def reset_all_data():
    print("🧹 Starting full data wipe...")
    
    # 1. Clear Postgres Data (Events, Incidents, Attack Chains)
    session = db.Session()
    try:
        print("   -> Deleting Attack Chains...")
        session.query(AttackChain).delete()
        print("   -> Deleting Incidents...")
        session.query(Incident).delete()
        print("   -> Deleting Log Events...")
        session.query(LogEvent).delete()
        
        session.commit()
        print("✅ Database events and incidents cleared.")
    except Exception as e:
        session.rollback()
        print(f"❌ Failed to clear database: {e}")
    finally:
        session.close()

    # 2. Clear Redis Rate Limits / Caches (if Redis is running)
    try:
        from src.redis_cache import _get_client
        redis_client = _get_client()
        if redis_client:
            redis_client.flushdb()
            print("✅ Redis cache and rate limits cleared.")
        else:
            print("⚠️ Redis not running, skipping Redis wipe.")
    except Exception as e:
        print(f"⚠️ Could not clear Redis: {e}")

    # 3. Clear local JSON/JSONL state files in data/
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    data_dir = os.path.join(project_root, 'data')
    
    files_to_delete = [
        'response_log.jsonl',
        'ueba_baselines.json',
        'analyst_feedback.jsonl',
        'model_drift.json',
        'threat_intel_cache.json',
        'osint_feeds_cache.json',
        'rate_limits.json',
        'attack_graph.gml'
    ]
    
    print("   -> Deleting local state files...")
    for filename in files_to_delete:
        filepath = os.path.join(data_dir, filename)
        if os.path.exists(filepath):
            os.remove(filepath)
            print(f"      Deleted {filename}")
            
    print("✅ Local state files cleared.")
    print("🚀 Project successfully reset to 0 incidents! Users, API keys, and configurations were preserved.")

if __name__ == "__main__":
    reset_all_data()
