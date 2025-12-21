
import os
import sys

# Add parent directory to path to allow imports from src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.generate_data import generate_logs
from src.log_parser import load_and_preprocess_logs
from src.anomaly_detection import train_anomaly_model, save_model

def rebuild():
    print("🔄 Generatng fresh training data...")
    # Generate 5000 logs with 0.5% attacks (mostly normal)
    generate_logs(num_rows=5000, output_file='data/sample_logs.csv', attack_ratio=0.005)
    
    print("📂 Loading data...")
    df = load_and_preprocess_logs('data/sample_logs.csv')
    
    print(f"🧠 Training model on {len(df)} records...")
    model, encoders = train_anomaly_model(df)
    
    # Save model to project root (where app expects it)
    model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'model.pkl'))
    save_model(model, encoders, model_path)
    print(f"✅ Model saved to {model_path}")

if __name__ == "__main__":
    rebuild()
