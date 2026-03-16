import pandas as pd
import numpy as np

def load_and_preprocess_logs(filepath):
    """
    Loads logs from CSV, parses timestamps, and handles missing values.
    """
    try:
        df = pd.read_csv(filepath)
        
        # Convert timestamp to datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Fill missing values if any
        df.fillna({
            'user': 'unknown',
            'role': 'unknown', 
            'ip': '0.0.0.0',
            'action': 'unknown',
            'status': 'unknown',
            'resource': 'unknown'
        }, inplace=True)
        
        # Extract hour for analysis
        df['hour'] = df['timestamp'].dt.hour
        
        return df
    except Exception as e:
        print(f"Error loading logs: {e}")
        return pd.DataFrame()
