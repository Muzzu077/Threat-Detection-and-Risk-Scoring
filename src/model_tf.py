import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Model, load_model
from tensorflow.keras.layers import Input, Dense, Dropout
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import pandas as pd
import os

MODEL_PATH = 'data/model_tf.keras'
ENCODER_PATH = 'data/encoders_tf.pkl'

def build_autoencoder(input_dim):
    """
    Builds a simple Autoencoder for anomaly detection.
    """
    # Encoder
    input_layer = Input(shape=(input_dim,))
    encoder = Dense(32, activation="relu")(input_layer)
    encoder = Dropout(0.2)(encoder)
    encoder = Dense(16, activation="relu")(encoder)
    encoder = Dense(8, activation="relu")(encoder)
    
    # Decoder
    decoder = Dense(16, activation="relu")(encoder)
    decoder = Dropout(0.2)(decoder)
    decoder = Dense(32, activation="relu")(decoder)
    decoder = Dense(input_dim, activation="linear")(decoder) # Reconstruct input
    
    autoencoder = Model(inputs=input_layer, outputs=decoder)
    autoencoder.compile(optimizer='adam', loss='mse')
    return autoencoder

def train_and_save_model(data_path='data/sample_logs.csv'):
    """
    Trains the autoencoder on 'normal' data from the CSV.
    """
    print("🧠 Training TensorFlow Autoencoder...")
    
    if not os.path.exists(data_path):
        print(f"❌ Data file {data_path} not found.")
        return None

    df = pd.read_csv(data_path)
    
    # Preprocessing
    # We need to encode categorical features: User, Role, Action, Resource, Status
    categorical_cols = ['user', 'role', 'action', 'status', 'resource']
    
    encoders = {}
    X_data = pd.DataFrame()

    for col in categorical_cols:
        le = LabelEncoder()
        # Fit on all data
        df[col] = df[col].astype(str)
        X_data[col] = le.fit_transform(df[col])
        encoders[col] = le
        
    # Scale numerical (though these are labels, scaling helps NN convergence)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_data)
    encoders['scaler'] = scaler # Save scaler too
    
    input_dim = X_scaled.shape[1]
    
    # Build & Train
    model = build_autoencoder(input_dim)
    model.fit(X_scaled, X_scaled, epochs=20, batch_size=32, shuffle=True, validation_split=0.1, verbose=0)
    
    # Save
    model.save(MODEL_PATH)
    joblib.dump(encoders, ENCODER_PATH)
    print(f"✅ Model saved to {MODEL_PATH}")
    print(f"✅ Encoders saved to {ENCODER_PATH}")
    return model

def load_tf_model():
    if os.path.exists(MODEL_PATH) and os.path.exists(ENCODER_PATH):
        try:
            model = load_model(MODEL_PATH)
            encoders = joblib.load(ENCODER_PATH)
            return model, encoders
        except Exception as e:
            print(f"⚠️ Error loading TF model: {e}")
            return None, None
    return None, None

def detect_anomalies_tf(df, model, encoders):
    """
    Returns anomaly scores (Reconstruction Error).
    Higher MSE = More Anomalous.
    """
    if model is None or encoders is None:
        return np.zeros(len(df))
        
    # Preprocess incoming df
    X_data = pd.DataFrame()
    categorical_cols = ['user', 'role', 'action', 'status', 'resource']
    
    for col in categorical_cols:
        le = encoders.get(col)
        if le:
            # Handle unseen labels carefully
            df[col] = df[col].astype(str)
            # Use a trick: map known, else 0 or mode?
            # Simple approach: map known, fill unknown with 0
            # A better way for label encoding in prod is OHE, but for this demo LE is fine.
            # We will use .map and fillna
            
            # create a mapping dict
            le_dict = dict(zip(le.classes_, le.transform(le.classes_)))
            X_data[col] = df[col].map(le_dict).fillna(0) 
            
    scaler = encoders.get('scaler')
    X_scaled = scaler.transform(X_data)
    
    # Predict (Reconstruct)
    reconstructions = model.predict(X_scaled, verbose=0)
    
    # MSE
    mse = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
    
    return mse # This is the raw anomaly score
