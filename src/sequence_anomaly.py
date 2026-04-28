"""
TrustFlow — Transformer-based Sequence Anomaly Detection

Detects anomalous *sessions* (sequences of consecutive actions by the same
user) using a small transformer encoder with a self-supervised reconstruction
objective. Sequences whose actions can't be reconstructed by the model — i.e.,
patterns the model has never seen — get high anomaly scores.

Model architecture:
    [token_embed + pos_embed] → MultiHeadAttention(heads=4)
                              → Dense(d_model) → Dense(vocab) softmax
    Loss: masked next-action cross-entropy (causal, teacher-forced).

The model is saved to data/sequence_transformer.keras. If no trained model
exists, score_session() falls back to a fast entropy/edit-distance heuristic
so the API endpoint always returns something useful.

Inference returns a per-user score in [0, 1] where higher = more anomalous.
"""
import os
import json
import math
from collections import Counter, defaultdict
from datetime import datetime

import numpy as np

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SEQ_MODEL_PATH = os.path.join(_PROJECT_ROOT, "data", "sequence_transformer.keras")
SEQ_VOCAB_PATH = os.path.join(_PROJECT_ROOT, "data", "sequence_vocab.json")

WINDOW_SIZE = 20    # tokens per session window
MIN_SESSION = 3     # ignore sessions shorter than this
D_MODEL     = 32
N_HEADS     = 4
N_LAYERS    = 2

# ── Tokenisation ─────────────────────────────────────────────────────────────

def _get(event, key: str, default=""):
    """Field accessor that works for both dicts and ORM rows."""
    if isinstance(event, dict):
        return event.get(key, default) or default
    return getattr(event, key, default) or default


def _action_token(event) -> str:
    """Compact token for one event — combines verb + resource bucket."""
    action = str(_get(event, "action")).upper()[:6]
    resource = str(_get(event, "resource"))
    res_bucket = "/".join(resource.lstrip("/").split("/")[:2])[:30] or "ROOT"
    status = str(_get(event, "status"))
    fail = "F" if status.lower() in ("failure", "error", "fail", "denied") else "S"
    return f"{action}|{res_bucket}|{fail}"


def _events_to_sessions(events):
    """Group events by user → ordered token sequence per user."""
    by_user = defaultdict(list)
    sorted_events = sorted(events, key=lambda e: getattr(e, "timestamp", None) or datetime.min)
    for e in sorted_events:
        user = getattr(e, "user", None)
        if not user:
            continue
        by_user[user].append(_action_token(e))
    return {u: toks for u, toks in by_user.items() if len(toks) >= MIN_SESSION}


# ── Heuristic fallback (works without training) ──────────────────────────────

def _heuristic_score(tokens: list) -> float:
    """
    Anomaly heuristic — compares the session's token entropy against the
    expected baseline. Anomalous sessions tend to have:
      • very low entropy (loop / scrape / brute-force) OR
      • very high entropy with many failures (probing)
    """
    if not tokens:
        return 0.0
    counts = Counter(tokens)
    n = len(tokens)
    failures = sum(1 for t in tokens if t.endswith("|F"))
    fail_rate = failures / n
    unique_ratio = len(counts) / n

    # Repetition score — pure loops are anomalous (e.g., 200x same token)
    repetition = 1.0 - unique_ratio
    score = 0.0
    if repetition > 0.85 and n >= 5:
        score = max(score, 0.7 + min(0.25, repetition - 0.85))
    # High failure probing
    if fail_rate > 0.5 and unique_ratio > 0.5:
        score = max(score, 0.65 + min(0.3, fail_rate - 0.5))
    # Resource fan-out (many distinct resources from one user — recon)
    if unique_ratio > 0.9 and n >= 10:
        score = max(score, 0.55 + min(0.3, (n - 10) / 50))

    return round(min(1.0, score), 3)


# ── Transformer encoder (TF/Keras) ───────────────────────────────────────────

def _build_transformer(vocab_size: int):
    """Small transformer encoder for next-token prediction."""
    import tensorflow as tf
    from tensorflow.keras import layers, models

    inputs = layers.Input(shape=(WINDOW_SIZE,), dtype="int32", name="tokens")
    tok_emb = layers.Embedding(vocab_size, D_MODEL, mask_zero=True)(inputs)
    positions = tf.range(start=0, limit=WINDOW_SIZE, delta=1)
    pos_emb = layers.Embedding(WINDOW_SIZE, D_MODEL)(positions)
    x = tok_emb + pos_emb

    for _ in range(N_LAYERS):
        attn = layers.MultiHeadAttention(num_heads=N_HEADS, key_dim=D_MODEL // N_HEADS)(x, x)
        x = layers.LayerNormalization()(x + attn)
        ff = layers.Dense(D_MODEL * 2, activation="relu")(x)
        ff = layers.Dense(D_MODEL)(ff)
        x = layers.LayerNormalization()(x + ff)

    logits = layers.Dense(vocab_size)(x)
    model = models.Model(inputs, logits, name="sequence_transformer")
    model.compile(optimizer="adam", loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True))
    return model


def train_sequence_transformer(events: list, epochs: int = 5, batch_size: int = 32):
    """Train the transformer on user sessions. Returns metrics dict."""
    sessions = _events_to_sessions(events)
    if len(sessions) < 5:
        return {"error": "not enough sessions to train", "session_count": len(sessions)}

    # Build vocab — reserve 0 for PAD
    vocab = {"<PAD>": 0}
    for toks in sessions.values():
        for t in toks:
            if t not in vocab:
                vocab[t] = len(vocab)

    # Build sliding-window training pairs (input shifted by 1 = causal LM)
    sequences = []
    for toks in sessions.values():
        ids = [vocab[t] for t in toks]
        for start in range(0, max(1, len(ids) - WINDOW_SIZE) + 1):
            window = ids[start:start + WINDOW_SIZE]
            window = window + [0] * (WINDOW_SIZE - len(window))
            sequences.append(window)
    if len(sequences) < 10:
        return {"error": "not enough windows to train", "windows": len(sequences)}

    X = np.array([s[:-1] + [0] for s in sequences], dtype="int32")
    Y = np.array([s[1:]  + [0] for s in sequences], dtype="int32")

    model = _build_transformer(len(vocab))
    history = model.fit(X, Y, epochs=epochs, batch_size=batch_size, verbose=0)

    # Persist
    os.makedirs(os.path.dirname(SEQ_MODEL_PATH), exist_ok=True)
    model.save(SEQ_MODEL_PATH)
    with open(SEQ_VOCAB_PATH, "w") as f:
        json.dump(vocab, f)

    final_loss = float(history.history["loss"][-1])
    return {
        "trained": True,
        "epochs": epochs,
        "final_loss": round(final_loss, 4),
        "vocab_size": len(vocab),
        "training_windows": len(sequences),
        "trained_at": datetime.utcnow().isoformat(),
    }


def _load_model():
    """Load the trained transformer + vocab. Returns (model, vocab) or (None, None)."""
    if not (os.path.exists(SEQ_MODEL_PATH) and os.path.exists(SEQ_VOCAB_PATH)):
        return None, None
    try:
        from tensorflow.keras.models import load_model
        model = load_model(SEQ_MODEL_PATH, compile=False)
        with open(SEQ_VOCAB_PATH) as f:
            vocab = json.load(f)
        return model, vocab
    except Exception as e:
        print(f"⚠️  Failed to load sequence transformer: {e}")
        return None, None


def _model_score(tokens: list, model, vocab) -> float:
    """Score a session by mean per-token cross-entropy under the trained model."""
    import tensorflow as tf

    ids = [vocab.get(t, 0) for t in tokens][:WINDOW_SIZE]
    if len(ids) < 2:
        return 0.0
    ids_padded = ids + [0] * (WINDOW_SIZE - len(ids))
    X = np.array([ids_padded], dtype="int32")
    logits = model(X, training=False).numpy()[0]  # (WINDOW_SIZE, vocab)
    # Compute per-token nll for the next-token target
    losses = []
    for i, target in enumerate(ids[1:], start=1):
        if target == 0:
            break
        probs = tf.nn.softmax(logits[i - 1]).numpy()
        p = max(float(probs[target]), 1e-9)
        losses.append(-math.log(p))
    if not losses:
        return 0.0
    mean_nll = float(np.mean(losses))
    # Map nll → [0, 1] anomaly score (calibrated to typical cross-entropy range)
    return round(min(1.0, mean_nll / (math.log(max(2, len(vocab))))), 3)


# ── Public API ───────────────────────────────────────────────────────────────

def score_sessions(events: list, top_k: int = 10) -> dict:
    """
    Score every user session and return the top-K most anomalous.

    Returns:
        {
          method: 'transformer' | 'heuristic',
          model_loaded: bool,
          sessions: [{user, length, anomaly_score, sample_tokens}],
          total_users: int,
        }
    """
    sessions = _events_to_sessions(events)
    if not sessions:
        return {"method": "heuristic", "model_loaded": False, "sessions": [], "total_users": 0}

    model, vocab = _load_model()
    method = "transformer" if model is not None else "heuristic"

    scored = []
    for user, tokens in sessions.items():
        if model is not None and vocab is not None:
            s = _model_score(tokens, model, vocab)
        else:
            s = _heuristic_score(tokens)
        scored.append({
            "user": user,
            "length": len(tokens),
            "anomaly_score": s,
            "sample_tokens": tokens[:6],
        })

    scored.sort(key=lambda x: x["anomaly_score"], reverse=True)
    return {
        "method": method,
        "model_loaded": model is not None,
        "sessions": scored[:top_k],
        "total_users": len(sessions),
        "computed_at": datetime.utcnow().isoformat(),
    }
