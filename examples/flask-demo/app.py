"""Tiny Flask app wired with TrustFlow's Python SDK WSGI middleware.

Run:
    pip install flask
    export TRUSTFLOW_API_KEY=tf_live_...
    export TRUSTFLOW_ENDPOINT=http://localhost:8000
    python app.py
    curl -X POST http://localhost:5050/login -d 'email=alice&password=hunter2'

Every request is shipped to the TrustFlow ingest API and shows up live on
the dashboard.
"""
import os
import sys

# Make the local SDK importable without `pip install`.
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python")
)

from flask import Flask, jsonify, request
from trustflow.middleware import TrustFlowMiddleware


app = Flask(__name__)


@app.route("/", methods=["GET"])
def root():
    return "demo running — try POST /login or GET /admin"


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email") or (request.json or {}).get("email")
    password = request.form.get("password") or (request.json or {}).get("password")
    if not email or not password or len(password) < 8:
        return jsonify({"error": "bad credentials"}), 401
    return jsonify({"ok": True, "email": email})


@app.route("/admin", methods=["GET"])
def admin():
    return jsonify({"error": "forbidden"}), 403


@app.route("/search", methods=["GET"])
def search():
    return jsonify({"results": [], "q": request.args.get("q", "")})


# Wrap the WSGI app so every request is captured + shipped.
app.wsgi_app = TrustFlowMiddleware(
    app.wsgi_app,
    api_key=os.environ.get("TRUSTFLOW_API_KEY", ""),
    endpoint=os.environ.get("TRUSTFLOW_ENDPOINT", "http://localhost:8000"),
)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5050"))
    print(
        f"[flask-demo] listening on http://localhost:{port} "
        f"(events → {os.environ.get('TRUSTFLOW_ENDPOINT', 'http://localhost:8000')})"
    )
    app.run(host="127.0.0.1", port=port, debug=False)
