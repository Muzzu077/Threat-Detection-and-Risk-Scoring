# TrustFlow SDK demos

Two minimal apps — Express (Node.js) and Flask (Python) — that demonstrate
shipping HTTP request logs to a running TrustFlow dashboard.

Run a TrustFlow stack first (`docker compose up -d`), generate an API key
in the dashboard, then point either demo at it.

## Express

```bash
cd examples/express-demo
npm install
export TRUSTFLOW_API_KEY=tf_live_...
export TRUSTFLOW_ENDPOINT=http://localhost:8000
node server.js
# In another terminal
curl -X POST -d 'email=alice&password=short' http://localhost:3001/login
curl -X POST -d 'email=alice&password=hunter2longerpassword' http://localhost:3001/login
curl http://localhost:3001/admin
```

## Flask

```bash
cd examples/flask-demo
python -m venv .venv && source .venv/bin/activate
pip install flask
export TRUSTFLOW_API_KEY=tf_live_...
export TRUSTFLOW_ENDPOINT=http://localhost:8000
python app.py
# In another terminal
curl -X POST -d 'email=alice&password=hunter2longerpassword' http://localhost:5050/login
```

Open the TrustFlow dashboard's live-feed page and watch events stream in.

## Smoke test

There's a one-shot smoke script at `scripts/smoke-test.sh` that drives the
demos against your local stack and asserts the events land in the API.
