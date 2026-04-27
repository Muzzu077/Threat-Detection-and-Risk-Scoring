# trustflow-sdk

TrustFlow SDK for Python -- ship HTTP logs to your TrustFlow dashboard with zero dependencies.

## Installation

```bash
pip install trustflow-sdk
```

Or install from source:

```bash
cd sdk/python
pip install .
```

## Quick Start

```python
from trustflow import TrustFlow

tp = TrustFlow(
    api_key="your-api-key",
    endpoint="https://trustflow.example.com",
)

tp.track({
    "timestamp": "2025-01-15T10:30:00Z",
    "user": "alice@example.com",
    "ip": "203.0.113.42",
    "action": "POST",
    "status": "success",
    "resource": "/api/login",
})

# Before process exit
tp.shutdown()
```

## Flask Middleware

```python
from flask import Flask
from trustflow.middleware import TrustFlowMiddleware

app = Flask(__name__)
app.wsgi_app = TrustFlowMiddleware(
    app.wsgi_app,
    api_key="your-api-key",
    endpoint="https://trustflow.example.com",
)

@app.route("/")
def index():
    return "OK"
```

## Django Middleware

Add the WSGI middleware in your `wsgi.py`:

```python
import os
from django.core.wsgi import get_wsgi_application
from trustflow.middleware import TrustFlowMiddleware

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myproject.settings")

application = get_wsgi_application()
application = TrustFlowMiddleware(
    application,
    api_key="your-api-key",
    endpoint="https://trustflow.example.com",
)
```

## Configuration

| Parameter | Env Variable | Default | Description |
|---|---|---|---|
| `api_key` | `TRUSTFLOW_API_KEY` | `""` | API key for authentication |
| `endpoint` | `TRUSTFLOW_ENDPOINT` | `http://localhost:8000` | TrustFlow API base URL |
| `batch_size` | -- | `25` | Auto-flush after this many queued events |
| `flush_interval` | -- | `5.0` | Seconds between periodic flushes |

## License

MIT
