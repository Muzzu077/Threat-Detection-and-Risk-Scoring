# threatpulse-sdk

ThreatPulse SDK for Python -- ship HTTP logs to your ThreatPulse dashboard with zero dependencies.

## Installation

```bash
pip install threatpulse-sdk
```

Or install from source:

```bash
cd sdk/python
pip install .
```

## Quick Start

```python
from threatpulse import ThreatPulse

tp = ThreatPulse(
    api_key="your-api-key",
    endpoint="https://threatpulse.example.com",
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
from threatpulse.middleware import ThreatPulseMiddleware

app = Flask(__name__)
app.wsgi_app = ThreatPulseMiddleware(
    app.wsgi_app,
    api_key="your-api-key",
    endpoint="https://threatpulse.example.com",
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
from threatpulse.middleware import ThreatPulseMiddleware

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myproject.settings")

application = get_wsgi_application()
application = ThreatPulseMiddleware(
    application,
    api_key="your-api-key",
    endpoint="https://threatpulse.example.com",
)
```

## Configuration

| Parameter | Env Variable | Default | Description |
|---|---|---|---|
| `api_key` | `THREATPULSE_API_KEY` | `""` | API key for authentication |
| `endpoint` | `THREATPULSE_ENDPOINT` | `http://localhost:8000` | ThreatPulse API base URL |
| `batch_size` | -- | `25` | Auto-flush after this many queued events |
| `flush_interval` | -- | `5.0` | Seconds between periodic flushes |

## License

MIT
