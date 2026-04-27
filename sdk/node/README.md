# trustflow-sdk

TrustFlow SDK for Node.js — ship HTTP logs to your TrustFlow threat detection dashboard with zero dependencies.

## Installation

```bash
npm install trustflow-sdk
```

## Quick Start

```js
const { TrustFlow } = require('trustflow-sdk');

const tp = new TrustFlow({
  apiKey: process.env.TRUSTFLOW_API_KEY,
  endpoint: 'https://your-trustflow-instance.com',
});

// Track an event manually
tp.track({
  timestamp: new Date().toISOString(),
  user: 'alice@example.com',
  ip: '203.0.113.42',
  action: 'POST',
  status: 'success',
  resource: '/api/login',
});

// Before process exit
await tp.shutdown();
```

## Express Middleware

Automatically capture every HTTP request/response:

```js
const express = require('express');
const { trustFlowMiddleware } = require('trustflow-sdk/express');

const app = express();

app.use(trustFlowMiddleware({
  apiKey: process.env.TRUSTFLOW_API_KEY,
  endpoint: 'https://your-trustflow-instance.com',
}));

app.get('/', (req, res) => res.send('OK'));
app.listen(3000);
```

The middleware automatically captures:
- **Timestamp** — request time (ISO 8601)
- **User** — from `req.user.email`, `req.user.id`, or `'anonymous'`
- **IP** — from `X-Forwarded-For` header or `req.ip`
- **Action** — HTTP method (GET, POST, etc.)
- **Status** — `'success'` (2xx/3xx) or `'failure'` (4xx/5xx)
- **Resource** — request path (`req.originalUrl`)

## How It Works

1. Events are queued in memory
2. When the queue reaches `batchSize` (default 25), events are flushed automatically
3. A periodic timer also flushes every `flushInterval` ms (default 5000)
4. Events are POSTed to `POST /api/v1/ingest` with your API key
5. On network failure, events are re-queued for the next flush attempt

## Configuration

| Option | Env Variable | Default | Description |
|---|---|---|---|
| `apiKey` | `TRUSTFLOW_API_KEY` | `''` | Your TrustFlow API key |
| `endpoint` | `TRUSTFLOW_ENDPOINT` | `http://localhost:8000` | TrustFlow API base URL |
| `batchSize` | — | `25` | Auto-flush after N queued events |
| `flushInterval` | — | `5000` | Periodic flush interval (ms) |

## API

### `new TrustFlow(options)`
Create a new client instance.

### `tp.track(event)`
Add an event object to the queue. Auto-flushes at `batchSize`.

### `tp.flush()`
Manually flush all queued events. Returns a Promise.

### `tp.shutdown()`
Stop the auto-flush timer and flush remaining events. Call before process exit.

## Requirements

- Node.js 18+ (uses native `fetch`)
- Zero dependencies

## License

MIT
