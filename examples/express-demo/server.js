// Tiny Express app wired with TrustFlow's Node SDK middleware.
// Run:
//   1) Generate an API key in the dashboard.
//   2) export TRUSTFLOW_API_KEY=tf_live_...
//      export TRUSTFLOW_ENDPOINT=http://localhost:8000
//   3) node server.js
//   4) curl http://localhost:3001/login -X POST -d email=alice
// Every request hits the TrustFlow ingest API and shows up on the dashboard.

const express = require('express');
const path = require('path');
const { trustFlowMiddleware } = require(path.join(__dirname, '..', '..', 'sdk', 'node', 'src', 'middleware.js'));

const app = express();
const PORT = process.env.PORT || 3001;

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// TrustFlow middleware: auto-tracks every request.
app.use(trustFlowMiddleware({
  apiKey: process.env.TRUSTFLOW_API_KEY,
  endpoint: process.env.TRUSTFLOW_ENDPOINT || 'http://localhost:8000',
}));

// A few routes that exercise different attack patterns.
app.get('/', (req, res) => {
  res.send('demo running — try POST /login or GET /admin');
});

app.post('/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password || password.length < 8) {
    res.status(401).json({ error: 'bad credentials' });
    return;
  }
  req.user = { email };  // SDK middleware reads this
  res.json({ ok: true, email });
});

app.get('/admin', (req, res) => {
  res.status(403).json({ error: 'forbidden' });
});

app.get('/search', (req, res) => {
  // Query string makes this look like a typical interactive endpoint.
  res.json({ results: [], q: req.query.q || '' });
});

app.listen(PORT, () => {
  console.log(`[express-demo] listening on http://localhost:${PORT}`);
  console.log(`[express-demo] sending events to ${process.env.TRUSTFLOW_ENDPOINT || 'http://localhost:8000'}`);
});
