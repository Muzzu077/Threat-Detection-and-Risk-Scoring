"""
TrustFlow SDK client for Python.

Zero-dependency: stdlib only (urllib, threading, json). Mirrors the Node SDK
in `sdk/node/src/index.js` so a Python service gets the same loud-fail and
queue-bounding guarantees:

  * Loud-fail on missing api_key (stderr) — silent 401s are the #1 cause of
    "the dashboard isn't showing my events".
  * Loud-fail when defaulting to localhost in a production-looking env.
  * Bounded queue (max_queue_size, default 10_000) — drops oldest first.
  * 4xx responses (except 429) are PERMANENT — events are discarded, not
    retried forever.
  * 429 / 5xx / network errors are TRANSIENT — events re-queued for retry.
"""

import json
import os
import sys
import threading
import urllib.error
import urllib.request


def _looks_production():
    """Best-effort check for a production-like environment.

    Honors NODE_ENV (for Node devs), ENV, FLASK_ENV, PYTHON_ENV, ENVIRONMENT.
    """
    for var in ("NODE_ENV", "ENV", "FLASK_ENV", "PYTHON_ENV", "ENVIRONMENT"):
        v = os.environ.get(var, "").lower()
        if v in ("production", "prod"):
            return True
    return False


class TrustFlow:
    """Batching client that ships events to the TrustFlow ingest API."""

    def __init__(
        self,
        api_key=None,
        endpoint=None,
        batch_size=25,
        flush_interval=5.0,
        max_queue_size=10000,
    ):
        """
        Args:
            api_key:        API key (or set TRUSTFLOW_API_KEY env var).
            endpoint:       TrustFlow base URL (or TRUSTFLOW_ENDPOINT env var).
            batch_size:     Auto-flush after this many queued events.
            flush_interval: Seconds between periodic flushes.
            max_queue_size: Hard cap on queued events. When full, oldest are
                            dropped first. Prevents unbounded memory growth
                            during long server outages.
        """
        self.api_key = api_key or os.environ.get("TRUSTFLOW_API_KEY", "")
        explicit_endpoint = endpoint or os.environ.get("TRUSTFLOW_ENDPOINT") or ""
        self.endpoint = explicit_endpoint or "http://localhost:8000"
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.max_queue_size = max_queue_size

        self._queue = []
        self._dropped = 0
        self._lock = threading.Lock()
        self._running = True
        self._timer = None

        # Loud-fail: empty API key — every request will 401 silently otherwise.
        if not self.api_key:
            print(
                "[TrustFlow] No API key configured. Set api_key= or "
                "TRUSTFLOW_API_KEY env var. Events will be rejected (401).",
                file=sys.stderr,
            )

        # Loud-fail: defaulted endpoint in a production-looking env.
        using_default = not explicit_endpoint
        if using_default and _looks_production():
            print(
                "[TrustFlow] endpoint not configured — defaulting to "
                "http://localhost:8000 in a production-like environment "
                "(NODE_ENV/ENV/FLASK_ENV=production). Set endpoint= or "
                "TRUSTFLOW_ENDPOINT env var to your dashboard URL or events "
                "will not be delivered.",
                file=sys.stderr,
            )
        elif using_default:
            print(
                "[TrustFlow] endpoint not configured — defaulting to "
                "http://localhost:8000. Set endpoint= (or TRUSTFLOW_ENDPOINT) "
                "for production deployments.",
                file=sys.stderr,
            )

        # Start the periodic flush timer
        self._schedule_flush()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def track(self, event: dict):
        """Add an event to the queue. Auto-flushes when batch_size is reached.

        If the queue is at max_queue_size, the OLDEST event is dropped to
        make room. This prevents the queue from growing without bound when
        the server is unreachable.
        """
        with self._lock:
            if len(self._queue) >= self.max_queue_size:
                self._queue.pop(0)
                self._dropped += 1
                if self._dropped == 1 or self._dropped % 1000 == 0:
                    print(
                        f"[TrustFlow] Queue full ({self.max_queue_size}) — "
                        f"dropping events. Total dropped: {self._dropped}. "
                        "Check that endpoint and api_key are correct.",
                        file=sys.stderr,
                    )
            self._queue.append(event)
            should_flush = len(self._queue) >= self.batch_size

        if should_flush:
            self.flush()

    def flush(self):
        """POST all queued events to the TrustFlow ingest endpoint.

        4xx responses (except 429) are treated as permanent failures: events
        are discarded with a stderr log. 429 / 5xx / network errors re-queue
        the events for retry, bounded by max_queue_size.
        """
        with self._lock:
            if not self._queue:
                return
            batch = list(self._queue)
            self._queue.clear()

        payload = json.dumps({"events": batch}).encode("utf-8")
        url = f"{self.endpoint}/api/v1/ingest"
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": self.api_key,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
            return  # success
        except urllib.error.HTTPError as exc:
            # 4xx (except 429) are permanent — don't keep retrying bad requests.
            if 400 <= exc.code < 500 and exc.code != 429:
                try:
                    body = exc.read().decode("utf-8", errors="replace")[:200]
                except Exception:
                    body = ""
                print(
                    f"[TrustFlow] ingest responded {exc.code}"
                    f"{' — ' + body if body else ''} — discarding "
                    f"{len(batch)} event(s) (will not retry).",
                    file=sys.stderr,
                )
                return
            # 429 / 5xx — transient, re-queue
            self._requeue(batch, f"ingest responded {exc.code}")
        except (urllib.error.URLError, OSError) as exc:
            # Network / DNS / timeout — transient, re-queue
            self._requeue(batch, str(exc))

    def shutdown(self):
        """Stop the periodic timer and flush remaining events synchronously."""
        self._running = False
        if self._timer is not None:
            self._timer.cancel()
        self.flush()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _requeue(self, batch, reason):
        """Re-queue a failed batch, dropping oldest events to honor max_queue_size."""
        with self._lock:
            merged = batch + self._queue
            if len(merged) > self.max_queue_size:
                self._dropped += len(merged) - self.max_queue_size
                merged = merged[-self.max_queue_size:]
            self._queue = merged
        print(f"[TrustFlow] flush failed: {reason}", file=sys.stderr)

    def _schedule_flush(self):
        """Schedule the next periodic flush using a daemon Timer thread."""
        if not self._running:
            return
        self._timer = threading.Timer(self.flush_interval, self._periodic_flush)
        self._timer.daemon = True
        self._timer.start()

    def _periodic_flush(self):
        """Executed by the timer thread."""
        try:
            self.flush()
        finally:
            self._schedule_flush()
