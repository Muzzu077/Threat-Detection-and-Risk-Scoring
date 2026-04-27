"""
TrustFlow SDK client for Python.
Zero-dependency: uses only stdlib (urllib, threading, json).
"""

import json
import os
import threading
import urllib.request
import urllib.error


class TrustFlow:
    """Batching client that ships events to the TrustFlow ingest API."""

    def __init__(
        self,
        api_key=None,
        endpoint=None,
        batch_size=25,
        flush_interval=5.0,
    ):
        """
        Args:
            api_key:        API key (or set TRUSTFLOW_API_KEY env var).
            endpoint:       TrustFlow base URL (or TRUSTFLOW_ENDPOINT env var).
            batch_size:     Auto-flush after this many queued events.
            flush_interval: Seconds between periodic flushes.
        """
        self.api_key = api_key or os.environ.get("TRUSTFLOW_API_KEY", "")
        self.endpoint = (
            endpoint
            or os.environ.get("TRUSTFLOW_ENDPOINT")
            or "http://localhost:8000"
        )
        self.batch_size = batch_size
        self.flush_interval = flush_interval

        self._queue = []
        self._lock = threading.Lock()
        self._running = True

        # Start the periodic flush timer
        self._schedule_flush()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def track(self, event: dict):
        """Add an event to the queue. Auto-flushes when batch_size is reached."""
        with self._lock:
            self._queue.append(event)
            should_flush = len(self._queue) >= self.batch_size

        if should_flush:
            self.flush()

    def flush(self):
        """POST all queued events to the TrustFlow ingest endpoint.

        On failure the events are re-queued for the next attempt.
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
                resp.read()  # drain the response
        except (urllib.error.URLError, OSError) as exc:
            # Re-queue so events aren't lost
            with self._lock:
                self._queue = batch + self._queue
            print(f"[TrustFlow] flush failed: {exc}")

    def shutdown(self):
        """Stop the periodic timer and flush remaining events."""
        self._running = False
        if self._timer is not None:
            self._timer.cancel()
        self.flush()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

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
