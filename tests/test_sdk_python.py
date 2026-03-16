"""
Tests for sdk/python/threatpulse — client and middleware.
"""
import pytest
import json
import threading
import time
from unittest.mock import patch, MagicMock
from http.server import HTTPServer, BaseHTTPRequestHandler


class TestThreatPulseClient:
    def test_init_defaults(self):
        from sdk.python.threatpulse.client import ThreatPulse
        tp = ThreatPulse(api_key="tp_live_test", flush_interval=9999)
        try:
            assert tp.api_key == "tp_live_test"
            assert tp.endpoint == "http://localhost:8000"
            assert tp.batch_size == 25
            assert tp._queue == []
        finally:
            tp.shutdown()

    def test_init_from_env(self, monkeypatch):
        monkeypatch.setenv("THREATPULSE_API_KEY", "tp_live_env_key")
        monkeypatch.setenv("THREATPULSE_ENDPOINT", "http://custom:9000")
        from sdk.python.threatpulse.client import ThreatPulse
        tp = ThreatPulse(flush_interval=9999)
        try:
            assert tp.api_key == "tp_live_env_key"
            assert tp.endpoint == "http://custom:9000"
        finally:
            tp.shutdown()

    def test_track_adds_to_queue(self):
        from sdk.python.threatpulse.client import ThreatPulse
        tp = ThreatPulse(api_key="k", flush_interval=9999, batch_size=100)
        try:
            tp.track({"user": "alice", "action": "login"})
            assert len(tp._queue) == 1
            assert tp._queue[0]["user"] == "alice"
        finally:
            tp.shutdown()

    def test_track_auto_flush_at_batch_size(self):
        from sdk.python.threatpulse.client import ThreatPulse
        tp = ThreatPulse(api_key="k", flush_interval=9999, batch_size=3)
        flush_called = []
        original_flush = tp.flush
        def mock_flush():
            flush_called.append(True)
            # Don't actually POST, just clear queue
            tp._queue.clear()
        tp.flush = mock_flush
        try:
            tp.track({"e": 1})
            tp.track({"e": 2})
            assert len(flush_called) == 0
            tp.track({"e": 3})  # triggers flush
            assert len(flush_called) == 1
        finally:
            tp.flush = original_flush
            tp.shutdown()

    def test_flush_empty_queue_noop(self):
        from sdk.python.threatpulse.client import ThreatPulse
        tp = ThreatPulse(api_key="k", flush_interval=9999)
        try:
            tp.flush()  # should not raise
        finally:
            tp.shutdown()

    def test_flush_requeues_on_failure(self):
        from sdk.python.threatpulse.client import ThreatPulse
        tp = ThreatPulse(
            api_key="k",
            endpoint="http://127.0.0.1:1",  # non-routable port
            flush_interval=9999,
            batch_size=100,
        )
        try:
            tp.track({"event": "test"})
            tp.flush()
            # Events should be re-queued
            assert len(tp._queue) == 1
        finally:
            tp.shutdown()

    def test_shutdown_stops_timer(self):
        from sdk.python.threatpulse.client import ThreatPulse
        tp = ThreatPulse(api_key="k", flush_interval=9999)
        tp.shutdown()
        assert tp._running is False

    def test_flush_posts_correct_format(self):
        """Test that flush sends correct JSON structure to the right URL."""
        from sdk.python.threatpulse.client import ThreatPulse

        captured = {}

        def mock_urlopen(req, timeout=10):
            captured["url"] = req.full_url
            captured["method"] = req.method
            captured["data"] = json.loads(req.data.decode())
            captured["headers"] = dict(req.headers)
            mock_resp = MagicMock()
            mock_resp.read.return_value = b'{"ok": true}'
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        tp = ThreatPulse(api_key="tp_live_abc", endpoint="http://example.com", flush_interval=9999)
        try:
            tp.track({"timestamp": "2024-01-01T00:00:00Z", "user": "test"})
            with patch("sdk.python.threatpulse.client.urllib.request.urlopen", mock_urlopen):
                tp.flush()

            assert captured["url"] == "http://example.com/api/v1/ingest"
            assert captured["method"] == "POST"
            assert "events" in captured["data"]
            assert len(captured["data"]["events"]) == 1
            assert captured["headers"]["X-api-key"] == "tp_live_abc"
        finally:
            tp.shutdown()


class TestThreatPulseMiddleware:
    def test_middleware_wraps_app(self):
        from sdk.python.threatpulse.middleware import ThreatPulseMiddleware

        def dummy_app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"Hello"]

        mw = ThreatPulseMiddleware(dummy_app, api_key="k")
        # Shutdown the timer to avoid background threads
        mw.tp.shutdown()
        assert mw.app is dummy_app

    def test_middleware_tracks_request(self):
        from sdk.python.threatpulse.middleware import ThreatPulseMiddleware

        tracked_events = []

        def dummy_app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"OK"]

        mw = ThreatPulseMiddleware(dummy_app, api_key="k")
        original_track = mw.tp.track
        def capture_track(event):
            tracked_events.append(event)
        mw.tp.track = capture_track

        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/api/login",
            "QUERY_STRING": "",
            "REMOTE_ADDR": "10.0.0.1",
        }

        def start_response(status, headers, exc_info=None):
            pass

        result = mw(environ, start_response)
        assert result == [b"OK"]
        assert len(tracked_events) == 1
        event = tracked_events[0]
        assert event["action"] == "POST"
        assert event["resource"] == "/api/login"
        assert event["ip"] == "10.0.0.1"
        assert event["status"] == "success"

        mw.tp.track = original_track
        mw.tp.shutdown()

    def test_middleware_captures_failure_status(self):
        from sdk.python.threatpulse.middleware import ThreatPulseMiddleware

        tracked_events = []

        def error_app(environ, start_response):
            start_response("500 Internal Server Error", [])
            return [b"Error"]

        mw = ThreatPulseMiddleware(error_app, api_key="k")
        mw.tp.track = lambda e: tracked_events.append(e)

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/broken",
            "QUERY_STRING": "",
            "REMOTE_ADDR": "1.2.3.4",
        }

        mw(environ, lambda *a, **kw: None)
        assert tracked_events[0]["status"] == "failure"
        mw.tp.shutdown()

    def test_middleware_x_forwarded_for(self):
        from sdk.python.threatpulse.middleware import ThreatPulseMiddleware

        tracked_events = []

        def app(environ, start_response):
            start_response("200 OK", [])
            return [b""]

        mw = ThreatPulseMiddleware(app, api_key="k")
        mw.tp.track = lambda e: tracked_events.append(e)

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/",
            "QUERY_STRING": "",
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_X_FORWARDED_FOR": "8.8.8.8, 10.0.0.1",
        }

        mw(environ, lambda *a, **kw: None)
        assert tracked_events[0]["ip"] == "8.8.8.8"
        mw.tp.shutdown()

    def test_middleware_with_query_string(self):
        from sdk.python.threatpulse.middleware import ThreatPulseMiddleware

        tracked_events = []

        def app(environ, start_response):
            start_response("200 OK", [])
            return [b""]

        mw = ThreatPulseMiddleware(app, api_key="k")
        mw.tp.track = lambda e: tracked_events.append(e)

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/search",
            "QUERY_STRING": "q=test",
            "REMOTE_ADDR": "127.0.0.1",
        }

        mw(environ, lambda *a, **kw: None)
        assert tracked_events[0]["resource"] == "/search?q=test"
        mw.tp.shutdown()
