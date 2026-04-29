"""
Tests for sdk/python/trustflow — client and middleware.
"""
import io
import json
import sys
import threading
import time
import urllib.error
from unittest.mock import patch, MagicMock
from http.server import HTTPServer, BaseHTTPRequestHandler


class TestTrustFlowClient:
    def test_init_defaults(self):
        from sdk.python.trustflow.client import TrustFlow
        tp = TrustFlow(api_key="tf_live_test", flush_interval=9999)
        try:
            assert tp.api_key == "tf_live_test"
            assert tp.endpoint == "http://localhost:8000"
            assert tp.batch_size == 25
            assert tp._queue == []
        finally:
            tp.shutdown()

    def test_init_from_env(self, monkeypatch):
        monkeypatch.setenv("TRUSTFLOW_API_KEY", "tf_live_env_key")
        monkeypatch.setenv("TRUSTFLOW_ENDPOINT", "http://custom:9000")
        from sdk.python.trustflow.client import TrustFlow
        tp = TrustFlow(flush_interval=9999)
        try:
            assert tp.api_key == "tf_live_env_key"
            assert tp.endpoint == "http://custom:9000"
        finally:
            tp.shutdown()

    def test_track_adds_to_queue(self):
        from sdk.python.trustflow.client import TrustFlow
        tp = TrustFlow(api_key="k", flush_interval=9999, batch_size=100)
        try:
            tp.track({"user": "alice", "action": "login"})
            assert len(tp._queue) == 1
            assert tp._queue[0]["user"] == "alice"
        finally:
            tp.shutdown()

    def test_track_auto_flush_at_batch_size(self):
        from sdk.python.trustflow.client import TrustFlow
        tp = TrustFlow(api_key="k", flush_interval=9999, batch_size=3)
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
        from sdk.python.trustflow.client import TrustFlow
        tp = TrustFlow(api_key="k", flush_interval=9999)
        try:
            tp.flush()  # should not raise
        finally:
            tp.shutdown()

    def test_flush_requeues_on_failure(self):
        from sdk.python.trustflow.client import TrustFlow
        tp = TrustFlow(
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
        from sdk.python.trustflow.client import TrustFlow
        tp = TrustFlow(api_key="k", flush_interval=9999)
        tp.shutdown()
        assert tp._running is False

    def test_flush_posts_correct_format(self):
        """Test that flush sends correct JSON structure to the right URL."""
        from sdk.python.trustflow.client import TrustFlow

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

        tp = TrustFlow(api_key="tf_live_abc", endpoint="http://example.com", flush_interval=9999)
        try:
            tp.track({"timestamp": "2024-01-01T00:00:00Z", "user": "test"})
            with patch("sdk.python.trustflow.client.urllib.request.urlopen", mock_urlopen):
                tp.flush()

            assert captured["url"] == "http://example.com/api/v1/ingest"
            assert captured["method"] == "POST"
            assert "events" in captured["data"]
            assert len(captured["data"]["events"]) == 1
            assert captured["headers"]["X-api-key"] == "tf_live_abc"
        finally:
            tp.shutdown()


class TestTrustFlowClientHardening:
    """Loud-fail / bounded queue / 4xx-drop parity with the Node SDK."""

    def test_loud_fail_on_missing_api_key(self, monkeypatch, capsys):
        # Make sure no env var leaks in
        monkeypatch.delenv("TRUSTFLOW_API_KEY", raising=False)
        from sdk.python.trustflow.client import TrustFlow
        tp = TrustFlow(flush_interval=9999)
        try:
            captured = capsys.readouterr()
            assert "no api key" in captured.err.lower()
        finally:
            tp.shutdown()

    def test_loud_fail_on_default_endpoint_in_production(self, monkeypatch, capsys):
        monkeypatch.setenv("TRUSTFLOW_API_KEY", "tf_live_x")
        monkeypatch.setenv("ENV", "production")
        monkeypatch.delenv("TRUSTFLOW_ENDPOINT", raising=False)
        from sdk.python.trustflow.client import TrustFlow
        tp = TrustFlow(flush_interval=9999)
        try:
            err = capsys.readouterr().err
            # In production with default endpoint, loudly warn
            assert "production" in err.lower() and "endpoint" in err.lower()
        finally:
            tp.shutdown()

    def test_max_queue_size_drops_oldest(self):
        from sdk.python.trustflow.client import TrustFlow
        tp = TrustFlow(api_key="k", flush_interval=9999, batch_size=10000, max_queue_size=3)
        try:
            tp.track({"i": 1})
            tp.track({"i": 2})
            tp.track({"i": 3})
            tp.track({"i": 4})  # should drop {"i": 1}
            tp.track({"i": 5})  # should drop {"i": 2}
            assert [e["i"] for e in tp._queue] == [3, 4, 5]
            assert tp._dropped == 2
        finally:
            tp.shutdown()

    def test_4xx_response_discards_batch(self):
        """A 4xx (non-429) response must NOT re-queue the events."""
        from sdk.python.trustflow.client import TrustFlow

        def mock_urlopen_400(req, timeout=10):
            raise urllib.error.HTTPError(
                req.full_url, 400, "Bad Request",
                hdrs=None, fp=io.BytesIO(b'{"detail":"bad payload"}')
            )

        tp = TrustFlow(api_key="k", flush_interval=9999, batch_size=100)
        try:
            tp.track({"a": 1})
            with patch("sdk.python.trustflow.client.urllib.request.urlopen", mock_urlopen_400):
                tp.flush()
            # 4xx → discarded, NOT re-queued
            assert tp._queue == []
        finally:
            tp.shutdown()

    def test_429_response_requeues_batch(self):
        """A 429 (rate-limited) response is transient and MUST re-queue."""
        from sdk.python.trustflow.client import TrustFlow

        def mock_urlopen_429(req, timeout=10):
            raise urllib.error.HTTPError(
                req.full_url, 429, "Too Many Requests",
                hdrs=None, fp=io.BytesIO(b'{"detail":"rate limited"}')
            )

        tp = TrustFlow(api_key="k", flush_interval=9999, batch_size=100)
        try:
            tp.track({"a": 1})
            with patch("sdk.python.trustflow.client.urllib.request.urlopen", mock_urlopen_429):
                tp.flush()
            # 429 → re-queued for retry
            assert len(tp._queue) == 1
        finally:
            tp.shutdown()

    def test_5xx_response_requeues_batch(self):
        """5xx is transient — re-queue for retry."""
        from sdk.python.trustflow.client import TrustFlow

        def mock_urlopen_500(req, timeout=10):
            raise urllib.error.HTTPError(
                req.full_url, 500, "Internal Server Error",
                hdrs=None, fp=io.BytesIO(b'')
            )

        tp = TrustFlow(api_key="k", flush_interval=9999, batch_size=100)
        try:
            tp.track({"a": 1})
            with patch("sdk.python.trustflow.client.urllib.request.urlopen", mock_urlopen_500):
                tp.flush()
            assert len(tp._queue) == 1
        finally:
            tp.shutdown()

    def test_requeue_respects_max_queue_size(self):
        """During an outage with active producers, retried + new events can't
        push the queue above max_queue_size — oldest must be dropped."""
        from sdk.python.trustflow.client import TrustFlow

        def mock_urlopen_500(req, timeout=10):
            raise urllib.error.HTTPError(
                req.full_url, 500, "Internal Server Error",
                hdrs=None, fp=io.BytesIO(b'')
            )

        tp = TrustFlow(api_key="k", flush_interval=9999, batch_size=100, max_queue_size=2)
        try:
            # Queue holds [A, B]; flush fails 500 → batch=[A,B] re-queued, queue still empty
            tp._queue = [{"i": "A"}, {"i": "B"}]
            with patch("sdk.python.trustflow.client.urllib.request.urlopen", mock_urlopen_500):
                tp.flush()
            assert len(tp._queue) == 2

            # Producer adds C, D, E during the outage. The cap is 2 so we should
            # only ever see the LAST 2 events at most.
            tp.track({"i": "C"})  # full → drop A; queue=[B,C]
            tp.track({"i": "D"})  # full → drop B; queue=[C,D]
            assert [e["i"] for e in tp._queue] == ["C", "D"]
            assert tp._dropped >= 2
        finally:
            tp.shutdown()


class TestTrustFlowMiddleware:
    def test_middleware_wraps_app(self):
        from sdk.python.trustflow.middleware import TrustFlowMiddleware

        def dummy_app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"Hello"]

        mw = TrustFlowMiddleware(dummy_app, api_key="k")
        # Shutdown the timer to avoid background threads
        mw.tp.shutdown()
        assert mw.app is dummy_app

    def test_middleware_tracks_request(self):
        from sdk.python.trustflow.middleware import TrustFlowMiddleware

        tracked_events = []

        def dummy_app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"OK"]

        mw = TrustFlowMiddleware(dummy_app, api_key="k")
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
        from sdk.python.trustflow.middleware import TrustFlowMiddleware

        tracked_events = []

        def error_app(environ, start_response):
            start_response("500 Internal Server Error", [])
            return [b"Error"]

        mw = TrustFlowMiddleware(error_app, api_key="k")
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
        from sdk.python.trustflow.middleware import TrustFlowMiddleware

        tracked_events = []

        def app(environ, start_response):
            start_response("200 OK", [])
            return [b""]

        mw = TrustFlowMiddleware(app, api_key="k")
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
        from sdk.python.trustflow.middleware import TrustFlowMiddleware

        tracked_events = []

        def app(environ, start_response):
            start_response("200 OK", [])
            return [b""]

        mw = TrustFlowMiddleware(app, api_key="k")
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
