"""
WSGI middleware for ThreatPulse.
Works with any WSGI framework (Flask, Django, etc.).
"""

import datetime
import os

from .client import ThreatPulse


class ThreatPulseMiddleware:
    """WSGI middleware that captures request/response details and ships them
    to ThreatPulse automatically."""

    def __init__(self, app, api_key=None, endpoint=None):
        """
        Args:
            app:      The WSGI application to wrap.
            api_key:  ThreatPulse API key (falls back to env var).
            endpoint: ThreatPulse API base URL (falls back to env var).
        """
        self.app = app
        self.tp = ThreatPulse(api_key=api_key, endpoint=endpoint)

    def __call__(self, environ, start_response):
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        query = environ.get("QUERY_STRING", "")
        resource = f"{path}?{query}" if query else path

        # Best-effort client IP
        ip = (
            environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
            or environ.get("REMOTE_ADDR", "unknown")
        )

        # Capture the response status via a wrapper around start_response
        captured = {}

        def _start_response(status, headers, exc_info=None):
            captured["status"] = status  # e.g. "200 OK"
            return start_response(status, headers, exc_info)

        result = self.app(environ, _start_response)

        # Determine success/failure from captured status
        status_code_str = captured.get("status", "500").split(" ", 1)[0]
        try:
            code = int(status_code_str)
        except ValueError:
            code = 500
        status_label = "success" if 200 <= code < 400 else "failure"

        # Try to determine user from environ (set by auth middleware in Flask/Django)
        user = (
            environ.get("REMOTE_USER")
            or "anonymous"
        )

        self.tp.track(
            {
                "timestamp": timestamp,
                "user": user,
                "ip": ip,
                "action": method,
                "status": status_label,
                "resource": resource,
            }
        )

        return result
