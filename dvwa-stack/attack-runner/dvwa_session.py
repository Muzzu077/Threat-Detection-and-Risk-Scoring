"""
DVWASession — wraps requests.Session with XFF headers, auto-login, CSRF token extraction.
"""

import re
import time
import logging
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class DVWASession:
    def __init__(self, base_url: str, xff_ip: str, username: str = "admin", password: str = "password"):
        self.base_url = base_url.rstrip("/")
        self.xff_ip = xff_ip
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({
            "X-Forwarded-For": xff_ip,
        })

    def set_meta(self, module_name: str):
        """Set the X-Attack-Meta header for log enrichment."""
        self.session.headers["X-Attack-Meta"] = f"{module_name}|{self.username}"

    def wait_for_dvwa(self, timeout: int = 120, interval: int = 3):
        """Block until DVWA responds on the login page."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = self.session.get(f"{self.base_url}/login.php", timeout=5)
                if r.status_code == 200:
                    logger.info("DVWA is ready")
                    return
            except requests.ConnectionError:
                pass
            time.sleep(interval)
        raise RuntimeError(f"DVWA not reachable at {self.base_url} after {timeout}s")

    def setup_database(self):
        """Hit the DVWA setup/reset DB page to initialize tables."""
        r = self.session.get(f"{self.base_url}/setup.php", timeout=10)
        token = self._extract_token(r.text)
        self.session.post(
            f"{self.base_url}/setup.php",
            data={"create_db": "Create / Reset Database", "user_token": token},
            timeout=10,
        )
        logger.info("DVWA database initialized")
        time.sleep(2)

    def login(self):
        """Log into DVWA and store the session cookie."""
        r = self.session.get(f"{self.base_url}/login.php", timeout=10)
        token = self._extract_token(r.text)
        r = self.session.post(
            f"{self.base_url}/login.php",
            data={
                "username": self.username,
                "password": self.password,
                "Login": "Login",
                "user_token": token,
            },
            timeout=10,
            allow_redirects=True,
        )
        if "login.php" in r.url and r.status_code == 200 and "Login failed" in r.text:
            raise RuntimeError("DVWA login failed — check credentials")
        logger.info("Logged into DVWA as %s (XFF: %s)", self.username, self.xff_ip)

    def set_security(self, level: str):
        """Set DVWA security level (low, medium, high)."""
        r = self.session.get(f"{self.base_url}/security.php", timeout=10)
        token = self._extract_token(r.text)
        self.session.post(
            f"{self.base_url}/security.php",
            data={"security": level, "seclev_submit": "Submit", "user_token": token},
            timeout=10,
        )
        logger.info("Security level set to %s", level)

    def get(self, path: str, **kwargs):
        """GET request with auto re-login on redirect to login page."""
        kwargs.setdefault("timeout", 10)
        r = self.session.get(f"{self.base_url}{path}", **kwargs)
        if "login.php" in r.url and "/login.php" not in path:
            logger.warning("Session expired, re-logging in")
            self.login()
            r = self.session.get(f"{self.base_url}{path}", **kwargs)
        return r

    def post(self, path: str, **kwargs):
        """POST request with auto re-login on redirect to login page."""
        kwargs.setdefault("timeout", 10)
        r = self.session.post(f"{self.base_url}{path}", **kwargs)
        if "login.php" in r.url and "/login.php" not in path:
            logger.warning("Session expired, re-logging in")
            self.login()
            r = self.session.post(f"{self.base_url}{path}", **kwargs)
        return r

    def get_csrf_token(self, path: str) -> str:
        """Fetch a page and extract the CSRF token."""
        r = self.get(path)
        return self._extract_token(r.text)

    def _extract_token(self, html: str) -> str:
        """Extract user_token from DVWA HTML."""
        soup = BeautifulSoup(html, "html.parser")
        tag = soup.find("input", {"name": "user_token"})
        if tag and tag.get("value"):
            return tag["value"]
        m = re.search(r"user_token['\"]?\s*value=['\"]([a-f0-9]+)", html)
        return m.group(1) if m else ""
