"""Weak Session IDs — harvest predictable session tokens from DVWA."""

from .base import AttackModule, logger


class WeakSessionIds(AttackModule):
    NAME = "weak_session_ids"

    def _harvest(self, session, count):
        for i in range(count):
            r = session.post(
                "/vulnerabilities/weak_id/",
                data={"Generate": "Generate"},
            )
            cookies = session.session.cookies.get_dict()
            dvwa_session = cookies.get("dvwaSession", "N/A")
            logger.debug("[weak_session_ids] Token %d: %s", i, dvwa_session)

    def run_low(self, session):
        self._harvest(session, 10)  # Sequential integers

    def run_medium(self, session):
        self._harvest(session, 8)  # Timestamp-based

    def run_high(self, session):
        self._harvest(session, 6)  # MD5 of sequential
