"""
Base class for all DVWA attack modules.
Modules receive a DVWASession (already has XFF headers set) and don't manage IPs.
"""

import logging
import random
import time

logger = logging.getLogger(__name__)


class AttackModule:
    NAME = "base"

    def run_low(self, session):
        raise NotImplementedError

    def run_medium(self, session):
        raise NotImplementedError

    def run_high(self, session):
        raise NotImplementedError

    def run(self, session, level: str):
        logger.info("[%s] Running at %s level (XFF: %s)", self.NAME, level, session.xff_ip)
        session.set_meta(self.NAME)
        dispatch = {
            "low": self.run_low,
            "medium": self.run_medium,
            "high": self.run_high,
        }
        fn = dispatch.get(level, self.run_low)
        try:
            fn(session)
        except Exception as e:
            logger.error("[%s] Error at %s: %s", self.NAME, level, e)
        # Small jitter between sub-requests within a module
        time.sleep(random.uniform(0.3, 1.5))
