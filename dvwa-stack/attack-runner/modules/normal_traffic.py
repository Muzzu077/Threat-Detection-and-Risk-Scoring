"""Normal (benign) traffic simulation — mimics legitimate employee browsing."""

import random
import time
from .base import AttackModule, logger

BENIGN_PAGES = [
    "/",
    "/about.php",
    "/instructions.php",
    "/security.php",
    "/index.php",
    "/dvwa/css/main.css",
    "/favicon.ico",
]


class NormalTraffic(AttackModule):
    NAME = "normal_traffic"

    def _browse(self, session, count):
        pages = random.sample(BENIGN_PAGES, min(count, len(BENIGN_PAGES)))
        for page in pages:
            session.get(page)
            logger.debug("[normal_traffic] Browsed %s", page)
            time.sleep(random.uniform(0.5, 2.0))

    def run_low(self, session):
        self._browse(session, random.randint(4, 8))

    def run_medium(self, session):
        self._browse(session, random.randint(3, 6))

    def run_high(self, session):
        self._browse(session, random.randint(2, 4))
