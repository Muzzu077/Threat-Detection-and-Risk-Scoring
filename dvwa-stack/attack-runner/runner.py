"""
Main orchestration loop — weighted severity distribution for realistic SOC feeds.

Severity distribution:
  70% normal (low-risk) traffic  — benign browsing
  20% medium-severity attacks    — XSS, CSRF, weak sessions, file inclusion
  10% high-severity attacks      — SQLi, brute force, command injection, file upload

Each module gets a unique geo-realistic IP per cycle via X-Forwarded-For.
"""

import os
import sys
import time
import random
import logging

from ip_pools import get_session_ip_sticky
from dvwa_session import DVWASession

from modules.brute_force import BruteForce
from modules.sql_injection import SqlInjection
from modules.sql_injection_blind import SqlInjectionBlind
from modules.xss_reflected import XssReflected
from modules.xss_stored import XssStored
from modules.xss_dom import XssDom
from modules.command_injection import CommandInjection
from modules.file_inclusion import FileInclusion
from modules.file_upload import FileUpload
from modules.csrf_attack import CsrfAttack
from modules.weak_session_ids import WeakSessionIds
from modules.normal_traffic import NormalTraffic

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("runner")

DVWA_URL = os.environ.get("DVWA_URL", "http://nginx")
LEVELS = ["low", "medium", "high"]

# ── Severity-weighted module tiers ────────────────────────────────────────────
# 70% normal | 20% medium | 10% high
TIER_LOW = [NormalTraffic()]                                      # 70%
TIER_MEDIUM = [                                                   # 20%
    XssReflected(), XssStored(), XssDom(),
    CsrfAttack(), WeakSessionIds(), FileInclusion(),
]
TIER_HIGH = [                                                     # 10%
    BruteForce(), SqlInjection(), SqlInjectionBlind(),
    CommandInjection(), FileUpload(),
]

TIER_WEIGHTS = [
    (0.55, TIER_LOW,    "low"),
    (0.82, TIER_MEDIUM, "medium"),   # 0.55 + 0.27
    (1.00, TIER_HIGH,   "high"),     # 0.82 + 0.18
]

# How many iterations per cycle before rotating IPs
ITERATIONS_PER_CYCLE = 20


def pick_tier():
    """Weighted random tier selection: 70% low, 20% medium, 10% high."""
    roll = random.random()
    for threshold, modules, tier_name in TIER_WEIGHTS:
        if roll < threshold:
            return modules, tier_name
    return TIER_LOW, "low"


def run_module(module, level, cycle_id):
    """Run a single attack module with its own session and spoofed IP."""
    ip = get_session_ip_sticky(module.NAME, cycle_id)
    session = DVWASession(DVWA_URL, xff_ip=ip)
    session.login()
    session.set_security(level)
    module.run(session, level)


def main():
    logger.info("Attack runner starting — target: %s", DVWA_URL)
    logger.info("Severity distribution: 70%% normal | 20%% medium | 10%% high")

    # Wait for DVWA to be available
    init_session = DVWASession(DVWA_URL, xff_ip="10.0.0.1")
    init_session.wait_for_dvwa(timeout=180)

    # Initialize DVWA database
    init_session.login()
    init_session.setup_database()
    init_session.login()

    logger.info("DVWA initialized. Starting weighted attack loop.")

    cycle_id = 0
    iteration = 0

    while True:
        # Pick severity tier and module
        tier_modules, tier_name = pick_tier()
        module = random.choice(tier_modules)
        level = random.choice(LEVELS)

        logger.info(
            "[iter %d | cycle %d] tier=%s module=%s level=%s",
            iteration, cycle_id, tier_name, module.NAME, level,
        )

        try:
            run_module(module, level, cycle_id)
        except Exception as e:
            logger.error("Module %s failed: %s", module.NAME, e)

        # Rotate IPs every N iterations
        iteration += 1
        if iteration % ITERATIONS_PER_CYCLE == 0:
            cycle_id += 1
            logger.info("IP rotation — new cycle_id: %d", cycle_id)

        # Delays: normal traffic faster, attacks slower
        if tier_name == "low":
            time.sleep(random.uniform(1, 4))
        elif tier_name == "medium":
            time.sleep(random.uniform(3, 8))
        else:
            time.sleep(random.uniform(4, 10))


if __name__ == "__main__":
    main()
