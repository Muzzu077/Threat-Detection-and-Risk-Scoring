"""
Main orchestration loop — cycles through attack modules at all security levels.
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

ATTACK_MODULES = [
    BruteForce(),
    SqlInjection(),
    SqlInjectionBlind(),
    XssReflected(),
    XssStored(),
    XssDom(),
    CommandInjection(),
    FileInclusion(),
    FileUpload(),
    CsrfAttack(),
    WeakSessionIds(),
]

NORMAL_MODULE = NormalTraffic()


def run_module(module, level, cycle_id):
    """Run a single attack module with its own session and spoofed IP."""
    ip = get_session_ip_sticky(module.NAME, cycle_id)
    session = DVWASession(DVWA_URL, xff_ip=ip)
    session.login()
    session.set_security(level)
    module.run(session, level)


def maybe_normal_traffic(cycle_id, level):
    """30% chance of injecting normal browsing traffic between attacks."""
    if random.random() < 0.3:
        ip = get_session_ip_sticky("normal_traffic", cycle_id)
        session = DVWASession(DVWA_URL, xff_ip=ip)
        session.login()
        session.set_security(level)
        NORMAL_MODULE.run(session, level)


def main():
    logger.info("Attack runner starting — target: %s", DVWA_URL)

    # Wait for DVWA to be available
    init_session = DVWASession(DVWA_URL, xff_ip="10.0.0.1")
    init_session.wait_for_dvwa(timeout=180)

    # Initialize DVWA database
    init_session.login()
    init_session.setup_database()
    # Re-login after DB reset
    init_session.login()

    logger.info("DVWA initialized. Starting attack cycles.")

    cycle_id = 0
    while True:
        for level in LEVELS:
            logger.info("=== Cycle %d | Level: %s ===", cycle_id, level)
            modules = list(ATTACK_MODULES)
            random.shuffle(modules)

            for module in modules:
                try:
                    run_module(module, level, cycle_id)
                except Exception as e:
                    logger.error("Module %s failed: %s", module.NAME, e)

                maybe_normal_traffic(cycle_id, level)
                time.sleep(random.uniform(2, 10))

        cycle_id += 1
        pause = random.uniform(5, 15)
        logger.info("Cycle %d complete. Pausing %.1fs before next cycle.", cycle_id - 1, pause)
        time.sleep(pause)


if __name__ == "__main__":
    main()
