# -*- coding: utf-8 -*-
"""Project Settings."""
import os
from datetime import datetime

from directory_constants.constants.exred_sector_names import CODES_SECTORS_DICT

import config

EXRED_SECTORS = CODES_SECTORS_DICT

# variables set in Paver configuration file
CONFIG_NAME = os.environ.get("CONFIG", "local")
TASK_ID = int(os.environ.get("TASK_ID", 0))

# optional variables set by user
BROWSERS = os.environ.get("BROWSERS", "").split()
BROWSERS_VERSIONS = os.environ.get("VERSIONS", "").split()
HUB_URL = os.environ.get("HUB_URL", None)
CAPABILITIES = os.environ.get("CAPABILITIES", None)
BUILD_ID = os.environ.get("CIRCLE_SHA1", str(datetime.date(datetime.now())))
EXRED_UI_URL = os.environ["EXRED_UI_URL"]

# BrowserStack variables
BROWSERSTACK_SERVER = os.environ.get(
    "BROWSERSTACK_SERVER", "hub.browserstack.com")
BROWSERSTACK_USER = os.environ.get("BROWSERSTACK_USER", "")
BROWSERSTACK_PASS = os.environ.get("BROWSERSTACK_PASS", "")
BROWSERSTACK_EXECUTOR_URL = ("http://{}:{}@{}/wd/hub".format(
    BROWSERSTACK_USER, BROWSERSTACK_PASS, BROWSERSTACK_SERVER))
BROWSERSTACK_SESSIONS_URL = "https://www.browserstack.com/automate/sessions/{}.json"


if (CONFIG_NAME.startswith("browserstack") and
        (BROWSERSTACK_SERVER and BROWSERSTACK_USER and BROWSERSTACK_PASS)):
    HUB_URL = BROWSERSTACK_EXECUTOR_URL

CONFIG = config.get(
    config_file=CONFIG_NAME, hub_url=HUB_URL, capabilities=CAPABILITIES,
    browsers=BROWSERS, versions=BROWSERS_VERSIONS, build_id=BUILD_ID)
