import os
from datetime import datetime

from directory_constants.constants.exred_sector_names import CODES_SECTORS_DICT

BUILD_VERSION = "v0.1"
BUILD_SUFFIX = os.environ.get("CIRCLE_SHA1", str(datetime.date(datetime.now())))

EXRED_UI_URL = os.environ["EXRED_UI_URL"]
EXRED_SECTORS = CODES_SECTORS_DICT
BROWSER_STACK_SERVER = os.environ.get(
    "BROWSER_STACK_SERVER", "hub.browserstack.com")
BROWSER_STACK_USERNAME = os.environ.get("BROWSER_STACK_USERNAME")
BROWSER_STACK_ACCESS_KEY = os.environ.get("BROWSER_STACK_ACCESS_KEY")
BROWSER_STACK_TASK_ID = int(os.environ.get("TASK_ID", 0))
BROWSER_STACK_EXECUTOR_URL = ("http://{}:{}@{}/wd/hub".format(
    BROWSER_STACK_USERNAME, BROWSER_STACK_ACCESS_KEY, BROWSER_STACK_SERVER))

BROWSER_STACK_SESSIONS_URL = "https://www.browserstack.com/automate/sessions/{}.json"

BROWSER_STACK_CONFIG = {
    "server": BROWSER_STACK_SERVER,
    "user": BROWSER_STACK_USERNAME,
    "key": BROWSER_STACK_ACCESS_KEY,
    "capabilities": {
        "browserstack.debug": True,
        "browserstack.selenium_version": "3.5.2",
        "build": "{}-{}".format(BUILD_VERSION, BUILD_SUFFIX),
        "project": "ExRed",
        "resolution": "1600x1200"
    },
    "environments": [
        {
            "browser": "Chrome",
            "browser_version": "61.0",
        },
        {
            "browser": "Chrome",
            "browser_version": "62.0",
        },
        {
            "browser": "Firefox",
            "browser_version": "56.0",
        },
        {
            "browser": "IE",
            "browser_version": "11.0",
        },
        {
            "browser": "Edge",
            "browser_version": "15.0",
        },
        {
            "browser": "Edge",
            "browser_version": "16.0",
        },
    ]
}
