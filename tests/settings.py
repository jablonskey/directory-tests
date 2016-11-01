import os


DIRECTORY_API_URL = os.environ["DIRECTORY_API_URL"]
DIRECTORY_UI_URL = os.environ["DIRECTORY_UI_URL"]
DIRECTORY_UI_LOAD_URL = os.environ["DIRECTORY_UI_LOAD_URL"]

LOCUST_MIN_WAIT = os.getenv("LOCUST_MIN_WAIT", 500)
LOCUST_MAX_WAIT = os.getenv("LOCUST_MAX_WAIT", 6000)
