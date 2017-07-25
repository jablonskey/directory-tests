# -*- coding: utf-8 -*-
"""SSO - Logout page"""
import logging

from requests import Response, Session

from tests import get_absolute_url
from tests.functional.features.utils import Method, check_response, make_request

URL = get_absolute_url("sso:logout")
EXPECTED_STRINGS = [
    "Sign out", "Are you sure you want to sign out?"
]


def go_to(session: Session) -> Response:
    """Go to the SSO Logout page.

    :param session: Supplier session object
    :return: response object
    """
    fab_landing = get_absolute_url("ui-buyer:landing")
    params = {"next": fab_landing}
    headers = {"Referer": get_absolute_url("ui-buyer:company-profile")}
    response = make_request(
        Method.GET, URL, session=session, params=params, headers=headers)
    return response


def should_be_here(response: Response):
    """Check if Supplier is on SSO logout page.

    :param response: response object
    """
    check_response(response, 200, body_contains=EXPECTED_STRINGS)
    logging.debug("Successfully got to the SSO logout page")


def logout(session: Session, token: str) -> Response:
    """Sign out from SSO/FAB.

    :param session: Supplier session object
    :param token: CSRF token required to submit the login form
    :return: response object
    """
    fab_landing = get_absolute_url("ui-buyer:landing")
    data = {
        "csrfmiddlewaretoken": token,
        "next": fab_landing
    }
    headers = {"Referer": "{}/?next={}".format(URL, fab_landing)}
    response = make_request(
        Method.POST, URL, session=session, headers=headers, data=data)

    return response
