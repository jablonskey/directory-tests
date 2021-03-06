# -*- coding: utf-8 -*-
"""FAB - Verify Company page"""
import logging

from requests import Response, Session

from tests import get_absolute_url
from tests.functional.utils.request import Method, check_response, make_request

URL = get_absolute_url("ui-buyer:confirm-company-address")
EXPECTED_STRINGS = [
    "Verify your company",
    ("Enter the verification code from the letter we sent to you after  "
     "you created your company profile"),
    ("We sent you a letter through the mail containing a twelve digit "
     "code.")
]

EXPECTED_STRINGS_VERIFIED = [
    "Your company has been verified",
    "View or amend your company profile"
]


def go_to(session: Session, *, referer: str = None) -> Response:
    """Go to "Confirm Company" page. This requires Company

    :param session: Supplier session object
    :param referer: (optional) custom referer header value
    :return: response object
    """
    referer = referer or get_absolute_url("ui-buyer:company-profile")
    headers = {"Referer": referer}
    response = make_request(Method.GET, URL, session=session, headers=headers)
    return response


def should_be_here(response: Response):
    """Check if Supplier is on Verify Company page.

    :param response: response with Verify Company page.
    """
    check_response(response, 200, body_contains=EXPECTED_STRINGS)
    logging.debug("Supplier is on the Verify Company page")


def submit(session: Session, token: str, verification_code: str, *,
           referer: str = None) -> Response:
    """Submit the form with verification code.

    :param session: Supplier session object
    :param token: CSRF token required to submit the form
    :param verification_code: code required to verify company's profile
    :param referer: (optional) custom referer header value
    :return: response object
    """
    if referer is None:
        referer = get_absolute_url("ui-buyer:company-profile")
    headers = {"Referer": referer}
    data = {
        "csrfmiddlewaretoken": token,
        "company_address_verification_view-current_step": "address",
        "address-code": verification_code
    }
    response = make_request(
        Method.POST, URL, session=session, headers=headers, data=data)
    return response


def should_see_company_is_verified(response: Response):
    """Check is Supplier was told that the company has been verified"""
    check_response(response, 200, body_contains=EXPECTED_STRINGS_VERIFIED)
    logging.debug("Supplier is on the Verify Company page")


def view_or_amend_profile(session: Session) -> Response:
    """Simulate clicking on the 'View or amend your company profile' link.

    :param session: Supplier session object
    :return: response object
    """
    headers = {"Referer": URL}
    url = get_absolute_url("ui-buyer:company-profile")
    response = make_request(Method.GET, url, session=session, headers=headers)
    return response
