# -*- coding: utf-8 -*-
"""FAB - Edit Company's Directory Profile page"""
import logging

from requests import Response, Session

from tests import get_absolute_url
from tests.functional.features.context_utils import Company, Message
from tests.functional.features.utils import Method, check_response, make_request

URL = get_absolute_url("ui-supplier:suppliers-contact")
EXPECTED_STRINGS = [
    "Send a message to",
    ("Fill in your details and a brief message summarising your needs that will"
     " be sent to the UK company."), "Your full name:", "Your company name:",
    "Country:", "Your email address:", "Industry:",
    "Enter a subject line for your message:", "Maximum 200 characters.",
    "Enter your message to the UK company:", "Maximum 1000 characters.",
    "Captcha:", "I agree to the great.gov.uk terms and conditions", "Send",
    "cancel"
]

EXPECTED_STRINGS_MESSAGE_SENT = [
    "Message sent", "Your message has been sent to", "Browse more companies"
]


def go_to(session: Session, company_number: str, company_name: str) -> Response:
    """Go to Company's FAS profile page using company's number.

    :param session: Supplier session object
    :param company_number: company number
    :param company_name: name of the company
    :return: response object
    """
    full_url = URL.format(company_number)
    response = make_request(Method.GET, full_url, session=session)
    should_be_here(response, name=company_name)
    return response


def should_be_here(response, *, name=None):
    expected = EXPECTED_STRINGS + [name] if name else EXPECTED_STRINGS
    check_response(response, 200, body_contains=expected)
    logging.debug("Supplier is on FAS Contact Company page")


def submit(session: Session, message: Message, company_number: str):
    headers = {"Referer": URL.format(company_number)}
    data = {
        "body": message.full_name,
        "company_name": message.full_name,
        "country": message.full_name,
        "email_address": message.full_name,
        "full_name": message.full_name,
        "recaptcha_challenge_field": message.recaptcha_challenge_field,
        "recaptcha_response_field": message.recaptcha_response_field,
        "sector": message.full_name,
        "subject": message.full_name,
        "terms": message.terms
    }
    response = make_request(
        Method.POST, URL, session=session, headers=headers, data=data)
    return response


def should_see_that_message_has_been_sent(company: Company, response: Response):
    expected = EXPECTED_STRINGS_MESSAGE_SENT + [company.title]
    check_response(response, 200, body_contains=expected)
    logging.debug("Buyer was told that the message has been sent")
