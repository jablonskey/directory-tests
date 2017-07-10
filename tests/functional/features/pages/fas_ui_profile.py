# -*- coding: utf-8 -*-
"""FAB - Edit Company's Directory Profile page"""
import logging

from tests import get_absolute_url
from tests.functional.features.utils import Method, check_response, make_request

URL = get_absolute_url("ui-supplier:suppliers")
EXPECTED_STRINGS = [
    "Contact",
    "Company description",
    "Facts &amp; details",
    "Industries of interest",
    "Keywords",
    "Contact company"
]


def go_to(context, supplier_alias, *, company_number=None):
    """Go to "Edit Company's Details" page.

    This requires:
     * Supplier to be logged in

    :param context: behave `context` object
    :param supplier_alias: alias of the Actor used in the scope of the scenario
    :param company_number: (optional) explicit company number
    """
    actor = context.get_actor(supplier_alias)
    company = context.get_company(actor.company_alias)
    session = actor.session

    company_number = company_number or company.number
    full_url = "{}/{}".format(URL, company_number)
    headers = {"Referer": get_absolute_url("ui-buyer:company-profile")}
    response = make_request(Method.GET, full_url, session=session,
                            headers=headers, allow_redirects=False,
                            context=context)

    should_be_here(response, number=company_number)
    logging.debug("%s is on the Company's FAS profile page", supplier_alias)


def should_be_here(response, *, number=None):
    expected = EXPECTED_STRINGS + [number] if number else EXPECTED_STRINGS
    check_response(response, 200, body_contains=expected)
    logging.debug("Supplier is on FAS Company's Profile page")


def should_see_online_profiles(context, supplier_alias):
    actor = context.get_actor(supplier_alias)
    company = context.get_company(actor.company_alias)
    content = context.response.content.decode("utf-8")

    if company.facebook:
        assert "Visit Facebook" in content
        assert company.facebook in content
    if company.linkedin:
        assert "Visit LinkedIn" in content
        assert company.linkedin in content
    if company.twitter:
        assert "Visit Twitter" in content
        assert company.twitter in content
    logging.debug("% can see all expected links to Online Profiles on FAB "
                  "Company's Directory Profile Page", supplier_alias)
